//! Implementation of the Plumtree epidemic broadcast tree protocol
//!
//! The implementation is based on [this paper][paper] by Joao Leitao, Jose Pereira, Luıs Rodrigues
//! and the [example implementation][impl] by Bartosz Sypytkowski
//!
//! [paper]: https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf
//! [impl]: https://gist.github.com/Horusiath/84fac596101b197da0546d1697580d99

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    hash::Hash,
    time::Duration,
};

use bytes::Bytes;
use derive_more::From;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

use super::{PeerAddress, IO};

pub enum InEvent<PA> {
    RecvMessage(PA, Message),
    Broadcast(Bytes),
    TimerExpired(Timer),
    NeighborUp(PA),
    NeighborDown(PA),
}

pub enum OutEvent<PA> {
    SendMessage(PA, Message),
    ScheduleTimer(Duration, Timer),
    EmitEvent(Event),
}

#[derive(Clone, Debug)]
pub enum Timer {
    SendGraft(MessageId),
    DispatchLazyPush,
}

#[derive(Clone, Debug)]
pub enum Event {
    Received(Bytes),
}

/// A message identifier, which is the message content's blake3 hash
#[derive(Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
pub struct MessageId([u8; 32]);

impl From<blake3::Hash> for MessageId {
    fn from(hash: blake3::Hash) -> Self {
        Self(hash.into())
    }
}

impl std::hash::Hash for MessageId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.0);
        text.make_ascii_lowercase();
        write!(f, "{}", text)
    }
}
impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.0);
        text.make_ascii_lowercase();
        write!(f, "{}…{}", &text[..5], &text[(text.len() - 2)..])
    }
}

#[derive(From, Serialize, Deserialize, Eq, PartialEq, Clone, Copy, Debug, Hash)]
pub struct Round(u16);

impl Round {
    pub fn next(&self) -> Round {
        Round(self.0 + 1)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    /// When receiving Gossip, emit as event and forward full message to eager peer
    /// and (after a delay) message IDs to lazy peers.
    Gossip(Gossip),
    /// When receiving Prune, move the peer from the eager to the lazy set
    Prune,
    /// When receiving Graft, move the peer to the eager set and send the full content for the
    /// included message ID.
    Graft(Graft),
    /// When receiving IHave, do nothing initially, and request the messages for the included
    /// message IDs after some time if they aren't pushed eagerly to us.
    IHave(Vec<IHave>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Gossip {
    id: MessageId,
    round: Round,
    content: Bytes,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IHave {
    id: MessageId,
    round: Round,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Graft {
    id: MessageId,
    round: Round,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LazyPush<PA> {
    id: MessageId,
    round: Round,
    peer: PA,
}

#[derive(Clone, Debug)]
pub struct Config {
    graft_timeout: Duration,
    ihave_timeout: Duration,
    dispatch_timeout: Duration,
    // optimization_threshold: Round,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            graft_timeout: Duration::from_secs(1),
            ihave_timeout: Duration::from_millis(30),
            dispatch_timeout: Duration::from_millis(30), // optimization_threshold: Round(5),
        }
    }
}

#[derive(Debug)]
pub struct State<PA> {
    me: PA,
    config: Config,

    eager_push_peers: HashSet<PA>,
    lazy_push_peers: HashSet<PA>,

    lazy_push_queue: HashMap<PA, Vec<IHave>>,

    missing_messages: IndexSet<LazyPush<PA>>,
    received_messages: IndexSet<MessageId>,
    cache: HashMap<MessageId, Gossip>,

    timers: HashSet<MessageId>,
    dispatch_timer_scheduled: bool,
}

impl<PA: PeerAddress> State<PA> {
    pub fn new(me: PA, config: Config) -> Self {
        Self {
            me,
            eager_push_peers: Default::default(),
            lazy_push_peers: Default::default(),
            lazy_push_queue: Default::default(),
            config,
            missing_messages: Default::default(),
            received_messages: Default::default(),
            timers: Default::default(),
            cache: Default::default(),
            dispatch_timer_scheduled: false,
        }
    }

    // TODO: optimization step from the paper

    pub fn handle(&mut self, event: InEvent<PA>, io: &mut impl IO<PA>) {
        match event {
            InEvent::RecvMessage(from, message) => self.handle_message(from, message, io),
            InEvent::Broadcast(data) => self.do_broadcast(data, io),
            InEvent::NeighborUp(peer) => self.on_neighbor_up(peer),
            InEvent::NeighborDown(peer) => self.on_neighbor_down(peer),
            InEvent::TimerExpired(timer) => match timer {
                Timer::DispatchLazyPush => self.on_dispatch_timer(io),
                Timer::SendGraft(id) => {
                    self.on_send_graft_timer(id.clone(), io);
                }
            },
        }
    }

    fn handle_message(&mut self, sender: PA, message: Message, io: &mut impl IO<PA>) {
        match message {
            Message::Gossip(details) => self.on_gossip(sender, details, io),
            Message::Prune => self.on_prune(sender),
            Message::IHave(details) => self.on_ihave(sender, details, io),
            Message::Graft(details) => self.on_graft(sender, details, io),
        }
    }

    /// Dispatches messages from lazy queue over to lazy peers.
    fn on_dispatch_timer(&mut self, io: &mut impl IO<PA>) {
        for (peer, list) in self.lazy_push_queue.drain() {
            io.push(OutEvent::SendMessage(peer, Message::IHave(list)));
        }

        self.dispatch_timer_scheduled = false;
    }

    /// Send a gossip message.
    /// Will be pushed in full to eager peers.
    /// Pushing the message ids to the lazy peers is delayed by a timer.
    fn do_broadcast(&mut self, data: Bytes, io: &mut impl IO<PA>) {
        let id = blake3::hash(&data).into();
        let message = Gossip {
            id,
            round: Round(0),
            content: data,
        };
        let me = self.me.clone();
        self.eager_push(message.clone(), &me, io);
        self.lazy_push(message.clone(), &me, io);
        self.received_messages.insert(id);
        self.cache.insert(id, message);
    }

    fn on_gossip(&mut self, sender: PA, message: Gossip, io: &mut impl IO<PA>) {
        if self.received_messages.contains(&message.id) {
            self.add_lazy(sender.clone());
            io.push(OutEvent::SendMessage(sender, Message::Prune));
        } else {
            self.received_messages.insert(message.id);
            let forward = Gossip {
                id: message.id,
                content: message.content.clone(),
                round: message.round.next(),
            };
            self.eager_push(forward.clone(), &sender, io);
            self.lazy_push(forward, &sender, io);
            io.push(OutEvent::EmitEvent(Event::Received(message.content)));
        }
    }

    fn on_prune(&mut self, sender: PA) {
        self.add_lazy(sender);
    }

    fn on_ihave(&mut self, sender: PA, ihaves: Vec<IHave>, io: &mut impl IO<PA>) {
        for ihave in ihaves {
            if self.received_messages.contains(&ihave.id) {
                let record = LazyPush {
                    id: ihave.id,
                    round: ihave.round,
                    peer: sender.clone(),
                };
                self.missing_messages.insert(record);
                self.timers.insert(ihave.id);
                io.push(OutEvent::ScheduleTimer(
                    self.config.ihave_timeout,
                    Timer::SendGraft(ihave.id),
                ));
            }
        }
    }

    fn on_send_graft_timer(&mut self, id: MessageId, io: &mut impl IO<PA>) {
        if !self.timers.contains(&id) {
            self.timers.insert(id);
            io.push(OutEvent::ScheduleTimer(
                self.config.graft_timeout,
                Timer::SendGraft(id),
            ));
        }
        if let Some(entry) = remove_first_match(&mut self.missing_messages, |x| x.id == id) {
            self.add_eager(entry.peer.clone());
            let message = Message::Graft(Graft {
                id,
                round: entry.round,
            });
            io.push(OutEvent::SendMessage(entry.peer, message));
        }
    }

    fn on_graft(&mut self, sender: PA, details: Graft, io: &mut impl IO<PA>) {
        self.add_eager(sender.clone());
        if self.received_messages.contains(&details.id) {
            if let Some(message) = self.cache.get(&details.id) {
                io.push(OutEvent::SendMessage(
                    sender,
                    Message::Gossip(message.clone()),
                ));
            }
        }
    }

    fn on_neighbor_up(&mut self, peer: PA) {
        self.eager_push_peers.insert(peer);
    }

    fn on_neighbor_down(&mut self, peer: PA) {
        self.missing_messages.retain(|keep| keep.peer != peer);
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.remove(&peer);
    }

    /// Moves peer into eager set.
    fn add_eager(&mut self, peer: PA) {
        self.lazy_push_peers.remove(&peer);
        self.eager_push_peers.insert(peer);
    }

    /// Moves peer into lazy set.
    fn add_lazy(&mut self, peer: PA) {
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.insert(peer);
    }

    /// Immediatelly sends message to eager peers.
    fn eager_push(&mut self, gossip: Gossip, sender: &PA, io: &mut impl IO<PA>) {
        for peer in self
            .eager_push_peers
            .iter()
            .filter(|peer| **peer != self.me && *peer != sender)
        {
            io.push(OutEvent::SendMessage(
                *peer,
                Message::Gossip(gossip.clone()),
            ));
        }
    }

    /// Puts lazy message announcements on top of the queue which will be consumed into batched
    /// IHave message once dispatch trigger activates (it's cyclic operation).
    fn lazy_push(&mut self, gossip: Gossip, sender: &PA, io: &mut impl IO<PA>) {
        for peer in self.lazy_push_peers.iter().filter(|x| *x != sender) {
            self.lazy_push_queue.entry(*peer).or_default().push(IHave {
                id: gossip.id,
                round: gossip.round,
            });
        }
        if !self.dispatch_timer_scheduled {
            io.push(OutEvent::ScheduleTimer(
                self.config.dispatch_timeout,
                Timer::DispatchLazyPush,
            ));
            self.dispatch_timer_scheduled = true;
        }
    }
}

fn remove_first_match<T: Eq + Hash + Clone>(
    set: &mut IndexSet<T>,
    find: impl Fn(&T) -> bool,
) -> Option<T> {
    let found = set.iter().enumerate().find(|(_idx, value)| find(value));
    if let Some((index, _found)) = found {
        set.shift_remove_index(index)
    } else {
        None
    }
}
