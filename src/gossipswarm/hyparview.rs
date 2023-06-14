//! Implementation of the HyParView membership protocol
//!
//! The implementation is based on [this paper][paper] by Joao Leitao, Jose Pereira, Luıs Rodrigues
//! and the [example implementation][impl] by Bartosz Sypytkowski
//!
//! [paper]: https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf
//! [impl]: https://gist.github.com/Horusiath/84fac596101b197da0546d1697580d99

use std::{collections::HashSet, hash::Hash, time::Duration};

use derive_more::{From, Sub};
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::{util::IndexSet, PeerAddress, IO};

#[derive(Debug)]
pub enum InEvent<PA> {
    Message(PA, Message<PA>),
    TimerExpired(Timer),
    PeerDisconnected(PA),
    RequestJoin(PA),
}

pub enum OutEvent<PA> {
    SendMessage(PA, Message<PA>),
    ScheduleTimer(Duration, Timer),
    DisconnectPeer(PA),
    EmitEvent(Event<PA>),
}

#[derive(Clone, Debug)]
pub enum Event<PA> {
    NeighborUp(PA),
    NeighborDown(PA),
}

#[derive(Debug)]
pub enum Timer {
    DoShuffle,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message<PA> {
    /// Sent to a peer if you want to join the swarm
    Join,
    /// When receiving Join, ForwardJoin is forwarded to the peer's ActiveView to introduce the
    /// new member.
    ForwardJoin(ForwardJoin<PA>),
    /// A shuffle request is sent occasionally to re-shuffle the PassiveView with contacts from
    /// other peers.
    Shuffle(Shuffle<PA>),
    /// Peers reply to Shuffle requests with a random subset of their PassiveView.
    ShuffleReply(ShuffleReply<PA>),
    /// Request to add sender to an active view of recipient. If `highPriority` is set, it cannot
    /// be denied.
    Neighbor(Neighbor),
    /// Disconnect request. If `alive` is set, sender can safely be added to passive set for future
    /// reconnections.
    /// If `response` is set, recipient should answer with its own `Disconnect` (with
    /// respond=false) as well.
    Disconnect(Disconnect),
}

#[derive(From, Sub, Eq, PartialEq, Clone, Debug, Copy, Serialize, Deserialize)]
pub struct Ttl(pub u16);
impl Ttl {
    pub fn expired(&self) -> bool {
        *self == Ttl(0)
    }
    pub fn next(&self) -> Ttl {
        *self - Ttl(1)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForwardJoin<PA> {
    peer: PA,
    ttl: Ttl,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Shuffle<PA> {
    origin: PA,
    nodes: Vec<PA>,
    ttl: Ttl,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShuffleReply<PA> {
    nodes: Vec<PA>,
}

impl<PA: Hash + Eq> ShuffleReply<PA> {
    pub fn from_iter(nodes: impl IntoIterator<Item = PA>) -> Self {
        Self {
            nodes: HashSet::<PA>::from_iter(nodes.into_iter())
                .into_iter()
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Neighbor {
    high_priority: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Disconnect {
    alive: Alive,
    respond: Respond,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub active_view_capacity: usize,
    pub passive_view_capacity: usize,
    pub active_random_walk_length: Ttl,
    pub passive_random_walk_length: Ttl,
    pub shuffle_ttl: Ttl,
    pub shuffle_active_view_count: usize,
    pub shuffle_passive_view_count: usize,
    pub shuffle_interval: Duration,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            active_view_capacity: 5,
            passive_view_capacity: 24,
            active_random_walk_length: Ttl(5),
            passive_random_walk_length: Ttl(2),
            shuffle_ttl: Ttl(2),
            shuffle_active_view_count: 2,
            shuffle_passive_view_count: 2,
            shuffle_interval: Duration::from_secs(60),
        }
    }
}

pub type Respond = bool;
pub type Alive = bool;

#[derive(Debug)]
pub struct State<PA, RG = ThreadRng> {
    me: PA,
    active_view: IndexSet<PA>,
    passive_view: IndexSet<PA>,
    config: Config,
    shuffle_scheduled: bool,
    rng: RG,
}

impl<PA> State<PA, rand::rngs::OsRng>
where
    PA: PeerAddress,
{
    pub fn new(me: PA, config: Config) -> Self {
        Self {
            me,
            active_view: IndexSet::new(),
            passive_view: IndexSet::new(),
            config,
            shuffle_scheduled: false,
            rng: rand::rngs::OsRng,
        }
    }
}

impl<PA, RG> State<PA, RG>
where
    PA: PeerAddress,
    RG: Rng,
{
    pub fn handle(&mut self, event: InEvent<PA>, io: &mut impl IO<PA>) {
        match event {
            InEvent::Message(from, message) => self.handle_message(from, message, io),
            InEvent::TimerExpired(timer) => match timer {
                Timer::DoShuffle => self.do_shuffle(io),
            },
            InEvent::PeerDisconnected(peer) => self.handle_disconnect(peer, io),
            InEvent::RequestJoin(peer) => self.handle_join(peer, io),
        }
    }

    fn handle_message(&mut self, from: PA, message: Message<PA>, io: &mut impl IO<PA>) {
        let is_disconnect = matches!(message, Message::Disconnect(Disconnect { .. }));
        match message {
            Message::Join => self.on_join(from, io),
            Message::ForwardJoin(details) => self.on_forward_join(from, details, io),
            Message::Shuffle(details) => self.on_shuffle(from, details, io),
            Message::ShuffleReply(details) => self.on_shuffle_reply(details),
            Message::Neighbor(details) => self.on_neighbor(from, details, io),
            Message::Disconnect(details) => self.on_disconnect(from, details, io),
        }

        // Disconnect from passive nodes right after receiving a message.
        if !is_disconnect && !self.active_view.contains(&from) {
            let message = Message::Disconnect(Disconnect {
                alive: true,
                respond: false,
            });
            io.push(OutEvent::SendMessage(from, message));
            io.push(OutEvent::DisconnectPeer(from));
        }
    }

    fn handle_join(&mut self, peer: PA, io: &mut impl IO<PA>) {
        io.push(OutEvent::SendMessage(peer, Message::Join));
    }

    fn handle_disconnect(&mut self, peer: PA, io: &mut impl IO<PA>) {
        self.on_disconnect(
            peer,
            // TODO: Is true, true correct? Recheck with paper.
            Disconnect {
                alive: true,
                respond: true,
            },
            io,
        );
    }

    fn on_join(&mut self, peer: PA, io: &mut impl IO<PA>) {
        self.add_active(peer.clone(), true, io);
        let ttl = self.config.active_random_walk_length;
        for node in self.active_view.iter_without(&peer) {
            let message = Message::ForwardJoin(ForwardJoin {
                peer: peer.clone(),
                ttl,
            });
            io.push(OutEvent::SendMessage(node.clone(), message));
        }
    }

    fn on_forward_join(&mut self, sender: PA, message: ForwardJoin<PA>, io: &mut impl IO<PA>) {
        if message.ttl.expired() || self.active_view.is_empty() {
            self.add_active(message.peer, true, io);
        } else {
            if message.ttl == self.config.passive_random_walk_length {
                self.add_passive(message.peer);
            }
            match self
                .active_view
                .pick_random_without(&[&sender], &mut self.rng)
            {
                None => self.add_active(message.peer, true, io),
                Some(next) => {
                    let message = Message::ForwardJoin(ForwardJoin {
                        peer: message.peer,
                        ttl: message.ttl.next(),
                    });
                    io.push(OutEvent::SendMessage(*next, message));
                }
            }
        }
    }

    fn on_neighbor(&mut self, from: PA, details: Neighbor, io: &mut impl IO<PA>) {
        if !self.shuffle_scheduled {
            io.push(OutEvent::ScheduleTimer(
                self.config.shuffle_interval,
                Timer::DoShuffle,
            ));
            self.shuffle_scheduled = true;
        }
        if details.high_priority || !self.passive_is_full() {
            self.add_active(from, details.high_priority, io)
        }
    }

    fn on_shuffle(&mut self, from: PA, shuffle: Shuffle<PA>, io: &mut impl IO<PA>) {
        if shuffle.ttl.expired() {
            let len = shuffle.nodes.len();
            for node in shuffle.nodes {
                self.add_passive(node);
            }
            let nodes = self.passive_view.shuffled_max(len, &mut self.rng);
            let message = Message::ShuffleReply(ShuffleReply::from_iter(nodes));
            io.push(OutEvent::SendMessage(shuffle.origin, message));
        } else {
            if let Some(node) = self
                .active_view
                .pick_random_without(&[&shuffle.origin, &from], &mut self.rng)
            {
                let message = Message::Shuffle(Shuffle {
                    origin: shuffle.origin,
                    nodes: shuffle.nodes,
                    ttl: shuffle.ttl.next(),
                });
                io.push(OutEvent::SendMessage(*node, message));
            }
        }
    }

    fn on_shuffle_reply(&mut self, message: ShuffleReply<PA>) {
        for node in message.nodes {
            self.add_passive(node);
        }
    }

    fn on_disconnect(&mut self, peer: PA, details: Disconnect, io: &mut impl IO<PA>) {
        if let Some(_) = self.remove_active(&peer, details.respond, io) {
            if !self.active_is_full() {
                if let Some(node) = self
                    .passive_view
                    .pick_random_without(&[&peer], &mut self.rng)
                {
                    let high_priority = self.active_view.is_empty();
                    let message = Message::Neighbor(Neighbor { high_priority });
                    io.push(OutEvent::SendMessage(*node, message));
                }
            }
            if details.alive {
                self.add_passive(peer.clone());
            }
        }
    }

    fn do_shuffle(&mut self, io: &mut impl IO<PA>) {
        if let Some(node) = self.active_view.pick_random(&mut self.rng) {
            let active = self.active_view.shuffled_without_max(
                &[&node],
                self.config.shuffle_active_view_count,
                &mut self.rng,
            );
            let passive = self.passive_view.shuffled_without_max(
                &[&node],
                self.config.shuffle_passive_view_count,
                &mut self.rng,
            );
            let mut nodes = HashSet::new();
            nodes.extend(active);
            nodes.extend(passive);
            let message = Shuffle {
                origin: self.me.clone(),
                nodes: HashSet::<PA>::from_iter(nodes.into_iter())
                    .into_iter()
                    .collect(),
                ttl: self.config.shuffle_ttl,
            };
            io.push(OutEvent::SendMessage(*node, Message::Shuffle(message)));
        }
        io.push(OutEvent::ScheduleTimer(
            self.config.shuffle_interval,
            Timer::DoShuffle,
        ));
    }

    fn passive_is_full(&self) -> bool {
        self.passive_view.len() >= self.config.passive_view_capacity
    }

    fn active_is_full(&self) -> bool {
        self.active_view.len() >= self.config.active_view_capacity
    }

    /// Add a peer to the passive view.
    ///
    /// If the passive view is full, it will first remove a random peer and then insert the new peer.
    /// If a peer is currently in the active view it will not be added.
    fn add_passive(&mut self, peer: PA) {
        if self.active_view.contains(&peer) || self.passive_view.contains(&peer) || peer == self.me
        {
            return;
        }
        if self.passive_is_full() {
            self.passive_view.remove_random(&mut self.rng);
        }
        self.passive_view.insert(peer);
    }

    /// Remove a peer from the active view.
    ///
    /// If respond is true, a Disconnect message will be sent to the peer.
    fn remove_active(&mut self, peer: &PA, respond: Respond, io: &mut impl IO<PA>) -> Option<PA> {
        self.active_view
            .get_index_of(peer)
            .and_then(|idx| self.remove_active_by_index(idx, respond, io))
    }

    fn remove_active_by_index(
        &mut self,
        peer_index: usize,
        respond: Respond,
        io: &mut impl IO<PA>,
    ) -> Option<PA> {
        if let Some(peer) = self.active_view.remove_index(peer_index) {
            if respond {
                let message = Message::Disconnect(Disconnect {
                    alive: true,
                    respond: false,
                });
                io.push(OutEvent::SendMessage(peer, message));
            }
            io.push(OutEvent::DisconnectPeer(peer));
            io.push(OutEvent::EmitEvent(Event::NeighborDown(peer)));
            self.add_passive(peer);
            Some(peer)
        } else {
            None
        }
    }

    /// Remove a random peer from the active view.
    fn remove_active_random(&mut self, io: &mut impl IO<PA>) {
        if let Some(index) = self.active_view.pick_random_index(&mut self.rng) {
            self.remove_active_by_index(index, true, io);
        }
    }

    /// Add a peer to the active view.
    ///
    /// If the active view is currently full, a random peer will be removed first.
    /// Sends a Neighbor message to the peer. If high_priority is true, the peer
    /// may not deny the Neighbor request.
    fn add_active(&mut self, peer: PA, high_priority: bool, io: &mut impl IO<PA>) {
        if self.active_view.contains(&peer) || peer == self.me {
            return;
        }
        if self.active_is_full() {
            self.remove_active_random(io);
        }
        self.passive_view.remove(&peer);
        self.active_view.insert(peer.clone());
        let message = Message::Neighbor(Neighbor { high_priority });
        io.push(OutEvent::SendMessage(peer, message));
        io.push(OutEvent::EmitEvent(Event::NeighborUp(peer)));
    }
}
