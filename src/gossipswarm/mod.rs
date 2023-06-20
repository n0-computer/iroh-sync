use std::{
    collections::VecDeque,
    fmt,
    hash::Hash,
    time::{Duration, Instant},
};

use bytes::Bytes;
use derive_more::From;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod hyparview;
mod plumtree;
mod util;

use hyparview::InEvent as SwarmIn;
use plumtree::InEvent as GossipIn;

pub trait PeerAddress: Hash + Eq + Copy + fmt::Debug + Ord + Serialize + DeserializeOwned {}
impl<T> PeerAddress for T where T: Hash + Eq + Copy + fmt::Debug + Ord + Serialize + DeserializeOwned
{}

/// Input event to the state handler.
#[derive(Debug)]
pub enum InEvent<PA> {
    /// Message received from the network.
    RecvMessage(PA, Message<PA>),
    /// Execute a command from the application.
    Command(Command<PA>),
    /// Trigger a previously scheduled timer.
    TimerExpired(Timer<PA>),
    /// Peer disconnected on the network level.
    PeerDisconnected(PA),
}

/// An output event from the state handler.
#[derive(Debug)]
pub enum OutEvent<PA> {
    /// Send a message on the network
    SendMessage(PA, Message<PA>),
    /// Emit an event to the application.
    EmitEvent(Event<PA>),
    /// Schedule a timer. The runtime is responsible for sending an [InEvent::TimerExpired]
    /// after the duration.
    ScheduleTimer(Duration, Timer<PA>),
    /// Close the connection to a peer on the network level.
    DisconnectPeer(PA),
}

impl<PA> From<hyparview::OutEvent<PA>> for OutEvent<PA> {
    fn from(event: hyparview::OutEvent<PA>) -> Self {
        use hyparview::OutEvent::*;
        match event {
            SendMessage(to, message) => Self::SendMessage(to, message.into()),
            ScheduleTimer(delay, timer) => Self::ScheduleTimer(delay, timer.into()),
            DisconnectPeer(peer) => Self::DisconnectPeer(peer),
            EmitEvent(event) => Self::EmitEvent(event.into()),
        }
    }
}

impl<PA> From<plumtree::OutEvent<PA>> for OutEvent<PA> {
    fn from(event: plumtree::OutEvent<PA>) -> Self {
        use plumtree::OutEvent::*;
        match event {
            SendMessage(to, message) => Self::SendMessage(to, message.into()),
            ScheduleTimer(delay, timer) => Self::ScheduleTimer(delay, timer.into()),
            EmitEvent(event) => Self::EmitEvent(event.into()),
        }
    }
}

pub trait IO<PA: Clone> {
    fn push(&mut self, event: impl Into<OutEvent<PA>>);
}

#[derive(From, Debug, Serialize, Deserialize, Clone)]
pub enum Message<PA> {
    Swarm(hyparview::Message<PA>),
    Gossip(plumtree::Message),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Event<PA> {
    NeighborUp(PA),
    NeighborDown(PA),
    Received(Bytes),
}

impl<PA> From<hyparview::Event<PA>> for Event<PA> {
    fn from(value: hyparview::Event<PA>) -> Self {
        match value {
            hyparview::Event::NeighborUp(peer) => Self::NeighborUp(peer),
            hyparview::Event::NeighborDown(peer) => Self::NeighborDown(peer),
        }
    }
}

impl<PA> From<plumtree::Event> for Event<PA> {
    fn from(value: plumtree::Event) -> Self {
        match value {
            plumtree::Event::Received(peer) => Self::Received(peer),
        }
    }
}

#[derive(From, Debug)]
pub enum Timer<PA> {
    Swarm(hyparview::Timer<PA>),
    Gossip(plumtree::Timer),
}

#[derive(Debug)]
pub enum Command<PA> {
    Join(PA),
    Broadcast(Bytes),
}

impl<PA: Clone> IO<PA> for VecDeque<OutEvent<PA>> {
    fn push(&mut self, event: impl Into<OutEvent<PA>>) {
        self.push_back(event.into())
    }
}

#[derive(Clone, Default)]
pub struct Config {
    pub membership: hyparview::Config,
    pub broadcast: plumtree::Config,
}

/// The Gossipswarm maintains the state of peer network and sends and receives gossip messages over
/// the swarm.
#[derive(Debug)]
pub struct State<PA> {
    me: PA,
    swarm: hyparview::State<PA, rand::rngs::OsRng>,
    gossip: plumtree::State<PA>,
    outbox: VecDeque<OutEvent<PA>>,
    stats: Stats,
}

impl<PA: PeerAddress> State<PA> {
    /// Initialize the local state.
    pub fn new(me: PA, config: Config) -> Self {
        Self {
            swarm: hyparview::State::new(me.clone(), config.membership),
            gossip: plumtree::State::new(me.clone(), config.broadcast),
            me,
            outbox: VecDeque::new(),
            stats: Stats::default(),
        }
    }

    /// The address of your local endpoint.
    pub fn endpoint(&self) -> &PA {
        &self.me
    }

    /// Handle an incoming event.
    ///
    /// Returns an iterator of outgoing events that must be processed by the application.
    #[must_use]
    pub fn handle<'a>(
        &'a mut self,
        event: InEvent<PA>,
        now: Instant,
    ) -> impl Iterator<Item = OutEvent<PA>> + 'a {
        let io = &mut self.outbox;
        // Process the event, store out events in outbox.
        match event {
            InEvent::Command(command) => match command {
                Command::Join(peer) => self.swarm.handle(SwarmIn::RequestJoin(peer), now, io),
                Command::Broadcast(data) => self.gossip.handle(GossipIn::Broadcast(data), io),
            },
            InEvent::RecvMessage(from, message) => {
                self.stats.messages_received += 1;
                match message {
                    Message::Swarm(message) => {
                        self.swarm
                            .handle(SwarmIn::RecvMessage(from, message), now, io)
                    }
                    Message::Gossip(message) => {
                        self.gossip.handle(GossipIn::RecvMessage(from, message), io)
                    }
                }
            }
            InEvent::TimerExpired(timer) => match timer {
                Timer::Swarm(timer) => self.swarm.handle(SwarmIn::TimerExpired(timer), now, io),
                Timer::Gossip(timer) => self.gossip.handle(GossipIn::TimerExpired(timer), io),
            },
            InEvent::PeerDisconnected(peer) => {
                self.swarm.handle(SwarmIn::PeerDisconnected(peer), now, io);
                self.gossip.handle(GossipIn::PeerDisconnected(peer), io);
            }
        }

        // Forward NeigborUp and NeighborDown events from hyparview to plumtree
        let mut io = VecDeque::new();
        for event in self.outbox.iter() {
            match event {
                OutEvent::EmitEvent(Event::NeighborUp(peer)) => self
                    .gossip
                    .handle(GossipIn::NeighborUp(peer.clone()), &mut io),
                OutEvent::EmitEvent(Event::NeighborDown(peer)) => self
                    .gossip
                    .handle(GossipIn::NeighborDown(peer.clone()), &mut io),
                _ => {}
            }
        }
        // Note that this is a no-op because plumtree::handle(NeighborUp | NeighborDown)
        // above does not emit any OutEvents.
        self.outbox.extend(io.drain(..));

        // Update sent message counter
        self.stats.messages_sent += self
            .outbox
            .iter()
            .filter(|event| matches!(event, OutEvent::SendMessage(_, _)))
            .count();

        self.outbox.drain(..)
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[cfg(test)]
mod test {
    use std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        time::{Duration, Instant},
    };

    use tracing::debug;

    use super::{Command, Config, Event, InEvent, OutEvent, PeerAddress, State, Timer};

    #[test]
    fn hyparview_smoke() {
        // Create a network with 4 nodes and active_view_capacity 2
        let mut config = Config::default();
        config.membership.active_view_capacity = 2;
        let mut network = Network::new(Instant::now());
        for i in 0..4 {
            network.push(State::new(i, config.clone()));
        }

        // Do some joins between nodes 0,1,2
        network.command(0, Command::Join(1));
        network.command(0, Command::Join(2));
        network.command(1, Command::Join(2));
        network.ticks(3);

        // Confirm emitted events
        let actual = network.events_sorted();
        let expected = sort(vec![
            (0, Event::NeighborUp(1)),
            (0, Event::NeighborUp(2)),
            (1, Event::NeighborUp(2)),
            (1, Event::NeighborUp(0)),
            (2, Event::NeighborUp(0)),
            (2, Event::NeighborUp(1)),
        ]);
        assert_eq!(actual, expected);

        // Confirm active connections
        assert_eq!(network.conns(), vec![(0, 1), (0, 2), (1, 2)]);

        // Now let node 3 join node 0.
        // Node 0 is full, so it will disconnect from either node 1 or node 2.
        network.command(3, Command::Join(0));
        network.ticks(3);

        // Confirm emitted events. There's two options because whether node 0 disconnects from
        // node 1 or node 2 is random.
        let actual = network.events_sorted();
        let expected1 = sort(vec![
            (3, Event::NeighborUp(0)),
            (0, Event::NeighborUp(3)),
            (0, Event::NeighborDown(1)),
            (1, Event::NeighborDown(0)),
        ]);
        let expected2 = sort(vec![
            (3, Event::NeighborUp(0)),
            (0, Event::NeighborUp(3)),
            (0, Event::NeighborDown(2)),
            (2, Event::NeighborDown(0)),
        ]);
        assert!((actual == expected1) || (actual == expected2));

        // Confirm active connections.
        if actual == expected1 {
            assert_eq!(network.conns(), vec![(0, 2), (0, 3), (1, 2)]);
        } else {
            assert_eq!(network.conns(), vec![(0, 1), (0, 3), (1, 2)]);
        }
    }

    #[test]
    fn plumtree_smoke() {
        let config = Config::default();
        let mut network = Network::new(Instant::now());
        // build a network with 6 nodes
        for i in 0..6 {
            network.push(State::new(i, config.clone()));
        }

        // connect nodes 1 and 2 to node 0
        (1..3).for_each(|i| network.command(i, Command::Join(0)));
        // connect nodes 4 and 5 to node 3
        (4..6).for_each(|i| network.command(i, Command::Join(3)));
        // run 3 ticks and drain events
        network.ticks(3);
        let _ = network.events();

        // now broadcast a first message
        network.command(1, Command::Broadcast(b"hi1".to_vec().into()));
        network.ticks(3);
        let events = network.events();
        let received: Vec<_> = events
            .filter(|x| matches!(x, (_, Event::Received(_))))
            .collect();
        // message should be received by two other nodes
        assert_eq!(received.len(), 2);

        // now connect the two sections of the swarm
        network.command(2, Command::Join(5));
        network.ticks(3);
        let _ = network.events();

        // now broadcast again
        network.command(1, Command::Broadcast(b"hi2".to_vec().into()));
        network.ticks(4);
        let events = network.events();
        let received: Vec<_> = events
            .filter(|x| matches!(x, (_, Event::Received(_))))
            .collect();
        // message should be received by all 5 other nodes
        assert_eq!(received.len(), 5);
    }

    pub const TICK_DURATION: Duration = Duration::from_millis(50);

    /// Test network implementation.
    /// Stores events in VecDeques and processes on ticks.
    /// Timers are checked after each tick. The local time is increased with TICK_DURATION before
    /// each tick.
    /// Note: Panics when sending to an unknown peer.
    struct Network<PA> {
        start: Instant,
        time: Instant,
        tick_duration: Duration,
        outqueue: Vec<(PA, OutEvent<PA>)>,
        inqueues: HashMap<PA, VecDeque<InEvent<PA>>>,
        peers: HashMap<PA, State<PA>>,
        conns: HashSet<ConnId<PA>>,
        events: VecDeque<(PA, Event<PA>)>,
        timers: TimerMap<(PA, Timer)>,
    }
    impl<PA> Network<PA> {
        pub fn new(time: Instant) -> Self {
            Self {
                start: time,
                time,
                tick_duration: TICK_DURATION,
                outqueue: Default::default(),
                inqueues: Default::default(),
                peers: Default::default(),
                conns: Default::default(),
                events: Default::default(),
                timers: TimerMap::new(),
            }
        }
    }

    fn push_back<PA: Eq + std::hash::Hash>(
        inqueues: &mut HashMap<PA, VecDeque<InEvent<PA>>>,
        peer: &PA,
        event: InEvent<PA>,
    ) {
        inqueues.get_mut(&peer).unwrap().push_back(event);
    }

    impl<PA: PeerAddress + Ord> Network<PA> {
        pub fn push(&mut self, peer: State<PA>) {
            self.inqueues.insert(*peer.endpoint(), VecDeque::new());
            self.peers.insert(*peer.endpoint(), peer);
        }

        pub fn events<'a>(&'a mut self) -> impl Iterator<Item = (PA, Event<PA>)> + 'a {
            self.events.drain(..)
        }

        pub fn events_sorted(&mut self) -> Vec<(PA, Event<PA>)> {
            sort(self.events().collect())
        }

        pub fn conns(&self) -> Vec<(PA, PA)> {
            sort(self.conns.iter().cloned().map(Into::into).collect())
        }

        pub fn command(&mut self, peer: PA, command: Command<PA>) {
            debug!(?peer, "~~ COMMAND {command:?}");
            push_back(&mut self.inqueues, &peer, InEvent::Command(command));
        }

        pub fn ticks(&mut self, n: usize) {
            (0..n).for_each(|_| self.tick())
        }

        pub fn get_tick(&self) -> u32 {
            ((self.time - self.start) / self.tick_duration.as_millis() as u32).as_millis() as u32
        }

        pub fn tick(&mut self) {
            self.time += self.tick_duration;
            debug!(tick = self.get_tick(), "~~ TICK");
            // process timers
            for (_time, (peer, timer)) in self.timers.drain_until(&self.time) {
                push_back(&mut self.inqueues, &peer, InEvent::TimerExpired(timer));
            }
            // process inqueues
            for (peer, queue) in self.inqueues.iter_mut() {
                let state = self.peers.get_mut(&peer).unwrap();
                while let Some(event) = queue.pop_front() {
                    debug!(peer = ?peer, "handle {event:?}");
                    let out = state.handle(event);
                    self.outqueue.extend(out.map(|ev| (*peer, ev)));
                }
            }
            // process outqueue
            for (from, event) in self.outqueue.drain(..) {
                match event {
                    OutEvent::SendMessage(to, message) => {
                        self.conns.insert((from, to).into());
                        push_back(&mut self.inqueues, &to, InEvent::RecvMessage(from, message));
                    }
                    OutEvent::ScheduleTimer(delay, timer) => {
                        self.timers.insert(self.time + delay, (from, timer));
                    }
                    OutEvent::DisconnectPeer(to) => {
                        debug!(peer = ?from, other = ?to, "disconnect");
                        self.conns.remove(&(from, to).into());
                        push_back(&mut self.inqueues, &from, InEvent::PeerDisconnected(to));
                        push_back(&mut self.inqueues, &to, InEvent::PeerDisconnected(from));
                    }
                    OutEvent::EmitEvent(event) => {
                        debug!(peer = ?from, "emit   {event:?}");
                        self.events.push_back((from, event));
                    }
                }
            }
        }
    }

    /// A BtreeMap with Instant as key. Allows to process expired items.
    pub struct TimerMap<T>(BTreeMap<Instant, Vec<T>>);
    impl<T> TimerMap<T> {
        pub fn new() -> Self {
            Self(Default::default())
        }
        pub fn insert(&mut self, instant: Instant, item: T) {
            let entry = self.0.entry(instant).or_default();
            entry.push(item);
        }
        pub fn drain_until(&mut self, from: &Instant) -> impl Iterator<Item = (Instant, T)> {
            let split_point = from.clone() + Duration::from_nanos(1);
            let later_half = self.0.split_off(&split_point);
            let expired = std::mem::replace(&mut self.0, later_half);
            expired
                .into_iter()
                .map(|(t, v)| v.into_iter().map(move |v| (t, v)))
                .flatten()
        }
    }

    /// Helper struct for active connections. A sorted tuple.
    #[derive(Debug, Clone, PartialOrd, Ord, Eq, PartialEq, Hash)]
    pub struct ConnId<PA>([PA; 2]);
    impl<PA: Ord> ConnId<PA> {
        pub fn new(a: PA, b: PA) -> Self {
            let mut conn = [a, b];
            conn.sort();
            Self(conn)
        }
    }
    impl<PA: Ord> From<(PA, PA)> for ConnId<PA> {
        fn from((a, b): (PA, PA)) -> Self {
            Self::new(a, b)
        }
    }
    impl<PA: Copy> From<ConnId<PA>> for (PA, PA) {
        fn from(conn: ConnId<PA>) -> (PA, PA) {
            (conn.0[0], conn.0[1])
        }
    }

    fn sort<T: Ord + Clone>(items: Vec<T>) -> Vec<T> {
        let mut sorted = items.clone();
        sorted.sort();
        sorted
    }
}
