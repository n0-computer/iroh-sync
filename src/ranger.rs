//! Implementation of Set Reconcilliation based on
//! "Range-Based Set Reconciliation" by Aljoscha Meyer.
//!

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::Bound;

#[derive(Debug, Clone, PartialEq)]
pub enum Range<K> {
    /// All elements in a set, denoted with x, y: x = y
    All(K),
    /// [x, y): x < y
    /// Includes x, but not y
    Regular(K, K),
    /// S \ [y, x) y < x
    /// This means that ranges are "wrap around" conceptually.
    /// Includes x, but not y
    Exclusion(K, K),
}

impl<K> Range<K>
where
    K: Ord,
{
    fn x(&self) -> &K {
        match self {
            Range::All(k) => k,
            Range::Regular(k, _) => k,
            Range::Exclusion(k, _) => k,
        }
    }

    fn y(&self) -> &K {
        match self {
            Range::All(k) => k,
            Range::Regular(_, k) => k,
            Range::Exclusion(_, k) => k,
        }
    }

    fn new(x: K, y: K) -> Self {
        match x.cmp(&y) {
            Ordering::Less => Range::Regular(x, y),
            Ordering::Greater => Range::Exclusion(x, y),
            Ordering::Equal => Range::All(x),
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct Fingerprint([u8; 32]);

impl Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fp({})", blake3::Hash::from(self.0).to_hex())
    }
}

impl Fingerprint {
    /// The fingerprint of the empty set
    fn empty() -> Self {
        Fingerprint::new(&[][..])
    }

    fn new(val: impl AsRef<[u8]>) -> Self {
        Fingerprint(blake3::hash(val.as_ref()).into())
    }
}

impl std::ops::BitXorAssign for Fingerprint {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= b;
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RangeFingerprint<K> {
    pub range: Range<K>,
    /// The fingerprint of `range`.
    pub fingerprint: Fingerprint,
}

/// Transfers items inside a range to the other participant.
#[derive(Debug, Clone, PartialEq)]
pub struct RangeItem<K, V> {
    /// The range out of which the elements are.
    pub range: Range<K>,
    pub values: Vec<(K, V)>,
    /// If false, requests to send local items in the range.
    /// Otherwise not.
    pub have_local: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessagePart<K, V> {
    RangeFingerprint(RangeFingerprint<K>),
    RangeItem(RangeItem<K, V>),
}

impl<K, V> MessagePart<K, V> {
    pub fn is_range_fingerprint(&self) -> bool {
        matches!(self, MessagePart::RangeFingerprint(_))
    }

    pub fn is_range_item(&self) -> bool {
        matches!(self, MessagePart::RangeItem(_))
    }

    pub fn values(&self) -> Option<&[(K, V)]> {
        match self {
            MessagePart::RangeFingerprint(_) => None,
            MessagePart::RangeItem(RangeItem { values, .. }) => Some(&values),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message<K, V> {
    parts: Vec<MessagePart<K, V>>,
}

impl<K, V> Message<K, V>
where
    K: Ord + Clone + AsRef<[u8]> + Default,
{
    /// Construct the initial message.
    fn init(store: &Store<K, V>) -> Self {
        let x = store.get_first().clone();
        let range = Range::All(x);
        let fingerprint = store.get_fingerprint(&range);
        let part = MessagePart::RangeFingerprint(RangeFingerprint { range, fingerprint });
        Message { parts: vec![part] }
    }

    pub fn parts(&self) -> &[MessagePart<K, V>] {
        &self.parts
    }
}

#[derive(Debug)]
struct Store<K, V> {
    data: BTreeMap<K, V>,
}

impl<K, V> Default for Store<K, V> {
    fn default() -> Self {
        Store {
            data: BTreeMap::default(),
        }
    }
}

impl<K, V> Store<K, V>
where
    K: Ord + Clone + AsRef<[u8]> + Default,
{
    /// Get a random element.
    fn get_first(&self) -> K {
        if let Some((k, _)) = self.data.first_key_value() {
            k.clone()
        } else {
            Default::default()
        }
    }

    /// Calculate the fingerprint of the given range.
    fn get_fingerprint(&self, range: &Range<K>) -> Fingerprint {
        let elements = self.get_range(range);
        if elements.is_empty() {
            return Fingerprint::empty();
        }
        let mut fp = Fingerprint::new(elements[0].0);
        for el in &elements[1..] {
            fp ^= Fingerprint::new(el.0);
        }

        fp
    }

    /// Insert the given key value pair.
    fn put(&mut self, k: K, v: V) {
        self.data.insert(k, v);
    }

    /// Returns all items in the given range
    fn get_range(&self, range: &Range<K>) -> Vec<(&K, &V)> {
        match range {
            Range::All(_) => self
                .data
                .range((Bound::<K>::Unbounded, Bound::<K>::Unbounded))
                .collect(),
            Range::Regular(x, y) => self
                .data
                .range((Bound::Included(x), Bound::Excluded(y)))
                .collect(),
            Range::Exclusion(x, y) => self
                .data
                .range((Bound::Included(x), Bound::Unbounded))
                .chain(self.data.range((Bound::Unbounded, Bound::Excluded(y))))
                .collect(),
        }
    }

    fn all(&self) -> impl Iterator<Item = (&K, &V)> {
        self.data.iter()
    }
}

#[derive(Debug)]
pub struct Peer<K, V> {
    store: Store<K, V>,
    /// Up to how many values to send immediately, before sending only a fingerprint.
    max_set_size: usize,
    /// `k` in the protocol, how many splits to generate. at least 2
    split_factor: usize,
}

impl<K, V> Default for Peer<K, V> {
    fn default() -> Self {
        Peer {
            store: Store::default(),
            max_set_size: 1,
            split_factor: 2,
        }
    }
}

impl<K, V> Peer<K, V>
where
    K: PartialEq + Ord + Clone + AsRef<[u8]> + Default + Debug,
    V: Clone + Debug,
{
    /// Generates the initial message.
    pub fn initial_message(&self) -> Message<K, V> {
        Message::init(&self.store)
    }

    /// Processes an incoming message and produces a response.
    /// If terminated, returns `None`
    pub fn process_message(&mut self, message: Message<K, V>) -> Option<Message<K, V>> {
        let mut out = Vec::new();

        // TODO: can these allocs be avoided?
        let mut items = Vec::new();
        let mut fingerprints = Vec::new();
        for part in message.parts {
            match part {
                MessagePart::RangeItem(item) => {
                    items.push(item);
                }
                MessagePart::RangeFingerprint(fp) => {
                    fingerprints.push(fp);
                }
            }
        }

        // Process item messages
        for RangeItem {
            range,
            values,
            have_local,
        } in items
        {
            let diff: Option<Vec<_>> = if have_local {
                None
            } else {
                Some(
                    self.store
                        .get_range(&range)
                        .into_iter()
                        .filter(|(k, _)| values.iter().find(|(vk, _)| &vk == k).is_none())
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
            };

            // Store incoming values
            for (k, v) in values {
                self.store.put(k, v);
            }

            if let Some(diff) = diff {
                if !diff.is_empty() {
                    out.push(MessagePart::RangeItem(RangeItem {
                        range,
                        values: diff,
                        have_local: true,
                    }));
                }
            }
        }

        // Process fingerprint messages
        for RangeFingerprint { range, fingerprint } in fingerprints {
            let local_fingerprint = self.store.get_fingerprint(&range);

            // Case1 Match, nothing to do
            if local_fingerprint == fingerprint {
                continue;
            }

            // Case2 Recursion Anchor
            let local_values = self.store.get_range(&range);
            if local_values.len() <= 1 || fingerprint == Fingerprint::empty() {
                out.push(MessagePart::RangeItem(RangeItem {
                    range,
                    values: local_values
                        .into_iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    have_local: false,
                }));
            } else {
                // Case3 Recurse
                // Create partition
                // m0 = x < m1 < .. < mk = y, with k>= 2
                // such that [ml, ml+1) is nonempty
                let mut ranges = Vec::with_capacity(self.split_factor);
                let chunk_len = div_ceil(local_values.len(), self.split_factor);

                for i in 0..self.split_factor {
                    let (x, y) = if i == 0 {
                        // first
                        (range.x(), local_values[(i + 1) * chunk_len].0)
                    } else if i == self.split_factor - 1 {
                        // last
                        (local_values[i * chunk_len].0, range.y())
                    } else {
                        // regular
                        (
                            local_values[i * chunk_len].0,
                            local_values[(i + 1) * chunk_len].0,
                        )
                    };
                    let range = Range::new(x.clone(), y.clone());
                    ranges.push(range);
                }

                for range in ranges.into_iter() {
                    let chunk = self.store.get_range(&range);
                    // Add either the fingerprint or the item set
                    let fingerprint = self.store.get_fingerprint(&range);
                    if chunk.len() > self.max_set_size {
                        out.push(MessagePart::RangeFingerprint(RangeFingerprint {
                            range,
                            fingerprint,
                        }));
                    } else {
                        out.push(MessagePart::RangeItem(RangeItem {
                            range,
                            values: chunk
                                .into_iter()
                                .map(|(k, v)| {
                                    let k: K = k.clone();
                                    let v: V = v.clone();
                                    (k, v)
                                })
                                .collect(),
                            have_local: false,
                        }));
                    }
                }
            }
        }

        // If we have any parts, return a message
        if !out.is_empty() {
            Some(Message { parts: out })
        } else {
            None
        }
    }

    /// Insert a key value pair.
    pub fn put(&mut self, k: K, v: V) {
        self.store.put(k, v);
    }

    /// List all existing key value pairs.
    pub fn all(&self) -> impl Iterator<Item = (&K, &V)> {
        self.store.all()
    }
}

/// Sadly https://doc.rust-lang.org/std/primitive.usize.html#method.div_ceil is still unstable..
fn div_ceil(a: usize, b: usize) -> usize {
    debug_assert!(a != 0);
    debug_assert!(b != 0);

    a / b + (a % b != 0) as usize
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    #[test]
    fn test_paper_1() {
        let alice_set = [("ape", 1), ("eel", 1), ("fox", 1), ("gnu", 1)];
        let bob_set = [
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1),
            ("hog", 1),
        ];

        let res = sync(&alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        // Initial message
        assert_eq!(res.alice_to_bob[0].parts.len(), 1);
        assert!(res.alice_to_bob[0].parts[0].is_range_fingerprint());

        // Response from Bob - recurse once
        assert_eq!(res.bob_to_alice[0].parts.len(), 2);
        assert!(res.bob_to_alice[0].parts[0].is_range_fingerprint());
        assert!(res.bob_to_alice[0].parts[1].is_range_fingerprint());

        // Last response from Alice
        assert_eq!(res.alice_to_bob[1].parts.len(), 3);
        assert!(res.alice_to_bob[1].parts[0].is_range_item());
        assert!(res.alice_to_bob[1].parts[1].is_range_fingerprint());
        assert!(res.alice_to_bob[1].parts[2].is_range_item());

        // Last response from Bob
        assert_eq!(res.bob_to_alice[1].parts.len(), 2);
        assert!(res.bob_to_alice[1].parts[0].is_range_item());
        assert!(res.bob_to_alice[1].parts[1].is_range_item());

        res.print_messages();
    }

    #[test]
    fn test_paper_2() {
        let alice_set = [
            ("ape", 1),
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1), // the only value being sent
            ("gnu", 1),
            ("hog", 1),
        ];
        let bob_set = [
            ("ape", 1),
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("gnu", 1),
            ("hog", 1),
        ];

        let res = sync(&alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        res.print_messages();
    }

    #[test]
    fn test_paper_3() {
        let alice_set = [
            ("ape", 1),
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1),
            ("gnu", 1),
            ("hog", 1),
        ];
        let bob_set = [("ape", 1), ("cat", 1), ("eel", 1), ("gnu", 1)];

        let res = sync(&alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        res.print_messages();
    }

    struct SyncResult<V> {
        alice: Peer<String, V>,
        bob: Peer<String, V>,
        alice_to_bob: Vec<Message<String, V>>,
        bob_to_alice: Vec<Message<String, V>>,
    }

    impl<V> SyncResult<V>
    where
        V: Debug,
    {
        fn print_messages(&self) {
            let len = std::cmp::max(self.alice_to_bob.len(), self.bob_to_alice.len());
            for i in 0..len {
                if let Some(msg) = self.alice_to_bob.get(i) {
                    println!("A -> B:");
                    print_message(msg);
                }
                if let Some(msg) = self.bob_to_alice.get(i) {
                    println!("B -> A:");
                    print_message(msg);
                }
            }
        }
    }

    fn print_message<V>(msg: &Message<String, V>)
    where
        V: Debug,
    {
        for part in &msg.parts {
            match part {
                MessagePart::RangeFingerprint(RangeFingerprint { range, fingerprint }) => {
                    println!(
                        "  RangeFingerprint({}, {}, {:?})",
                        range.x(),
                        range.y(),
                        fingerprint
                    );
                }
                MessagePart::RangeItem(RangeItem {
                    range,
                    values,
                    have_local,
                }) => {
                    println!(
                        "  RangeItem({} | {}) (local?: {})\n  {:?}",
                        range.x(),
                        range.y(),
                        have_local,
                        values,
                    );
                }
            }
        }
    }

    fn sync<V>(alice_set: &[(&str, V)], bob_set: &[(&str, V)]) -> SyncResult<V>
    where
        V: Clone + Debug + PartialEq,
    {
        let mut expected_set = BTreeMap::new();

        let mut alice = Peer::<String, V>::default();
        for (k, v) in alice_set {
            alice.put(k.to_string(), v.clone());
            expected_set.insert(k.to_string(), v.clone());
        }

        let mut bob = Peer::<String, V>::default();
        for (k, v) in bob_set {
            bob.put(k.to_string(), v.clone());
            expected_set.insert(k.to_string(), v.clone());
        }

        let mut alice_to_bob = Vec::new();
        let mut bob_to_alice = Vec::new();
        let initial_message = alice.initial_message();

        let mut next_to_bob = Some(initial_message);
        let mut rounds = 0;
        while let Some(msg) = next_to_bob.take() {
            assert!(rounds < 100, "too many rounds");
            rounds += 1;
            alice_to_bob.push(msg.clone());

            if let Some(msg) = bob.process_message(msg) {
                bob_to_alice.push(msg.clone());
                next_to_bob = alice.process_message(msg);
            }
        }
        let alice_now: Vec<_> = alice.all().collect();
        assert_eq!(expected_set.iter().collect::<Vec<_>>(), alice_now, "alice");

        let bob_now: Vec<_> = bob.all().collect();
        assert_eq!(expected_set.iter().collect::<Vec<_>>(), bob_now, "bob");

        // Check that values were never sent twice
        let mut alice_sent = BTreeMap::new();
        for msg in &alice_to_bob {
            for part in &msg.parts {
                if let Some(values) = part.values() {
                    for (key, value) in values {
                        assert!(
                            alice_sent.insert(key.clone(), value.clone()).is_none(),
                            "alice: duplicate {:?} - {:?}",
                            key,
                            value
                        );
                    }
                }
            }
        }

        let mut bob_sent = BTreeMap::new();
        for msg in &bob_to_alice {
            for part in &msg.parts {
                if let Some(values) = part.values() {
                    for (key, value) in values {
                        assert!(
                            bob_sent.insert(key.clone(), value.clone()).is_none(),
                            "bob: duplicate {:?} - {:?}",
                            key,
                            value
                        );
                    }
                }
            }
        }

        SyncResult {
            alice,
            bob,
            alice_to_bob,
            bob_to_alice,
        }
    }

    #[test]
    fn store_get_range() {
        let mut store = Store::<&'static str, usize>::default();
        let set = [
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1),
            ("hog", 1),
        ];

        for (k, v) in &set {
            store.put(*k, *v);
        }

        let all: Vec<_> = store
            .get_range(&Range::All(""))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&all, &set[..]);

        let regular: Vec<_> = store
            .get_range(&Range::Regular("bee", "eel"))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[..3]);

        // empty start
        let regular: Vec<_> = store
            .get_range(&Range::Regular("", "eel"))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[..3]);

        let regular: Vec<_> = store
            .get_range(&Range::Regular("cat", "hog"))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[1..5]);

        let excluded: Vec<_> = store
            .get_range(&Range::Exclusion("fox", "bee"))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();

        assert_eq!(excluded.len(), 2);
        assert_eq!(excluded[0].0, "fox");
        assert_eq!(excluded[1].0, "hog");

        let excluded: Vec<_> = store
            .get_range(&Range::Exclusion("fox", "doe"))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();

        assert_eq!(excluded.len(), 4);
        assert_eq!(excluded[0].0, "fox");
        assert_eq!(excluded[1].0, "hog");
        assert_eq!(excluded[2].0, "bee");
        assert_eq!(excluded[3].0, "cat");
    }

    #[test]
    fn test_div_ceil() {
        assert_eq!(div_ceil(1, 1), 1 / 1);
        assert_eq!(div_ceil(2, 1), 2 / 1);
        assert_eq!(div_ceil(4, 2), 4 / 2);

        assert_eq!(div_ceil(3, 2), 2);
        assert_eq!(div_ceil(5, 3), 2);
    }
}
