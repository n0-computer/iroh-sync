//! Implementation of Set Reconcilliation based on
//! "Range-Based Set Reconciliation" by Aljoscha Meyer.
//!

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::Bound;

/// Stores a range.
///
/// There are three possibilities
/// - x, x: All elements in a set, denoted with
/// - [x, y): x < y: Includes x, but not y
/// - S \ [y, x) y < x: Includes x, but not y.
/// This means that ranges are "wrap around" conceptually.
#[derive(Debug, Clone, PartialEq)]
pub struct Range<K> {
    x: K,
    y: K,
}

impl<K> Range<K> {
    pub fn x(&self) -> &K {
        &self.x
    }

    pub fn y(&self) -> &K {
        &self.y
    }

    pub fn new(x: K, y: K) -> Self {
        Range { x, y }
    }
}

impl<K> From<(K, K)> for Range<K> {
    fn from((x, y): (K, K)) -> Self {
        Range { x, y }
    }
}

impl<K> Range<K>
where
    K: Ord,
{
    /// Is this key inside the range?
    pub fn contains(&self, k: &K) -> bool {
        match self.range_type() {
            Ordering::Equal => true,
            Ordering::Less => &self.x <= k && k < &self.y,
            Ordering::Greater => &self.x > k && k <= &self.y,
        }
    }

    pub fn range_type(&self) -> Ordering {
        self.x.cmp(&self.y)
    }

    pub fn is_all(&self) -> bool {
        matches!(self.range_type(), Ordering::Equal)
    }

    pub fn is_regular(&self) -> bool {
        matches!(self.range_type(), Ordering::Less)
    }

    pub fn is_wrap_around(&self) -> bool {
        matches!(self.range_type(), Ordering::Greater)
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

    fn new<T: AsFingerprint>(val: T) -> Self {
        val.as_fingerprint()
    }
}

pub trait AsFingerprint {
    fn as_fingerprint(&self) -> Fingerprint;
}

impl<T: AsRef<[u8]>> AsFingerprint for T {
    fn as_fingerprint(&self) -> Fingerprint {
        Fingerprint(blake3::hash(self.as_ref()).into())
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
    K: Ord + Clone + Default + AsFingerprint,
{
    /// Construct the initial message.
    fn init(store: &Store<K, V>, limit: Option<&Range<K>>) -> Self {
        let x = store.get_first().clone();
        let range = Range::new(x.clone(), x);
        let fingerprint = store.get_fingerprint(&range, limit);
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
    K: Ord + Clone + Default + AsFingerprint,
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
    fn get_fingerprint(&self, range: &Range<K>, limit: Option<&Range<K>>) -> Fingerprint {
        let elements = self.get_range(range, limit);
        if elements.is_empty() {
            return Fingerprint::empty();
        }
        let mut fp = elements[0].0.as_fingerprint();
        for el in &elements[1..] {
            fp ^= el.0.as_fingerprint();
        }

        fp
    }

    /// Insert the given key value pair.
    fn put(&mut self, k: K, v: V) {
        self.data.insert(k, v);
    }

    /// Returns all items in the given range
    fn get_range(&self, range: &Range<K>, limit: Option<&Range<K>>) -> Vec<(&K, &V)> {
        match range.range_type() {
            Ordering::Equal => {
                let bound = (Bound::<K>::Unbounded, Bound::<K>::Unbounded);
                if let Some(limit) = limit {
                    self.data
                        .range(bound)
                        .filter(|(k, _)| limit.contains(k))
                        .collect()
                } else {
                    self.data.range(bound).collect()
                }
            }
            Ordering::Less => {
                let bound = (Bound::Included(&range.x), Bound::Excluded(&range.y));
                if let Some(limit) = limit {
                    self.data
                        .range(bound)
                        .filter(|(k, _)| limit.contains(k))
                        .collect()
                } else {
                    self.data.range(bound).collect()
                }
            }
            Ordering::Greater => {
                let bound_a = (Bound::Unbounded, Bound::Excluded(&range.y));
                let bound_b = (Bound::Included(&range.x), Bound::Unbounded);
                if let Some(limit) = limit {
                    self.data
                        .range(bound_a)
                        .chain(self.data.range(bound_b))
                        .filter(|(k, _)| limit.contains(k))
                        .collect()
                } else {
                    self.data
                        .range(bound_a)
                        .chain(self.data.range(bound_b))
                        .collect()
                }
            }
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
    limit: Option<Range<K>>,
}

impl<K, V> Default for Peer<K, V> {
    fn default() -> Self {
        Peer {
            store: Store::default(),
            max_set_size: 1,
            split_factor: 2,
            limit: None,
        }
    }
}

impl<K, V> Peer<K, V>
where
    K: PartialEq + Ord + Clone + Default + Debug + AsFingerprint,
    V: Clone + Debug,
{
    pub fn with_limit(limit: Range<K>) -> Self {
        Peer {
            store: Store::default(),
            max_set_size: 1,
            split_factor: 2,
            limit: Some(limit),
        }
    }

    /// Generates the initial message.
    pub fn initial_message(&self) -> Message<K, V> {
        Message::init(&self.store, self.limit.as_ref())
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
                        .get_range(&range, self.limit.as_ref())
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
            let local_fingerprint = self.store.get_fingerprint(&range, self.limit.as_ref());

            // Case1 Match, nothing to do
            if local_fingerprint == fingerprint {
                continue;
            }

            // Case2 Recursion Anchor
            let local_values = self.store.get_range(&range, self.limit.as_ref());
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

                // Select the first index, for which the key is larger than the x of the range.
                let mut start_index = local_values
                    .iter()
                    .position(|(k, _)| range.x() <= k)
                    .unwrap_or(0);
                let max_len = local_values.len();
                for i in 0..self.split_factor {
                    let s_index = start_index;
                    let start = (s_index * chunk_len) % max_len;
                    let e_index = s_index + 1;
                    let end = (e_index * chunk_len) % max_len;

                    let (x, y) = if i == 0 {
                        // first
                        (range.x(), local_values[end].0)
                    } else if i == self.split_factor - 1 {
                        // last
                        (local_values[start].0, range.y())
                    } else {
                        // regular
                        (local_values[start].0, local_values[end].0)
                    };
                    let range = Range::new(x.clone(), y.clone());
                    ranges.push(range);
                    start_index += 1;
                }

                for range in ranges.into_iter() {
                    let chunk = self.store.get_range(&range, self.limit.as_ref());
                    // Add either the fingerprint or the item set
                    let fingerprint = self.store.get_fingerprint(&range, self.limit.as_ref());
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

        let res = sync(None, &alice_set, &bob_set);
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

        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");
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

        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");
    }

    #[test]
    fn test_limits() {
        let alice_set = [("ape", 1), ("bee", 1), ("cat", 1)];
        let bob_set = [("ape", 1), ("cat", 1), ("doe", 1)];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        // With Limit: just ape
        let limit = ("ape", "bee").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 0, "B -> A message count");

        // With Limit: just bee, cat
        let limit = ("bee", "doe").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
    }

    #[test]
    fn test_prefixes_simple() {
        let alice_set = [("/foo/bar", 1), ("/foo/baz", 1), ("/foo/cat", 1)];
        let bob_set = [("/foo/bar", 1), ("/alice/bar", 1), ("/alice/baz", 1)];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        // With Limit: just /alice
        let limit = ("/alice", "/b").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
    }

    #[test]
    fn test_prefixes_empty_alice() {
        let alice_set = [];
        let bob_set = [("/foo/bar", 1), ("/alice/bar", 1), ("/alice/baz", 1)];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");

        // With Limit: just /alice
        let limit = ("/alice", "/b").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
    }

    #[test]
    fn test_prefixes_empty_bob() {
        let alice_set = [("/foo/bar", 1), ("/foo/baz", 1), ("/foo/cat", 1)];
        let bob_set = [];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");

        // With Limit: just /alice
        let limit = ("/alice", "/b").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 0, "B -> A message count");
    }

    #[test]
    fn test_multikey() {
        #[derive(Default, Clone, PartialEq, Eq)]
        struct Multikey {
            author: [u8; 4],
            key: Vec<u8>,
        }

        impl PartialOrd for Multikey {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for Multikey {
            fn cmp(&self, other: &Self) -> Ordering {
                let author = self.author.cmp(&other.author);
                if author == Ordering::Equal {
                    self.key.cmp(&other.key)
                } else {
                    author
                }
            }
        }

        impl Debug for Multikey {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let key = if let Ok(key) = std::str::from_utf8(&self.key) {
                    key.to_string()
                } else {
                    hex::encode(&self.key)
                };
                f.debug_struct("Multikey")
                    .field("author", &hex::encode(&self.author))
                    .field("key", &key)
                    .finish()
            }
        }
        impl AsFingerprint for Multikey {
            fn as_fingerprint(&self) -> Fingerprint {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&self.author);
                hasher.update(&self.key);
                Fingerprint(hasher.finalize().into())
            }
        }

        impl Multikey {
            fn new(author: [u8; 4], key: impl AsRef<[u8]>) -> Self {
                Multikey {
                    author,
                    key: key.as_ref().to_vec(),
                }
            }
        }
        let author_a = [1u8; 4];
        let author_b = [2u8; 4];
        let alice_set = [
            (Multikey::new(author_a, "ape"), 1),
            (Multikey::new(author_a, "bee"), 1),
            (Multikey::new(author_b, "bee"), 1),
            (Multikey::new(author_a, "doe"), 1),
        ];
        let bob_set = [
            (Multikey::new(author_a, "ape"), 1),
            (Multikey::new(author_a, "bee"), 1),
            (Multikey::new(author_a, "cat"), 1),
            (Multikey::new(author_b, "cat"), 1),
        ];

        // No limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        // Needs more thought

        // Only author_a
        let limit = Range::new(Multikey::new(author_a, ""), Multikey::new(author_b, ""));
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");

        // All authors, but only cat
        let limit = Range::new(
            Multikey::new(author_a, "cat"),
            Multikey::new(author_b, "doe"),
        );
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
    }

    struct SyncResult<K, V> {
        alice: Peer<K, V>,
        bob: Peer<K, V>,
        alice_to_bob: Vec<Message<K, V>>,
        bob_to_alice: Vec<Message<K, V>>,
    }

    impl<K, V> SyncResult<K, V>
    where
        K: Debug,
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

    fn print_message<K, V>(msg: &Message<K, V>)
    where
        K: Debug,
        V: Debug,
    {
        for part in &msg.parts {
            match part {
                MessagePart::RangeFingerprint(RangeFingerprint { range, fingerprint }) => {
                    println!(
                        "  RangeFingerprint({:?}, {:?}, {:?})",
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
                        "  RangeItem({:?} | {:?}) (local?: {})\n  {:?}",
                        range.x(),
                        range.y(),
                        have_local,
                        values,
                    );
                }
            }
        }
    }

    fn sync<K, V>(
        limit: Option<Range<K>>,
        alice_set: &[(K, V)],
        bob_set: &[(K, V)],
    ) -> SyncResult<K, V>
    where
        K: PartialEq + Ord + Clone + Default + Debug + AsFingerprint,
        V: Clone + Debug + PartialEq,
    {
        println!("Using Limit: {:?}", limit);
        let mut expected_set_alice = BTreeMap::new();
        let mut expected_set_bob = BTreeMap::new();

        let mut alice = if let Some(limit) = limit.clone() {
            Peer::<K, V>::with_limit(limit)
        } else {
            Peer::<K, V>::default()
        };
        for (k, v) in alice_set {
            alice.put(k.clone(), v.clone());

            let include = if let Some(ref limit) = limit {
                limit.contains(k)
            } else {
                true
            };
            if include {
                expected_set_bob.insert(k.clone(), v.clone());
            }
            // alices things are always in alices store
            expected_set_alice.insert(k.clone(), v.clone());
        }

        let mut bob = if let Some(limit) = limit.clone() {
            Peer::<K, V>::with_limit(limit)
        } else {
            Peer::<K, V>::default()
        };
        for (k, v) in bob_set {
            bob.put(k.clone(), v.clone());
            let include = if let Some(ref limit) = limit {
                limit.contains(k)
            } else {
                true
            };
            if include {
                expected_set_alice.insert(k.clone(), v.clone());
            }
            // bobs things are always in bobs store
            expected_set_bob.insert(k.clone(), v.clone());
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
        let res = SyncResult {
            alice,
            bob,
            alice_to_bob,
            bob_to_alice,
        };
        res.print_messages();

        let alice_now: Vec<_> = res.alice.all().collect();
        assert_eq!(
            expected_set_alice.iter().collect::<Vec<_>>(),
            alice_now,
            "alice"
        );

        let bob_now: Vec<_> = res.bob.all().collect();
        assert_eq!(expected_set_bob.iter().collect::<Vec<_>>(), bob_now, "bob");

        // Check that values were never sent twice
        let mut alice_sent = BTreeMap::new();
        for msg in &res.alice_to_bob {
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
        for msg in &res.bob_to_alice {
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

        res
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
            .get_range(&Range::new("", ""), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&all, &set[..]);

        let regular: Vec<_> = store
            .get_range(&("bee", "eel").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[..3]);

        // empty start
        let regular: Vec<_> = store
            .get_range(&("", "eel").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[..3]);

        let regular: Vec<_> = store
            .get_range(&("cat", "hog").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[1..5]);

        let excluded: Vec<_> = store
            .get_range(&("fox", "bee").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();

        assert_eq!(excluded.len(), 2);
        assert_eq!(excluded[0].0, "fox");
        assert_eq!(excluded[1].0, "hog");

        let excluded: Vec<_> = store
            .get_range(&("fox", "doe").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();

        assert_eq!(excluded.len(), 4);
        assert_eq!(excluded[0].0, "bee");
        assert_eq!(excluded[1].0, "cat");
        assert_eq!(excluded[2].0, "fox");
        assert_eq!(excluded[3].0, "hog");

        // Limit
        let all: Vec<_> = store
            .get_range(&("", "").into(), Some(&("bee", "doe").into()))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&all, &set[..2]);
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
