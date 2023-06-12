// Names and concepts are roughly based on Willows design at the moment:
//
// https://hackmd.io/DTtck8QOQm6tZaQBBtTf7w
//
// This is going to change!

use std::{cmp::Ordering, collections::HashMap, time::SystemTime};

use blake3::Hash;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;

use crate::ranger::{AsFingerprint, Fingerprint, Peer, RangeKey};

#[derive(Debug)]
pub struct Author {
    priv_key: SigningKey,
    id: AuthorId,
}

impl Author {
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let priv_key = SigningKey::generate(rng);
        let id = AuthorId(priv_key.verifying_key());

        Author { priv_key, id }
    }

    pub fn id(&self) -> &AuthorId {
        &self.id
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.priv_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.id.verify(msg, signature)
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorId(VerifyingKey);

impl AuthorId {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct Namespace {
    priv_key: SigningKey,
    id: NamespaceId,
}

impl Namespace {
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let priv_key = SigningKey::generate(rng);
        let id = NamespaceId(priv_key.verifying_key());

        Namespace { priv_key, id }
    }

    pub fn id(&self) -> &NamespaceId {
        &self.id
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.priv_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.id.verify(msg, signature)
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct NamespaceId(VerifyingKey);

impl NamespaceId {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Debug)]
pub struct Replica {
    namespace: Namespace,
    peer: Peer<RecordIdentifier, SignedEntry>,
    content: HashMap<Hash, Vec<u8>>,
}

impl Replica {
    pub fn new(namespace: Namespace) -> Self {
        Replica {
            namespace,
            peer: Peer::default(),
            content: HashMap::default(),
        }
    }

    /// Inserts a new record at the given key.
    pub fn insert(&mut self, key: impl AsRef<[u8]>, author: &Author, data: impl AsRef<[u8]>) {
        let id = RecordIdentifier::new(key, self.namespace.id(), author.id());
        let record = Record::from_data(data.as_ref(), self.namespace.id());

        // Store content
        self.content
            .insert(*record.content_hash(), data.as_ref().to_vec());

        // Store signed entries
        let entry = Entry::new(id.clone(), record);
        let signed_entry = entry.sign(&self.namespace, author);
        self.peer.put(id, signed_entry);
    }

    /// Gets all entries matching this key and author.
    pub fn get<'a, 'b: 'a, 'c: 'a>(
        &'a self,
        key: impl AsRef<[u8]> + 'c,
        author: &'b AuthorId,
    ) -> impl Iterator<Item = &SignedEntry> + 'a {
        self.peer.all().filter_map(move |(_, e)| {
            if e.entry.id.key == key.as_ref() && &e.entry.id.author == author {
                Some(e)
            } else {
                None
            }
        })
    }

    pub fn peer_mut(&mut self) -> &mut Peer<RecordIdentifier, SignedEntry> {
        &mut self.peer
    }
}

/// A signed entry.
#[derive(Debug, Clone)]
pub struct SignedEntry {
    signature: EntrySignature,
    entry: Entry,
}

impl SignedEntry {
    pub fn from_entry(entry: Entry, namespace: &Namespace, author: &Author) -> Self {
        let signature = EntrySignature::from_entry(&entry, namespace, author);
        SignedEntry { signature, entry }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        self.signature
            .verify(&self.entry, &self.entry.id.namespace, &self.entry.id.author)
    }

    pub fn signature(&self) -> &EntrySignature {
        &self.signature
    }

    pub fn entry(&self) -> &Entry {
        &self.entry
    }
}

/// Signature over an entry.
#[derive(Debug, Clone)]
pub struct EntrySignature {
    author_signature: Signature,
    namespace_signature: Signature,
}

impl EntrySignature {
    pub fn from_entry(entry: &Entry, namespace: &Namespace, author: &Author) -> Self {
        // TODO: this should probably include a namespace prefix
        // namespace in the cryptographic sense.
        let bytes = entry.to_vec();
        let namespace_signature = namespace.sign(&bytes);
        let author_signature = author.sign(&bytes);

        EntrySignature {
            author_signature,
            namespace_signature,
        }
    }

    pub fn verify(
        &self,
        entry: &Entry,
        namespace: &NamespaceId,
        author: &AuthorId,
    ) -> Result<(), SignatureError> {
        let bytes = entry.to_vec();
        namespace.verify(&bytes, &self.namespace_signature)?;
        author.verify(&bytes, &self.author_signature)?;

        Ok(())
    }
}

/// A single entry in a replica.
#[derive(Debug, Clone)]
pub struct Entry {
    id: RecordIdentifier,
    record: Record,
}

impl Entry {
    pub fn new(id: RecordIdentifier, record: Record) -> Self {
        Entry { id, record }
    }

    pub fn id(&self) -> &RecordIdentifier {
        &self.id
    }

    pub fn record(&self) -> &Record {
        &self.record
    }

    /// Serialize this entry into its canonical byte representation used for signing.
    pub fn into_vec(&self, out: &mut Vec<u8>) {
        self.id.as_bytes(out);
        self.record.as_bytes(out);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.into_vec(&mut out);
        out
    }

    pub fn sign(self, namespace: &Namespace, author: &Author) -> SignedEntry {
        SignedEntry::from_entry(self, namespace, author)
    }
}

/// The indentifier of a record.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordIdentifier {
    /// The key of the record.
    key: Vec<u8>,
    /// The namespace this record belongs to.
    namespace: NamespaceId,
    /// The author that wrote this record.
    author: AuthorId,
}

impl AsFingerprint for RecordIdentifier {
    fn as_fingerprint(&self) -> crate::ranger::Fingerprint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update(self.author.as_bytes());
        hasher.update(&self.key);
        Fingerprint(hasher.finalize().into())
    }
}

impl PartialOrd for NamespaceId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NamespaceId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PartialOrd for AuthorId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuthorId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl RangeKey for RecordIdentifier {
    fn contains(&self, range: &crate::ranger::Range<Self>) -> bool {
        // For now we just do key inclusion and check if namespace and author match
        if self.namespace != range.x().namespace || self.namespace != range.y().namespace {
            return false;
        }
        if self.author != range.x().author || self.author != range.y().author {
            return false;
        }

        let mapped_range = range.clone().map(|x, y| (x.key, y.key));
        crate::ranger::contains(&self.key, &mapped_range)
    }
}

impl RecordIdentifier {
    pub fn new(key: impl AsRef<[u8]>, namespace: &NamespaceId, author: &AuthorId) -> Self {
        RecordIdentifier {
            key: key.as_ref().to_vec(),
            namespace: *namespace,
            author: *author,
        }
    }

    pub fn as_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.namespace.as_bytes());
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(&self.key);
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn namespace(&self) -> &NamespaceId {
        &self.namespace
    }

    pub fn author(&self) -> &AuthorId {
        &self.author
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    /// Record creation timestamp. Counted as micros since the Unix epoch.
    timestamp: u64,
    /// Length of the data referenced by `hash`.
    len: u64,
    hash: Hash,
}

impl Record {
    pub fn new(timestamp: u64, len: u64, hash: Hash) -> Self {
        Record {
            timestamp,
            len,
            hash,
        }
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn content_len(&self) -> u64 {
        self.len
    }

    pub fn content_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn from_data(data: impl AsRef<[u8]>, namespace: &NamespaceId) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time drift")
            .as_micros() as u64;
        let data = data.as_ref();
        let len = data.len() as u64;
        // Salted hash
        // TODO: do we actually want this?
        // TODO: this should probably use a namespace prefix if used
        let mut hasher = blake3::Hasher::new();
        hasher.update(namespace.as_bytes());
        hasher.update(data);
        let hash = hasher.finalize();

        Self::new(timestamp, len, hash)
    }

    pub fn as_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.len.to_be_bytes());
        out.extend_from_slice(self.hash.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basics() {
        let mut rng = rand::thread_rng();
        let alice = Author::new(&mut rng);
        let myspace = Namespace::new(&mut rng);

        let record_id = RecordIdentifier::new("/my/key", myspace.id(), alice.id());
        let record = Record::from_data(b"this is my cool data", myspace.id());
        let entry = Entry::new(record_id, record);
        let signed_entry = entry.sign(&myspace, &alice);
        signed_entry.verify().expect("failed to verify");

        let mut my_replica = Replica::new(myspace);
        for i in 0..10 {
            my_replica.insert(format!("/{i}"), &alice, format!("{i}: hello from alice"));
        }

        for i in 0..10 {
            let res: Vec<_> = my_replica.get(format!("/{i}"), alice.id()).collect();
            assert_eq!(res.len(), 1);
            let len = format!("{i}: hello from alice").as_bytes().len() as u64;
            assert_eq!(res[0].entry().record().content_len(), len);

            res[0].verify().expect("invalid signature");
        }
    }

    #[test]
    fn test_replica_sync() {
        let alice_set = ["ape", "eel", "fox", "gnu"];
        let bob_set = ["bee", "cat", "doe", "eel", "fox", "hog"];

        let mut rng = rand::thread_rng();
        let author = Author::new(&mut rng);
        let myspace = Namespace::new(&mut rng);
        let mut alice = Replica::new(myspace.clone());
        for el in &alice_set {
            alice.insert(el, &author, el);
        }

        let mut bob = Replica::new(myspace);
        for el in &bob_set {
            bob.insert(el, &author, el);
        }

        sync(&author, &mut alice, &mut bob, &alice_set, &bob_set);
    }

    fn sync(
        author: &Author,
        alice: &mut Replica,
        bob: &mut Replica,
        alice_set: &[&str],
        bob_set: &[&str],
    ) {
        // Sync alice - bob
        let mut next_to_bob = Some(alice.peer_mut().initial_message());
        let mut rounds = 0;
        while let Some(msg) = next_to_bob.take() {
            assert!(rounds < 100, "too many rounds");
            rounds += 1;
            if let Some(msg) = bob.peer_mut().process_message(msg) {
                next_to_bob = alice.peer_mut().process_message(msg);
            }
        }

        // Check result
        for el in alice_set {
            assert_eq!(
                alice.get(el, author.id()).collect::<Vec<_>>().len(),
                1,
                "{}",
                el
            );
            assert_eq!(
                bob.get(el, author.id()).collect::<Vec<_>>().len(),
                1,
                "{}",
                el
            );
        }

        for el in bob_set {
            assert_eq!(
                alice.get(el, author.id()).collect::<Vec<_>>().len(),
                1,
                "{}",
                el
            );
            assert_eq!(
                bob.get(el, author.id()).collect::<Vec<_>>().len(),
                1,
                "{}",
                el
            );
        }
    }
}
