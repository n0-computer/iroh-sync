// Names and concepts are roughly based on Willows design at the moment:
//
// https://hackmd.io/DTtck8QOQm6tZaQBBtTf7w
//
// This is going to change!

use std::time::SystemTime;

use blake3::Hash;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;

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

#[derive(Debug, Clone, Copy)]
pub struct AuthorId(VerifyingKey);

impl AuthorId {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Debug)]
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

#[derive(Debug, Copy, Clone)]
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
    entries: Vec<SignedEntry>,
}

/// A signed entry.
#[derive(Debug)]
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
}

/// Signature over an entry.
#[derive(Debug)]
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
#[derive(Debug)]
pub struct Entry {
    id: RecordIdentifier,
    record: Record,
}

impl Entry {
    pub fn new(id: RecordIdentifier, record: Record) -> Self {
        Entry { id, record }
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
#[derive(Debug)]
pub struct RecordIdentifier {
    /// The key of the record.
    key: Vec<u8>,
    /// The namespace this record belongs to.
    namespace: NamespaceId,
    /// The author that wrote this record.
    author: AuthorId,
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
}

#[derive(Debug)]
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
    }
}
