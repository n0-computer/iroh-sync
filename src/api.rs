use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::Mutex,
};

use blake3::Hash;
use crossbeam::channel;
use once_cell::sync::Lazy;
use url::Url;

#[derive(Debug, Clone)]
pub struct AuthorKeypair {
    name: String,
}

impl AuthorKeypair {
    pub fn new(name: impl AsRef<str>) -> Self {
        AuthorKeypair {
            name: name.as_ref().into(),
        }
    }
}

impl Display for AuthorKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "author:{}", self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    name: String,
    blobs: HashMap<String, Blob>,
}

impl std::hash::Hash for Collection {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.name.as_bytes());
    }
}

impl Display for Collection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "collection:{}", self.name)
    }
}

impl Collection {
    pub fn new(name: impl AsRef<str>) -> Self {
        Collection {
            name: name.as_ref().into(),
            blobs: HashMap::default(),
        }
    }

    pub fn insert(&mut self, blob_builder: BlobBuilder) -> Blob {
        let blob = blob_builder.build(self);
        self.blobs.insert(blob.name().into(), blob.clone());
        blob
    }

    pub fn all(&self) -> impl Iterator<Item = &Blob> {
        self.blobs.values()
    }
}

pub struct BlobBuilder {
    name: String,
    content: Vec<u8>,
}

impl BlobBuilder {
    pub fn new(name: impl AsRef<str>) -> Self {
        BlobBuilder {
            name: name.as_ref().into(),
            content: Vec::new(),
        }
    }
    pub fn content(mut self, content: impl AsRef<[u8]>) -> Self {
        self.content = content.as_ref().to_vec();
        self
    }

    pub fn build(self, collection: &Collection) -> Blob {
        let hash = blake3::hash(&self.content);
        Blob {
            name: self.name,
            collection: collection.clone(),
            content: self.content,
            hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Blob {
    name: String,
    collection: Collection,
    content: Vec<u8>,
    hash: Hash,
}

impl Blob {
    pub fn collection(&self) -> &Collection {
        &self.collection
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn set_content(&mut self, content: impl AsRef<[u8]>) {
        self.content = content.as_ref().to_vec();
    }
}

static PEERS: Lazy<Mutex<HashMap<Url, Peer>>> = Lazy::new(|| HashMap::new().into());
struct Peer {
    connections: Vec<(channel::Sender<PeerMessage>, channel::Receiver<PeerMessage>)>,
}

pub struct Syncer {
    // TODO: multiple?
    peer: Url,
    auth: AuthorKeypair,
    connection: Option<(channel::Sender<PeerMessage>, channel::Receiver<PeerMessage>)>,
    synced_collections: HashSet<Collection>,
}

enum PeerMessage {}

impl Syncer {
    pub fn builder() -> SyncerBuilder {
        SyncerBuilder::default()
    }

    pub fn connect(&mut self) {
        // TODO: actually dial the peer
        let mut l = PEERS.lock().unwrap();
        let peer = l.entry(self.peer.clone()).or_insert_with(|| Peer {
            connections: Vec::new(),
        });
        let (s0, r0) = channel::unbounded();
        let (s1, r1) = channel::unbounded();

        peer.connections.push((s0, r1));
        self.connection = Some((s1, r0));
    }

    pub fn watcher(&self) -> Watcher {
        todo!()
    }

    pub fn sync_collection(&mut self, collection: &Collection) {
        self.synced_collections.insert(collection.clone());
    }
}

pub struct Watcher {
    receiver: channel::Receiver<Change>,
}

impl Watcher {
    pub fn next(&self) -> Option<Change> {
        self.receiver.recv().ok()
    }
}

#[derive(Debug)]
pub struct Change {}

#[derive(Default)]
pub struct SyncerBuilder {
    peer: Option<Url>,
    auth: Option<AuthorKeypair>,
}

impl SyncerBuilder {
    pub fn peer(mut self, url: impl AsRef<str>) -> Self {
        self.peer = Some(url.as_ref().parse().expect("invalid url"));
        self
    }

    pub fn auth(mut self, keypair: &AuthorKeypair) -> Self {
        self.auth = Some(keypair.clone());
        self
    }

    pub fn build(self) -> Syncer {
        let mut syncer = Syncer {
            peer: self.peer.expect("missing peer"),
            auth: self.auth.expect("missing auth"),
            synced_collections: Default::default(),
            connection: None,
        };

        syncer.connect();
        syncer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example() {
        // Create an author keypair.
        let author_keypair = AuthorKeypair::new("cool-bear");

        // Create a collection (and its keypair)
        let mut collection = Collection::new("demo");

        // Create a blob
        let blob_builder =
            BlobBuilder::new("/notes/cool-bear-hello").content(b"hello world from cool-bear");
        let mut blob = collection.insert(blob_builder);

        println!(
            "created blob {}/{}: {}",
            blob.collection(), // the collection identifier
            blob.name(),       // the identifier of the blob in the collection
            blob.hash(),       // the blake3 hash of the blob
        );
        // => created blob +chatting.b..../notes/cool-bear-hello: b....

        // Setup a connection to a sync node
        let mut syncer = Syncer::builder()
            .peer("https://demo.iroh.computer")
            .auth(&author_keypair) // authenticate via the author keypair (could be a different key)
            .build();

        // Setup facilities to react to updates the syncer is processsing
        let watcher = syncer.watcher();
        std::thread::spawn(move || {
            while let Some(change) = watcher.next() {
                println!("new change incoming: {:?}", change);
            }

            println!("my watch has ended");
        });

        // this syncer will keep track of this collection and sync changes back and forth now
        syncer.sync_collection(&collection);

        // print all currently known blob
        for blob in collection.all() {
            println!("blob {}: {}", blob.name(), blob.hash());
        }

        // Update the original blob
        blob.set_content(b"hello world, this is an updated version");

        // changes will now be synced to the connected syncer (and any peers that are connected to it)
    }
}
