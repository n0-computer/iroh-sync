use std::fmt::Display;

use blake3::Hash;

pub struct AuthorKeypair {}

impl AuthorKeypair {
    pub fn new(name: impl AsRef<str>) -> Self {
        todo!()
    }
}

pub struct Collection {}

impl Display for Collection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Collection {
    pub fn new(name: impl AsRef<str>) -> Self {
        todo!()
    }

    pub fn insert(&mut self, blob_name: impl AsRef<str>) -> BlobBuilder {
        todo!()
    }

    pub fn all(&self) -> Vec<&Blob> {
        todo!()
    }
}

pub struct BlobBuilder {}

impl BlobBuilder {
    pub fn content(mut self, content: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    pub fn build(self) -> Blob {
        todo!()
    }
}

pub struct Blob {}

impl Blob {
    pub fn collection(&self) -> &Collection {
        todo!()
    }

    pub fn name(&self) -> &str {
        todo!()
    }

    pub fn hash(&self) -> Hash {
        todo!()
    }

    pub fn set_content(&mut self, content: impl AsRef<[u8]>) {
        todo!()
    }
}

pub struct Syncer {}

impl Syncer {
    pub fn builder() -> SyncerBuilder {
        todo!()
    }

    pub fn watcher(&self) -> Watcher {
        todo!()
    }

    pub fn sync_collection(&self, collection: &Collection) {
        todo!()
    }
}

pub struct Watcher {}

impl Watcher {
    pub fn next(&self) -> Option<Change> {
        todo!()
    }
}

#[derive(Debug)]
pub struct Change {}

pub struct SyncerBuilder {}

impl SyncerBuilder {
    pub fn peer(mut self, url: impl AsRef<str>) -> Self {
        todo!()
    }

    pub fn auth(mut self, keypair: &AuthorKeypair) -> Self {
        todo!()
    }

    pub fn build(mut self) -> Syncer {
        todo!()
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
        let mut blob = collection
            .insert("/notes/cool-bear-hello") // creates a BlobBuilder
            .content(b"hello world from cool-bear") // content
            .build();

        println!(
            "created blob {}/{}: {}",
            blob.collection(), // the collection identifier
            blob.name(),       // the identifier of the blob in the collection
            blob.hash(),       // the blake3 hash of the blob
        );
        // => created blob +chatting.b..../notes/cool-bear-hello: b....

        // Setup a connection to a sync node
        let syncer = Syncer::builder()
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
