//! Content-addressed blob store: worker modules and static assets,
//! sha256-named, immutable once written. Peers fetch missing blobs
//! from each other over the peer API; verification happens here on
//! every write so a lying peer can't poison the store.
//!
//! Layout: <data_dir>/blobs/<aa>/<sha256hex>

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct BlobStore {
    root: PathBuf,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl BlobStore {
    pub fn open(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, sha_hex: &str) -> PathBuf {
        self.root.join(&sha_hex[..2]).join(sha_hex)
    }

    pub fn has(&self, sha: &[u8; 32]) -> bool {
        self.path_for(&hex::encode(sha)).exists()
    }

    /// Store bytes, returning their sha256. Idempotent.
    pub fn put(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        let sha: [u8; 32] = Sha256::digest(bytes).into();
        self.put_verified(&sha, bytes)?;
        Ok(sha)
    }

    /// Store bytes that must hash to `expected` (peer fetch path).
    pub fn put_verified(&self, expected: &[u8; 32], bytes: &[u8]) -> Result<()> {
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if actual != *expected {
            bail!(
                "blob hash mismatch: expected {} got {}",
                hex::encode(expected),
                hex::encode(actual)
            );
        }
        let hex = hex::encode(expected);
        let path = self.path_for(&hex);
        if path.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        // Write-then-rename so a crashed write never leaves a corrupt
        // blob under its final name.
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn get(&self, sha: &[u8; 32]) -> Result<Vec<u8>> {
        let hex = hex::encode(sha);
        std::fs::read(self.path_for(&hex)).with_context(|| format!("blob {hex} not on disk"))
    }

    /// Absolute path (for workerd embeds / streaming reads).
    pub fn file_path(&self, sha: &[u8; 32]) -> Option<PathBuf> {
        let p = self.path_for(&hex::encode(sha));
        p.exists().then_some(p)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (BlobStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "rf-blob-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        (BlobStore::open(dir.clone()).unwrap(), dir)
    }

    #[test]
    fn put_get_roundtrip() {
        let (store, dir) = tmp_store();
        let sha = store.put(b"hello").unwrap();
        assert!(store.has(&sha));
        assert_eq!(store.get(&sha).unwrap(), b"hello");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn lying_peer_rejected() {
        let (store, dir) = tmp_store();
        let wrong = [0u8; 32];
        assert!(store.put_verified(&wrong, b"not-that-hash").is_err());
        assert!(!store.has(&wrong));
        std::fs::remove_dir_all(dir).ok();
    }
}
