//! Durable node state: a single redb file holding everything the node
//! must remember across restarts — manifests, claims, KV entries.
//! This is what makes a node statically stable: it boots and serves
//! from here with zero peers reachable.
//!
//! Layout (all values are postcard/envelope bytes):
//!   manifests:  worker name          → manifest Envelope
//!   claims:     "task\0holder_hex"   → claim Envelope
//!   kv:         "ns\0key"            → KvEntry (postcard)

use anyhow::{Context, Result};
use redb::{Database, ReadableDatabase, TableDefinition};
use rf_core::envelope::Envelope;
use rf_core::kv::KvEntry;
use std::path::Path;

const MANIFESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("manifests");
const CLAIMS: TableDefinition<&str, &[u8]> = TableDefinition::new("claims");
const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");

pub struct Store {
    db: Database,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(path)
            .with_context(|| format!("opening redb at {}", path.display()))?;
        // Ensure tables exist so first reads don't error.
        let tx = db.begin_write()?;
        {
            tx.open_table(MANIFESTS)?;
            tx.open_table(CLAIMS)?;
            tx.open_table(KV)?;
        }
        tx.commit()?;
        Ok(Self { db })
    }

    // ---- manifests ----

    pub fn put_manifest(&self, name: &str, env: &Envelope) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(MANIFESTS)?;
            t.insert(name, env.to_bytes().as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_manifests(&self) -> Result<Vec<Envelope>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(MANIFESTS)?;
        let mut out = Vec::new();
        for item in t.range::<&str>(..)? {
            let (_, v) = item?;
            out.push(Envelope::from_bytes(v.value()).context("corrupt manifest in store")?);
        }
        Ok(out)
    }

    // ---- claims ----

    fn claim_key(task: &str, holder_hex: &str) -> String {
        format!("{task}\0{holder_hex}")
    }

    pub fn put_claim(&self, task: &str, holder_hex: &str, env: &Envelope) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(CLAIMS)?;
            t.insert(Self::claim_key(task, holder_hex).as_str(), env.to_bytes().as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_claim(&self, task: &str, holder_hex: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(CLAIMS)?;
            t.remove(Self::claim_key(task, holder_hex).as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_claims(&self) -> Result<Vec<Envelope>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(CLAIMS)?;
        let mut out = Vec::new();
        for item in t.range::<&str>(..)? {
            let (_, v) = item?;
            out.push(Envelope::from_bytes(v.value()).context("corrupt claim in store")?);
        }
        Ok(out)
    }

    // ---- kv ----

    fn kv_key(ns: &str, key: &str) -> String {
        format!("{ns}\0{key}")
    }

    pub fn put_kv(&self, ns: &str, key: &str, entry: &KvEntry) -> Result<()> {
        let bytes = postcard::to_stdvec(entry)?;
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(KV)?;
            t.insert(Self::kv_key(ns, key).as_str(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_kv(&self, ns: &str, key: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(KV)?;
            t.remove(Self::kv_key(ns, key).as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// (namespace, key, entry) triples.
    pub fn load_kv(&self) -> Result<Vec<(String, String, KvEntry)>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(KV)?;
        let mut out = Vec::new();
        for item in t.range::<&str>(..)? {
            let (k, v) = item?;
            let raw = k.value();
            let (ns, key) = raw
                .split_once('\0')
                .ok_or_else(|| anyhow::anyhow!("corrupt kv key in store"))?;
            let entry: KvEntry =
                postcard::from_bytes(v.value()).context("corrupt kv entry in store")?;
            out.push((ns.to_string(), key.to_string(), entry));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_core::hlc::Hlc;
    use rf_core::identity::{Keypair, PublicId};

    fn tmp() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rf-store-{}-{}.redb",
            std::process::id(),
            rand::random::<u32>()
        ))
    }

    #[test]
    fn manifests_roundtrip() {
        let path = tmp();
        let store = Store::open(&path).unwrap();
        let kp = Keypair::from_seed([1; 32]);
        let env = Envelope::seal(&"hello".to_string(), &kp);
        store.put_manifest("w", &env).unwrap();
        let loaded = store.load_manifests().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].digest(), env.digest());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn kv_roundtrip_and_delete() {
        let path = tmp();
        let store = Store::open(&path).unwrap();
        let e = KvEntry {
            hlc: Hlc { wall_ms: 5, logical: 0 },
            writer: PublicId([2; 32]),
            value: Some(b"v".to_vec()),
            expires_at_ms: None,
        };
        store.put_kv("ns", "k", &e).unwrap();
        assert_eq!(store.load_kv().unwrap(), vec![("ns".into(), "k".into(), e)]);
        store.delete_kv("ns", "k").unwrap();
        assert!(store.load_kv().unwrap().is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn survives_reopen() {
        let path = tmp();
        {
            let store = Store::open(&path).unwrap();
            let kp = Keypair::from_seed([1; 32]);
            store.put_claim("t", "aa", &Envelope::seal(&"c".to_string(), &kp)).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.load_claims().unwrap().len(), 1);
        std::fs::remove_file(&path).ok();
    }
}
