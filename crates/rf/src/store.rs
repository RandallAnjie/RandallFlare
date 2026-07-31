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
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use rf_core::envelope::Envelope;
use rf_core::kv::KvEntry;
use std::path::Path;

const MANIFESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("manifests");
const CLAIMS: TableDefinition<&str, &[u8]> = TableDefinition::new("claims");
const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");
/// Per-database Raft durable state: meta = (epoch, voted_for),
/// log keyed "name\0<seq zero-padded>" → postcard Entry.
const D1META: TableDefinition<&str, &[u8]> = TableDefinition::new("d1_meta");
const D1LOG: TableDefinition<&str, &[u8]> = TableDefinition::new("d1_log");
/// Transparency log: every manifest envelope ever accepted, keyed
/// "name\0<version zero-padded>" so range scans return version order.
const LOG: TableDefinition<&str, &[u8]> = TableDefinition::new("manifest_log");

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
            tx.open_table(LOG)?;
            tx.open_table(D1META)?;
            tx.open_table(D1LOG)?;
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

    fn log_key(name: &str, version: u64) -> String {
        format!("{name}\0{version:020}")
    }

    /// Append an accepted manifest envelope to the transparency log.
    pub fn put_log(&self, name: &str, version: u64, env: &Envelope) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(LOG)?;
            t.insert(Self::log_key(name, version).as_str(), env.to_bytes().as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Full accepted history for one worker, version-ascending.
    pub fn load_log(&self, name: &str) -> Result<Vec<Envelope>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(LOG)?;
        let prefix = format!("{name}\0");
        let mut out = Vec::new();
        for item in t.range::<&str>(prefix.as_str()..)? {
            let (k, v) = item?;
            if !k.value().starts_with(&prefix) {
                break;
            }
            out.push(Envelope::from_bytes(v.value()).context("corrupt log entry")?);
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

    // ---- d1 raft state ----

    pub fn put_d1_meta(
        &self,
        name: &str,
        epoch: u64,
        voted_for: Option<rf_core::identity::PublicId>,
    ) -> Result<()> {
        let bytes = postcard::to_stdvec(&(epoch, voted_for))?;
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(D1META)?;
            t.insert(name, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_d1_meta(
        &self,
        name: &str,
    ) -> Result<(u64, Option<rf_core::identity::PublicId>)> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(D1META)?;
        match t.get(name)? {
            Some(v) => Ok(postcard::from_bytes(v.value()).context("corrupt d1 meta")?),
            None => Ok((0, None)),
        }
    }

    fn d1_log_key(name: &str, seq: u64) -> String {
        format!("{name}\0{seq:020}")
    }

    /// Truncate the log from `from_seq` onward, then append `tail`.
    pub fn put_d1_log(
        &self,
        name: &str,
        from_seq: u64,
        tail: &[rf_core::quorum::Entry],
    ) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(D1LOG)?;
            // Remove everything at/after from_seq (conflict suffix).
            let start = Self::d1_log_key(name, from_seq);
            let end = format!("{name}\x01");
            let stale: Vec<String> = t
                .range::<&str>(start.as_str()..end.as_str())?
                .map(|item| item.map(|(k, _)| k.value().to_string()))
                .collect::<std::result::Result<_, _>>()?;
            for k in stale {
                t.remove(k.as_str())?;
            }
            for e in tail {
                let bytes = postcard::to_stdvec(e)?;
                t.insert(Self::d1_log_key(name, e.seq).as_str(), bytes.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_d1_log(&self, name: &str) -> Result<Vec<rf_core::quorum::Entry>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(D1LOG)?;
        let start = format!("{name}\0");
        let end = format!("{name}\x01");
        let mut out = Vec::new();
        for item in t.range::<&str>(start.as_str()..end.as_str())? {
            let (_, v) = item?;
            out.push(postcard::from_bytes(v.value()).context("corrupt d1 log entry")?);
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
