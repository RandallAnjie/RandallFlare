//! KV — last-write-wins register per key, HLC-ordered.
//!
//! Contract mirrors CF KV: eventually consistent, a write becomes
//! visible everywhere within the propagation window, deletes are
//! tombstones (GC'd after a horizon so a resurrecting replica can't
//! bring a deleted key back), per-key TTL is honored at read time.
//!
//! Total order for merge: (hlc, writer, value-hash) — the trailing
//! components only break exact HLC ties, deterministically on every
//! node.

use crate::hlc::Hlc;
use crate::identity::PublicId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvEntry {
    pub hlc: Hlc,
    pub writer: PublicId,
    /// None = tombstone.
    pub value: Option<Vec<u8>>,
    /// Absolute expiry (epoch ms); enforced at read.
    pub expires_at_ms: Option<u64>,
}

impl KvEntry {
    fn value_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        match &self.value {
            Some(v) => {
                h.update([1u8]);
                h.update(v);
            }
            None => h.update([0u8]),
        }
        if let Some(e) = self.expires_at_ms {
            h.update(e.to_le_bytes());
        }
        h.finalize().into()
    }

    /// True if `self` supersedes `other` under the deterministic total
    /// order.
    fn beats(&self, other: &KvEntry) -> bool {
        (self.hlc, &self.writer.0, self.value_hash())
            > (other.hlc, &other.writer.0, other.value_hash())
    }

    pub fn visible(&self, now_ms: u64) -> Option<&[u8]> {
        let v = self.value.as_deref()?;
        if let Some(exp) = self.expires_at_ms {
            if now_ms >= exp {
                return None;
            }
        }
        Some(v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Merge {
    Applied,
    Stale,
}

/// One KV namespace. BTreeMap so iteration order (and thus digests)
/// is identical on every node.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Namespace {
    entries: BTreeMap<String, KvEntry>,
}

impl Namespace {
    pub fn new() -> Self {
        Self::default()
    }

    /// Local write. Caller supplies an HLC strictly newer than
    /// anything observed (from `hlc::Clock`).
    pub fn put(
        &mut self,
        key: &str,
        value: Option<Vec<u8>>,
        hlc: Hlc,
        writer: PublicId,
        expires_at_ms: Option<u64>,
    ) -> KvEntry {
        let entry = KvEntry {
            hlc,
            writer,
            value,
            expires_at_ms,
        };
        self.entries.insert(key.to_string(), entry.clone());
        entry
    }

    /// Fold a remote entry in.
    pub fn merge(&mut self, key: &str, incoming: KvEntry) -> Merge {
        match self.entries.get(key) {
            Some(existing) if !incoming.beats(existing) => Merge::Stale,
            _ => {
                self.entries.insert(key.to_string(), incoming);
                Merge::Applied
            }
        }
    }

    pub fn get(&self, key: &str, now_ms: u64) -> Option<&[u8]> {
        self.entries.get(key)?.visible(now_ms)
    }

    pub fn entry(&self, key: &str) -> Option<&KvEntry> {
        self.entries.get(key)
    }

    /// Live keys with an optional prefix, lexicographic, capped.
    pub fn list<'a>(
        &'a self,
        prefix: &'a str,
        now_ms: u64,
        limit: usize,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .range(prefix.to_string()..)
            .take_while(move |(k, _)| k.starts_with(prefix))
            .filter(move |(_, e)| e.visible(now_ms).is_some())
            .map(|(k, _)| k.as_str())
            .take(limit)
    }

    /// Order-independent digest of the full namespace state — two
    /// replicas with equal digests need no sync.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        for (k, e) in &self.entries {
            h.update((k.len() as u64).to_le_bytes());
            h.update(k.as_bytes());
            h.update(e.hlc.wall_ms.to_le_bytes());
            h.update(e.hlc.logical.to_le_bytes());
            h.update(e.writer.0);
            h.update(e.value_hash());
        }
        h.finalize().into()
    }

    /// Full dump for anti-entropy (namespaces are expected to stay small; delta
    /// sync can come later without a wire change — the receiver merges
    /// entry-by-entry either way).
    pub fn dump(&self) -> impl Iterator<Item = (&String, &KvEntry)> {
        self.entries.iter()
    }

    pub fn apply_dump<'a>(
        &mut self,
        items: impl IntoIterator<Item = (&'a String, &'a KvEntry)>,
    ) -> usize {
        let mut applied = 0;
        for (k, e) in items {
            if self.merge(k, e.clone()) == Merge::Applied {
                applied += 1;
            }
        }
        applied
    }

    /// Drop tombstones older than `horizon_ms` and values expired
    /// longer than `horizon_ms` ago.
    pub fn gc(&mut self, now_ms: u64, horizon_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| {
            let dead_since = match (&e.value, e.expires_at_ms) {
                (None, _) => Some(e.hlc.wall_ms),
                (Some(_), Some(exp)) if now_ms >= exp => Some(exp),
                _ => None,
            };
            match dead_since {
                Some(t) => now_ms.saturating_sub(t) < horizon_ms,
                None => true,
            }
        });
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u8) -> PublicId {
        PublicId([n; 32])
    }

    fn hlc(w: u64, l: u32) -> Hlc {
        Hlc {
            wall_ms: w,
            logical: l,
        }
    }

    #[test]
    fn later_hlc_wins_regardless_of_merge_order() {
        let old = KvEntry {
            hlc: hlc(1, 0),
            writer: pid(1),
            value: Some(b"old".to_vec()),
            expires_at_ms: None,
        };
        let new = KvEntry {
            hlc: hlc(2, 0),
            writer: pid(2),
            value: Some(b"new".to_vec()),
            expires_at_ms: None,
        };
        let mut a = Namespace::new();
        a.merge("k", old.clone());
        a.merge("k", new.clone());
        let mut b = Namespace::new();
        b.merge("k", new);
        b.merge("k", old);
        assert_eq!(a.get("k", 10), Some(&b"new"[..]));
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn tombstone_hides_key_and_gc_reaps_it() {
        let mut ns = Namespace::new();
        ns.put("k", Some(b"v".to_vec()), hlc(1, 0), pid(1), None);
        ns.put("k", None, hlc(2, 0), pid(1), None);
        assert_eq!(ns.get("k", 10), None);
        assert_eq!(ns.gc(2 + 1000, 1000), 1);
        assert!(ns.is_empty());
    }

    #[test]
    fn ttl_enforced_at_read() {
        let mut ns = Namespace::new();
        ns.put("k", Some(b"v".to_vec()), hlc(1, 0), pid(1), Some(100));
        assert!(ns.get("k", 99).is_some());
        assert!(ns.get("k", 100).is_none());
    }

    #[test]
    fn identical_hlc_ties_converge() {
        let e1 = KvEntry {
            hlc: hlc(5, 0),
            writer: pid(1),
            value: Some(b"a".to_vec()),
            expires_at_ms: None,
        };
        let e2 = KvEntry {
            hlc: hlc(5, 0),
            writer: pid(2),
            value: Some(b"b".to_vec()),
            expires_at_ms: None,
        };
        let mut a = Namespace::new();
        a.merge("k", e1.clone());
        a.merge("k", e2.clone());
        let mut b = Namespace::new();
        b.merge("k", e2);
        b.merge("k", e1);
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn dump_apply_converges_replicas() {
        let mut a = Namespace::new();
        let mut b = Namespace::new();
        a.put("x", Some(b"1".to_vec()), hlc(1, 0), pid(1), None);
        b.put("y", Some(b"2".to_vec()), hlc(2, 0), pid(2), None);
        let a_items: Vec<_> = a.dump().map(|(k, v)| (k.clone(), v.clone())).collect();
        b.apply_dump(a_items.iter().map(|(k, v)| (k, v)));
        let b_items: Vec<_> = b.dump().map(|(k, v)| (k.clone(), v.clone())).collect();
        a.apply_dump(b_items.iter().map(|(k, v)| (k, v)));
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn list_prefix_and_limit() {
        let mut ns = Namespace::new();
        for k in ["a/1", "a/2", "b/1"] {
            ns.put(k, Some(b"v".to_vec()), hlc(1, 0), pid(1), None);
        }
        let got: Vec<_> = ns.list("a/", 10, 10).collect();
        assert_eq!(got, vec!["a/1", "a/2"]);
        let capped: Vec<_> = ns.list("", 10, 2).collect();
        assert_eq!(capped.len(), 2);
    }
}
