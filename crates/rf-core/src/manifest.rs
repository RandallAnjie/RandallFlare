//! Worker manifests — the operator-signed unit of deployment.
//!
//! Workers and Pages are one product: a worker = ES modules + an
//! optional static asset tree (served under an `ASSETS` binding /
//! fallback route). All file content is referenced by sha256 and moves
//! through the content-addressed blob store; the manifest is just the
//! signed recipe.
//!
//! Merge rule (the deploy CRDT): per worker name, higher `version`
//! wins; identical versions break ties by envelope digest (lower
//! wins). Deletion is a tombstone manifest (`deleted: true`) with a
//! higher version. Convergent regardless of gossip order.

use crate::cron::CronExpr;
use crate::envelope::{Envelope, EnvelopeError};
use crate::identity::PublicId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleKind {
    EsModule,
    CommonJs,
    Wasm,
    Text,
    Data,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    /// Path inside the worker bundle, e.g. "index.js" or "lib/util.js".
    pub path: String,
    pub sha256: [u8; 32],
    pub kind: ModuleKind,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetFile {
    /// URL path relative to root, e.g. "index.html", "css/site.css".
    pub path: String,
    pub sha256: [u8; 32],
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerManifest {
    pub name: String,
    /// Monotonic per worker; the operator's deploy tool bumps it.
    pub version: u64,
    pub deleted: bool,
    /// Path of the main module. Empty string = assets-only worker
    /// (the merged "Pages" case) — ingress serves the asset tree
    /// directly with no JS in front.
    pub main: String,
    pub modules: Vec<Module>,
    pub assets: Vec<AssetFile>,
    /// Hostnames routed to this worker (full hostnames, lowercase).
    pub hostnames: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// KV namespaces bound into the worker: binding name → namespace id.
    pub kv_bindings: BTreeMap<String, String>,
    pub crons: Vec<String>,
    pub compatibility_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Envelope(EnvelopeError),
    NotOperator,
    BadName,
    MainNotInModules,
    BadCron(String),
    BadHostname(String),
    DuplicatePath(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Envelope(e) => write!(f, "envelope: {e}"),
            ManifestError::NotOperator => f.write_str("not signed by the operator key"),
            ManifestError::BadName => f.write_str("worker name must be [a-z0-9-]{1,63}"),
            ManifestError::MainNotInModules => f.write_str("main module not in modules list"),
            ManifestError::BadCron(c) => write!(f, "invalid cron expression: {c}"),
            ManifestError::BadHostname(h) => write!(f, "invalid hostname: {h}"),
            ManifestError::DuplicatePath(p) => write!(f, "duplicate path in bundle: {p}"),
        }
    }
}

impl std::error::Error for ManifestError {}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with('.')
        && !h.ends_with('.')
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl WorkerManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if !valid_name(&self.name) {
            return Err(ManifestError::BadName);
        }
        if self.deleted {
            return Ok(()); // tombstones carry no content requirements
        }
        if !self.main.is_empty() && !self.modules.iter().any(|m| m.path == self.main) {
            return Err(ManifestError::MainNotInModules);
        }
        let mut seen = std::collections::HashSet::new();
        for p in self.modules.iter().map(|m| &m.path).chain(self.assets.iter().map(|a| &a.path)) {
            if !seen.insert(p) {
                return Err(ManifestError::DuplicatePath(p.clone()));
            }
        }
        for c in &self.crons {
            if CronExpr::parse(c).is_err() {
                return Err(ManifestError::BadCron(c.clone()));
            }
        }
        for h in &self.hostnames {
            if !valid_hostname(h) {
                return Err(ManifestError::BadHostname(h.clone()));
            }
        }
        Ok(())
    }

    /// Every blob this manifest needs on disk before it can serve.
    pub fn blob_refs(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.modules.iter().map(|m| m.sha256).chain(self.assets.iter().map(|a| a.sha256))
    }
}

#[derive(Debug, Clone)]
pub struct ManifestRecord {
    pub manifest: WorkerManifest,
    pub digest: [u8; 32],
    pub envelope: Envelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestIngest {
    Changed,
    Stale,
}

/// All deployed workers, merged CRDT-style. The operator key pins who
/// may deploy; multi-operator support later = a set of keys here.
#[derive(Debug)]
pub struct ManifestSet {
    operator: PublicId,
    workers: HashMap<String, ManifestRecord>,
}

impl ManifestSet {
    pub fn new(operator: PublicId) -> Self {
        Self { operator, workers: HashMap::new() }
    }

    pub fn operator(&self) -> &PublicId {
        &self.operator
    }

    pub fn ingest(&mut self, env: &Envelope) -> Result<ManifestIngest, ManifestError> {
        let manifest: WorkerManifest =
            env.open(Some(&self.operator)).map_err(|e| match e {
                EnvelopeError::BadSignature => ManifestError::NotOperator,
                other => ManifestError::Envelope(other),
            })?;
        manifest.validate()?;
        let digest = env.digest();
        match self.workers.get(&manifest.name) {
            Some(existing) => {
                let newer = manifest.version > existing.manifest.version
                    || (manifest.version == existing.manifest.version
                        && digest < existing.digest);
                if !newer {
                    return Ok(ManifestIngest::Stale);
                }
            }
            None => {}
        }
        self.workers.insert(
            manifest.name.clone(),
            ManifestRecord { manifest, digest, envelope: env.clone() },
        );
        Ok(ManifestIngest::Changed)
    }

    pub fn get(&self, name: &str) -> Option<&ManifestRecord> {
        self.workers.get(name)
    }

    /// Live (non-tombstone) workers.
    pub fn live(&self) -> impl Iterator<Item = &ManifestRecord> {
        self.workers.values().filter(|r| !r.manifest.deleted)
    }

    pub fn all(&self) -> impl Iterator<Item = &ManifestRecord> {
        self.workers.values()
    }

    /// hostname → worker name routing table. Deterministic on
    /// conflicts: the worker with the lower manifest digest wins a
    /// contested hostname (converges everywhere; operator tooling
    /// should prevent contests in the first place).
    pub fn routes(&self) -> BTreeMap<String, String> {
        let mut by_host: BTreeMap<String, &ManifestRecord> = BTreeMap::new();
        for rec in self.live() {
            for h in &rec.manifest.hostnames {
                by_host
                    .entry(h.clone())
                    .and_modify(|cur| {
                        if rec.digest < cur.digest {
                            *cur = rec;
                        }
                    })
                    .or_insert(rec);
            }
        }
        by_host.into_iter().map(|(h, r)| (h, r.manifest.name.clone())).collect()
    }

    /// Order-independent digest over (name, version, digest) — cheap
    /// anti-entropy comparison.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut names: Vec<_> = self.workers.keys().collect();
        names.sort();
        let mut h = Sha256::new();
        for n in names {
            let r = &self.workers[n];
            h.update(n.as_bytes());
            h.update(r.manifest.version.to_le_bytes());
            h.update(r.digest);
        }
        h.finalize().into()
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    fn op() -> Keypair {
        Keypair::from_seed([42u8; 32])
    }

    fn mk(name: &str, version: u64, hosts: &[&str]) -> WorkerManifest {
        WorkerManifest {
            name: name.into(),
            version,
            deleted: false,
            main: "index.js".into(),
            modules: vec![Module {
                path: "index.js".into(),
                sha256: [version as u8; 32],
                kind: ModuleKind::EsModule,
                size: 10,
            }],
            assets: vec![],
            hostnames: hosts.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-07-31".into(),
        }
    }

    #[test]
    fn higher_version_wins_any_order() {
        let op = op();
        let v1 = Envelope::seal(&mk("w", 1, &["a.example.com"]), &op);
        let v2 = Envelope::seal(&mk("w", 2, &["a.example.com"]), &op);
        let mut s1 = ManifestSet::new(op.public());
        s1.ingest(&v1).unwrap();
        s1.ingest(&v2).unwrap();
        let mut s2 = ManifestSet::new(op.public());
        s2.ingest(&v2).unwrap();
        assert_eq!(s2.ingest(&v1).unwrap(), ManifestIngest::Stale);
        assert_eq!(s1.get("w").unwrap().manifest.version, 2);
        assert_eq!(s1.digest(), s2.digest());
    }

    #[test]
    fn non_operator_deploy_rejected() {
        let mallory = Keypair::from_seed([9u8; 32]);
        let env = Envelope::seal(&mk("w", 1, &[]), &mallory);
        let mut s = ManifestSet::new(op().public());
        assert_eq!(s.ingest(&env).unwrap_err(), ManifestError::NotOperator);
    }

    #[test]
    fn tombstone_removes_from_live_and_routes() {
        let op = op();
        let mut s = ManifestSet::new(op.public());
        s.ingest(&Envelope::seal(&mk("w", 1, &["a.example.com"]), &op)).unwrap();
        assert_eq!(s.routes().len(), 1);
        let mut dead = mk("w", 2, &[]);
        dead.deleted = true;
        dead.modules.clear();
        dead.main = String::new();
        s.ingest(&Envelope::seal(&dead, &op)).unwrap();
        assert_eq!(s.live().count(), 0);
        assert!(s.routes().is_empty());
    }

    #[test]
    fn contested_hostname_resolves_deterministically() {
        let op = op();
        let a = Envelope::seal(&mk("wa", 1, &["x.example.com"]), &op);
        let b = Envelope::seal(&mk("wb", 1, &["x.example.com"]), &op);
        let mut s1 = ManifestSet::new(op.public());
        s1.ingest(&a).unwrap();
        s1.ingest(&b).unwrap();
        let mut s2 = ManifestSet::new(op.public());
        s2.ingest(&b).unwrap();
        s2.ingest(&a).unwrap();
        assert_eq!(s1.routes(), s2.routes());
    }

    #[test]
    fn assets_only_worker_validates() {
        let mut m = mk("site", 1, &["s.example.com"]);
        m.modules.clear();
        m.main = String::new();
        m.assets.push(AssetFile { path: "index.html".into(), sha256: [7; 32], size: 3 });
        assert!(m.validate().is_ok());
    }

    #[test]
    fn bad_names_rejected() {
        for bad in ["", "UPPER", "has_underscore", "-lead", "trail-", &"x".repeat(64)] {
            let mut m = mk("ok", 1, &[]);
            m.name = bad.to_string();
            assert!(m.validate().is_err(), "{bad:?} should be invalid");
        }
    }
}
