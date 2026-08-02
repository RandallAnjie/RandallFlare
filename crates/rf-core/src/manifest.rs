//! Worker manifests — the operator-signed unit of deployment.
//!
//! The single deploy unit: a worker = ES modules + an
//! optional static asset tree (served under an `ASSETS` binding /
//! fallback route). All file content is referenced by sha256 and moves
//! through the content-addressed blob store; the manifest is just the
//! signed recipe.
//!
//! Merge rule (the deploy CRDT): per worker name, higher `version`
//! wins; identical versions break ties by envelope digest (lower
//! wins). Deletion is a tombstone manifest (`deleted: true`) with a
//! higher version. Convergent regardless of gossip order.
//!
//! Transparency: every manifest carries `prev` — the envelope digest
//! of its predecessor — forming a per-worker hash chain. Version 1
//! must have `prev = None`; a version+1 successor must link the exact
//! envelope we hold. A worker's full history is therefore verifiable
//! offline (see [`verify_chain`]), and a stolen operator key cannot
//! silently rewrite the past — a mismatching link is rejected, a fork
//! at the same version resolves deterministically and leaves both
//! branches visible in peers' logs.

use crate::cron::CronExpr;
use crate::envelope::{Envelope, EnvelopeError};
use crate::identity::SignerId;
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
    /// Envelope digest of the previous version (hash-chain link).
    /// None iff version == 1.
    pub prev: Option<[u8; 32]>,
    pub deleted: bool,
    /// Path of the main module. Empty string = assets-only worker
    /// (a pure static site) — ingress serves the asset tree
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
    BadPath(String),
    DuplicatePath(String),
    /// Hash-chain violation: v1 with a prev, or a v+1 successor whose
    /// prev doesn't link the envelope we hold.
    ChainBroken,
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
            ManifestError::BadPath(p) => write!(f, "unsafe worker bundle path: {p}"),
            ManifestError::DuplicatePath(p) => write!(f, "duplicate path in bundle: {p}"),
            ManifestError::ChainBroken => f.write_str("manifest hash chain broken"),
        }
    }
}

impl std::error::Error for ManifestError {}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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

fn valid_bundle_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.as_bytes().iter().any(|b| b.is_ascii_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl WorkerManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if !valid_name(&self.name) {
            return Err(ManifestError::BadName);
        }
        if (self.version == 1) != self.prev.is_none() {
            return Err(ManifestError::ChainBroken);
        }
        if self.deleted {
            return Ok(()); // tombstones carry no content requirements
        }
        if !self.main.is_empty() && !self.modules.iter().any(|m| m.path == self.main) {
            return Err(ManifestError::MainNotInModules);
        }
        let mut seen = std::collections::HashSet::new();
        for p in self
            .modules
            .iter()
            .map(|m| &m.path)
            .chain(self.assets.iter().map(|a| &a.path))
        {
            if !valid_bundle_path(p) {
                return Err(ManifestError::BadPath(p.clone()));
            }
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
        self.modules
            .iter()
            .map(|m| m.sha256)
            .chain(self.assets.iter().map(|a| a.sha256))
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

/// All deployed workers, merged CRDT-style. The operator identity
/// (ed25519 key or wallet address) pins who may deploy;
/// multi-operator support later = a set of identities here.
#[derive(Debug)]
pub struct ManifestSet {
    operator: SignerId,
    workers: HashMap<String, ManifestRecord>,
}

impl ManifestSet {
    pub fn new(operator: SignerId) -> Self {
        Self {
            operator,
            workers: HashMap::new(),
        }
    }

    pub fn operator(&self) -> &SignerId {
        &self.operator
    }

    pub fn ingest(&mut self, env: &Envelope) -> Result<ManifestIngest, ManifestError> {
        let manifest: WorkerManifest = env.open(Some(&self.operator)).map_err(|e| match e {
            EnvelopeError::BadSignature => ManifestError::NotOperator,
            other => ManifestError::Envelope(other),
        })?;
        manifest.validate()?;
        let digest = env.digest();
        if let Some(existing) = self.workers.get(&manifest.name) {
            let newer = manifest.version > existing.manifest.version
                || (manifest.version == existing.manifest.version && digest < existing.digest);
            if !newer {
                return Ok(ManifestIngest::Stale);
            }
            // Chain check: a direct successor must link the exact
            // envelope we hold. (A jump over versions we never saw
            // is accepted — the transparency log lets an auditor
            // verify the gap later.)
            if manifest.version == existing.manifest.version + 1
                && manifest.prev != Some(existing.digest)
            {
                return Err(ManifestError::ChainBroken);
            }
        }
        self.workers.insert(
            manifest.name.clone(),
            ManifestRecord {
                manifest,
                digest,
                envelope: env.clone(),
            },
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
        by_host
            .into_iter()
            .map(|(h, r)| (h, r.manifest.name.clone()))
            .collect()
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

/// Verify a worker's transparency log offline: contiguous versions,
/// every envelope operator-signed, every `prev` linking the previous
/// envelope's digest, and (when the log starts at v1) a None root.
/// Returns the decoded manifests oldest-first.
pub fn verify_chain(
    envelopes: &[Envelope],
    operator: &SignerId,
) -> Result<Vec<WorkerManifest>, ManifestError> {
    let mut out: Vec<WorkerManifest> = Vec::with_capacity(envelopes.len());
    let mut prev_digest: Option<[u8; 32]> = None;
    for env in envelopes {
        let m: WorkerManifest = env.open(Some(operator)).map_err(|e| match e {
            EnvelopeError::BadSignature => ManifestError::NotOperator,
            other => ManifestError::Envelope(other),
        })?;
        if let Some(last) = out.last() {
            if m.version != last.version + 1 || m.name != last.name {
                return Err(ManifestError::ChainBroken);
            }
            if m.prev != prev_digest {
                return Err(ManifestError::ChainBroken);
            }
        } else if m.version == 1 && m.prev.is_some() {
            return Err(ManifestError::ChainBroken);
        }
        prev_digest = Some(env.digest());
        out.push(m);
    }
    Ok(out)
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
            prev: None,
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

    fn opid() -> SignerId {
        SignerId::Ed(op().public())
    }

    #[test]
    fn frozen_v03_manifest_wire_decodes() {
        #[derive(Serialize)]
        struct LegacyManifest {
            name: String,
            version: u64,
            prev: Option<[u8; 32]>,
            deleted: bool,
            main: String,
            modules: Vec<Module>,
            assets: Vec<AssetFile>,
            hostnames: Vec<String>,
            env: BTreeMap<String, String>,
            kv_bindings: BTreeMap<String, String>,
            crons: Vec<String>,
            compatibility_date: String,
        }
        let m = mk("legacy", 1, &[]);
        let old = LegacyManifest {
            name: m.name.clone(),
            version: m.version,
            prev: m.prev,
            deleted: m.deleted,
            main: m.main.clone(),
            modules: m.modules.clone(),
            assets: m.assets.clone(),
            hostnames: m.hostnames.clone(),
            env: m.env.clone(),
            kv_bindings: m.kv_bindings.clone(),
            crons: m.crons.clone(),
            compatibility_date: m.compatibility_date.clone(),
        };
        let raw = postcard::to_stdvec(&old).unwrap();
        let decoded: WorkerManifest = postcard::from_bytes(&raw).unwrap();
        assert_eq!(decoded.name, "legacy");
    }

    /// Seal a chained successor: fills `prev` from the prior envelope.
    fn seal_after(m: &mut WorkerManifest, prior: &Envelope, key: &Keypair) -> Envelope {
        m.prev = Some(prior.digest());
        Envelope::seal(m, key)
    }

    #[test]
    fn higher_version_wins_any_order() {
        let op = op();
        let v1 = Envelope::seal(&mk("w", 1, &["a.example.com"]), &op);
        let v2 = seal_after(&mut mk("w", 2, &["a.example.com"]), &v1, &op);
        let mut s1 = ManifestSet::new(opid());
        s1.ingest(&v1).unwrap();
        s1.ingest(&v2).unwrap();
        let mut s2 = ManifestSet::new(opid());
        s2.ingest(&v2).unwrap();
        assert_eq!(s2.ingest(&v1).unwrap(), ManifestIngest::Stale);
        assert_eq!(s1.get("w").unwrap().manifest.version, 2);
        assert_eq!(s1.digest(), s2.digest());
    }

    #[test]
    fn non_operator_deploy_rejected() {
        let mallory = Keypair::from_seed([9u8; 32]);
        let env = Envelope::seal(&mk("w", 1, &[]), &mallory);
        let mut s = ManifestSet::new(opid());
        assert_eq!(s.ingest(&env).unwrap_err(), ManifestError::NotOperator);
    }

    #[test]
    fn eth_operator_can_deploy() {
        use crate::identity::{AnyKeypair, EthKeypair};
        let wallet = AnyKeypair::Eth(EthKeypair::from_seed([8u8; 32]).unwrap());
        let env = Envelope::seal_any(&mk("w", 1, &[]), &wallet);
        let mut s = ManifestSet::new(wallet.signer_id());
        assert_eq!(s.ingest(&env).unwrap(), ManifestIngest::Changed);
        // The ed operator set rejects it.
        let mut other = ManifestSet::new(opid());
        assert_eq!(other.ingest(&env).unwrap_err(), ManifestError::NotOperator);
    }

    #[test]
    fn tombstone_removes_from_live_and_routes() {
        let op = op();
        let mut s = ManifestSet::new(opid());
        let v1 = Envelope::seal(&mk("w", 1, &["a.example.com"]), &op);
        s.ingest(&v1).unwrap();
        assert_eq!(s.routes().len(), 1);
        let mut dead = mk("w", 2, &[]);
        dead.deleted = true;
        dead.modules.clear();
        dead.main = String::new();
        s.ingest(&seal_after(&mut dead, &v1, &op)).unwrap();
        assert_eq!(s.live().count(), 0);
        assert!(s.routes().is_empty());
    }

    #[test]
    fn contested_hostname_resolves_deterministically() {
        let op = op();
        let a = Envelope::seal(&mk("wa", 1, &["x.example.com"]), &op);
        let b = Envelope::seal(&mk("wb", 1, &["x.example.com"]), &op);
        let mut s1 = ManifestSet::new(opid());
        s1.ingest(&a).unwrap();
        s1.ingest(&b).unwrap();
        let mut s2 = ManifestSet::new(opid());
        s2.ingest(&b).unwrap();
        s2.ingest(&a).unwrap();
        assert_eq!(s1.routes(), s2.routes());
    }

    #[test]
    fn chain_rules_enforced() {
        let op = op();
        let mut s = ManifestSet::new(opid());
        // v1 with a prev is invalid.
        let mut bad_root = mk("w", 1, &[]);
        bad_root.prev = Some([1; 32]);
        assert_eq!(
            s.ingest(&Envelope::seal(&bad_root, &op)).unwrap_err(),
            ManifestError::ChainBroken
        );
        // Proper root, then a v2 with a wrong link is rejected.
        let v1 = Envelope::seal(&mk("w", 1, &[]), &op);
        s.ingest(&v1).unwrap();
        let mut forged = mk("w", 2, &[]);
        forged.prev = Some([9; 32]);
        assert_eq!(
            s.ingest(&Envelope::seal(&forged, &op)).unwrap_err(),
            ManifestError::ChainBroken
        );
        // Correct link accepted.
        let v2 = seal_after(&mut mk("w", 2, &[]), &v1, &op);
        assert_eq!(s.ingest(&v2).unwrap(), ManifestIngest::Changed);
        // A jump (v4 while we hold v2) is accepted — auditable later.
        let mut v4 = mk("w", 4, &[]);
        v4.prev = Some([7; 32]);
        assert_eq!(
            s.ingest(&Envelope::seal(&v4, &op)).unwrap(),
            ManifestIngest::Changed
        );
    }

    #[test]
    fn verify_chain_walks_and_rejects_tampering() {
        let op = op();
        let v1 = Envelope::seal(&mk("w", 1, &[]), &op);
        let v2 = seal_after(&mut mk("w", 2, &[]), &v1, &op);
        let v3 = seal_after(&mut mk("w", 3, &[]), &v2, &op);
        let chain = vec![v1.clone(), v2.clone(), v3.clone()];
        let ms = verify_chain(&chain, &opid()).unwrap();
        assert_eq!(
            ms.iter().map(|m| m.version).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // Drop the middle link → broken.
        assert_eq!(
            verify_chain(&[v1.clone(), v3.clone()], &opid()).unwrap_err(),
            ManifestError::ChainBroken
        );
        // Replace the middle with a re-signed variant → v3.prev no
        // longer matches.
        let mut alt2 = mk("w", 2, &["evil.example.com"]);
        let alt2_env = seal_after(&mut alt2, &v1, &op);
        assert_eq!(
            verify_chain(&[v1, alt2_env, v3], &opid()).unwrap_err(),
            ManifestError::ChainBroken
        );
    }

    #[test]
    fn assets_only_worker_validates() {
        let mut m = mk("site", 1, &["s.example.com"]);
        m.modules.clear();
        m.main = String::new();
        m.assets.push(AssetFile {
            path: "index.html".into(),
            sha256: [7; 32],
            size: 3,
        });
        assert!(m.validate().is_ok());
    }

    #[test]
    fn bad_names_rejected() {
        for bad in [
            "",
            "UPPER",
            "has_underscore",
            "-lead",
            "trail-",
            &"x".repeat(64),
        ] {
            let mut m = mk("ok", 1, &[]);
            m.name = bad.to_string();
            assert!(m.validate().is_err(), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn unsafe_bundle_paths_are_rejected() {
        for bad in ["../secret", "/etc/passwd", "a/../../b", "a\\b", "a//b", "."] {
            let mut m = mk("safe", 1, &[]);
            m.main = bad.to_string();
            m.modules[0].path = bad.to_string();
            assert_eq!(
                m.validate().unwrap_err(),
                ManifestError::BadPath(bad.to_string())
            );
        }
    }
}
