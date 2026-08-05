//! The node's shared in-memory state: rf-core decision structures
//! hydrated from the store on boot, write-through on every change,
//! change events fanned out to the gossip/runtime/ingress loops.

use crate::blob::BlobStore;
use crate::config::NodeConfig;
use crate::management::Management;
use crate::objectstore::ObjectStore;
use crate::store::Store;
use anyhow::Result;
use rf_core::claim::{ClaimSet, Ingest};
use rf_core::envelope::Envelope;
use rf_core::hlc::{Clock, Hlc};
use rf_core::identity::{Keypair, PublicId};
use rf_core::kv::{KvEntry, Merge, Namespace};
use rf_core::manifest::{ManifestIngest, ManifestSet, WorkerManifest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::sync::broadcast;

pub type KvListPage = (Vec<(String, Option<u64>)>, bool, Option<String>);
pub type KvMetadataListPage = (
    Vec<(String, Option<u64>, Option<Vec<u8>>)>,
    bool,
    Option<String>,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// A manifest changed — runtime must reconcile, gossip must
    /// republish the digest, blobs may need fetching.
    Manifests,
    /// One of our own claims changed — gossip must republish.
    OwnClaims,
    /// A KV namespace changed locally.
    Kv(String),
    /// Local Worker materialization/runtime status changed.
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentStatus {
    pub version: u64,
    pub state: String,
    #[serde(default)]
    pub detail: String,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLogLine {
    pub at_ms: u64,
    pub version: u64,
    pub stream: String,
    pub message: String,
}

/// What we know about a live peer, scraped from its gossip state.
#[derive(Debug, Clone, Default)]
pub struct PeerView {
    pub api_addr: Option<SocketAddr>,
    pub public: bool,
    pub label: String,
    pub ipv4: Option<String>,
    pub manifest_digest: String,
    pub kv_digests: BTreeMap<String, String>,
    pub deployments: BTreeMap<String, DeploymentStatus>,
    /// Self-declared hardware/service capabilities carried by authenticated
    /// cluster gossip (for example `build`, `email`, and `rclone`).
    pub capabilities: BTreeSet<String>,
    pub generation: u64,
}

pub struct Inner {
    pub clock: Clock,
    pub claims: ClaimSet,
    pub manifests: ManifestSet,
    pub kv: HashMap<String, Namespace>,
    /// node_id hex → view. Live peers only (dead ones drop out).
    pub peers: BTreeMap<String, PeerView>,
    /// worker name → local workerd port (published by the runtime).
    pub worker_ports: HashMap<String, u16>,
    pub runtime_status: HashMap<String, DeploymentStatus>,
    pub runtime_logs: HashMap<String, VecDeque<RuntimeLogLine>>,
    /// Request metadata waiting for the next one-second redb batch.
    pub pending_request_logs: VecDeque<crate::observability::RequestLogEntry>,
    /// Loopback port of the kvbind server (set at daemon start).
    pub kvbind_port: u16,
    /// Loopback port of the native workerd R2 binding adapter.
    pub r2bind_port: u16,
    pub d1bind_port: u16,
    pub qbind_port: u16,
    pub analyticsbind_port: u16,
    pub pbind_port: u16,
    pub workflowbind_port: u16,
    pub emailbind_port: u16,
    pub servicebind_port: u16,
    pub binarybind_port: u16,
    /// Per-process unguessable tokens used only for rf → workerd event
    /// delivery. They are regenerated on every Worker start and never gossip.
    pub worker_event_tokens: HashMap<String, String>,
    /// Current local share of the signed cluster request/minute budget:
    /// (unix-minute, accepted requests).
    pub quota_request_window: (u64, u64),
}

pub struct Node {
    pub cfg: NodeConfig,
    pub keypair: Keypair,
    pub store: Store,
    pub blobs: BlobStore,
    pub objects: ObjectStore,
    pub management: Management,
    pub inner: Mutex<Inner>,
    r2_schemas: Mutex<HashSet<String>>,
    queue_schemas: Mutex<HashSet<String>>,
    analytics_schemas: Mutex<HashSet<String>>,
    pipeline_schemas: Mutex<HashSet<String>>,
    workflow_schemas: Mutex<HashSet<String>>,
    flow_schemas: Mutex<HashSet<String>>,
    email_schemas: Mutex<HashSet<String>>,
    cron_schemas: Mutex<HashSet<String>>,
    /// Serializes cluster-quota preflight with the following local R2 metadata
    /// commit. Cross-node admission remains intentionally conservative and is
    /// backed by the per-bucket D1 quorum.
    pub(crate) r2_quota_gate: tokio::sync::Mutex<()>,
    events: broadcast::Sender<NodeEvent>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn kv_metadata_namespace(namespace: &str) -> String {
    format!(
        "__rf_kvmeta/{}",
        crate::blob::sha256_hex(namespace.as_bytes())
    )
}

impl Node {
    pub fn open(cfg: NodeConfig, keypair: Keypair) -> Result<Self> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg.data_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let store = Store::open(&cfg.data_dir.join("state.redb"))?;
        let blobs = BlobStore::open(cfg.data_dir.join("blobs"))?;
        let objects = ObjectStore::open(&cfg.data_dir, &cfg.storage)?;
        let mut inner = Inner {
            clock: Clock::new(),
            claims: ClaimSet::new(),
            manifests: ManifestSet::new(cfg.operator),
            kv: HashMap::new(),
            peers: BTreeMap::new(),
            worker_ports: HashMap::new(),
            runtime_status: HashMap::new(),
            runtime_logs: HashMap::new(),
            pending_request_logs: VecDeque::new(),
            kvbind_port: 0,
            r2bind_port: 0,
            d1bind_port: 0,
            qbind_port: 0,
            analyticsbind_port: 0,
            pbind_port: 0,
            workflowbind_port: 0,
            emailbind_port: 0,
            servicebind_port: 0,
            binarybind_port: 0,
            worker_event_tokens: HashMap::new(),
            quota_request_window: (0, 0),
        };
        // Hydrate: static stability means booting entirely from disk.
        for env in store.load_manifests()? {
            if let Err(e) = inner.manifests.ingest(&env) {
                tracing::warn!("dropping stored manifest: {e}");
            }
        }
        for env in store.load_claims()? {
            if let Err(e) = inner.claims.ingest(&env) {
                tracing::warn!("dropping stored claim: {e}");
            }
        }
        for (ns, key, entry) in store.load_kv()? {
            inner.clock.observe(entry.hlc, now_ms());
            inner.kv.entry(ns).or_default().merge(&key, entry);
        }
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            cfg,
            keypair,
            store,
            blobs,
            objects,
            management: Management::default(),
            inner: Mutex::new(inner),
            r2_schemas: Mutex::new(HashSet::new()),
            queue_schemas: Mutex::new(HashSet::new()),
            analytics_schemas: Mutex::new(HashSet::new()),
            pipeline_schemas: Mutex::new(HashSet::new()),
            workflow_schemas: Mutex::new(HashSet::new()),
            flow_schemas: Mutex::new(HashSet::new()),
            email_schemas: Mutex::new(HashSet::new()),
            cron_schemas: Mutex::new(HashSet::new()),
            r2_quota_gate: tokio::sync::Mutex::new(()),
            events,
        })
    }

    pub fn id(&self) -> PublicId {
        self.keypair.public()
    }

    pub fn id_hex(&self) -> String {
        self.id().to_string()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.events.subscribe()
    }

    fn emit(&self, ev: NodeEvent) {
        let _ = self.events.send(ev);
    }

    pub fn hlc_now(&self) -> Hlc {
        self.inner.lock().unwrap().clock.now(now_ms())
    }

    // ---- manifests ----

    /// Ingest a manifest envelope (from gossip sync or a deploy).
    /// Returns Ok(true) when state changed.
    pub fn ingest_manifest(&self, env: &Envelope) -> Result<bool> {
        let changed = {
            let mut inner = self.inner.lock().unwrap();
            match inner.manifests.ingest(env)? {
                ManifestIngest::Changed => {
                    let m: WorkerManifest = env.open(Some(&self.cfg.operator))?;
                    self.store.put_manifest(&m.name, env)?;
                    // Transparency log: append-only history of every
                    // accepted version.
                    self.store.put_log(&m.name, m.version, env)?;
                    true
                }
                ManifestIngest::Stale => false,
            }
        };
        if changed {
            self.emit(NodeEvent::Manifests);
        }
        Ok(changed)
    }

    pub fn manifest_digest_hex(&self) -> String {
        hex::encode(self.inner.lock().unwrap().manifests.digest())
    }

    pub fn manifest_envelopes(&self) -> Vec<Envelope> {
        self.inner
            .lock()
            .unwrap()
            .manifests
            .all()
            .map(|r| r.envelope.clone())
            .collect()
    }

    /// Blob hashes referenced by live manifests but absent on disk.
    pub fn missing_blobs(&self) -> Vec<[u8; 32]> {
        let manifests = {
            let inner = self.inner.lock().unwrap();
            inner
                .manifests
                .live()
                .map(|record| record.manifest.clone())
                .collect::<Vec<_>>()
        };
        let mut manifests = manifests;
        manifests.extend(
            crate::preview::active_previews(self)
                .into_iter()
                .map(|(_, spec)| spec.manifest),
        );
        let mut missing = Vec::new();
        for manifest in manifests {
            for sha in manifest.blob_refs() {
                if !self.blobs.has(&sha) && !missing.contains(&sha) {
                    missing.push(sha);
                }
            }
        }
        missing
    }

    pub fn notify_blobs_changed(&self) {
        self.emit(NodeEvent::Runtime);
    }

    pub(crate) fn notify_runtime_changed(&self) {
        self.emit(NodeEvent::Runtime);
    }

    // ---- claims ----

    pub fn ingest_claim(&self, env: &Envelope) -> Result<bool> {
        let changed = {
            let mut inner = self.inner.lock().unwrap();
            match inner.claims.ingest(env) {
                Ok(Ingest::Changed) => {
                    // Pull our clock past the remote's so our next
                    // claims sort after everything we've seen.
                    if let Ok(c) = env.open::<rf_core::claim::Claim>(None) {
                        inner.clock.observe(c.renewed, now_ms());
                        self.store.put_claim(&c.task, &c.holder.to_string(), env)?;
                    }
                    true
                }
                Ok(Ingest::Stale) => false,
                Err(e) => {
                    tracing::debug!("rejecting claim: {e}");
                    false
                }
            }
        };
        if changed {
            self.emit(NodeEvent::OwnClaims); // republish set may change winners
        }
        Ok(changed)
    }

    /// Try to grab `task`. Returns true if, as of local knowledge, we
    /// issued a claim (we may still lose adjudication once gossip
    /// converges — callers must re-check `holds` after a settle delay).
    pub fn claim_try(&self, task: &str, ttl_ms: u64) -> Result<bool> {
        let env = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.claims.open_for_claim(task, now_ms()) {
                return Ok(false);
            }
            let now = inner.clock.now(now_ms());
            ClaimSet::make_claim(&self.keypair, task, now, ttl_ms)
        };
        self.ingest_claim(&env)?;
        self.emit(NodeEvent::OwnClaims);
        Ok(true)
    }

    pub fn holds(&self, task: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .claims
            .holds(task, &self.id(), now_ms())
    }

    /// Renew or release our claim on `task`.
    pub fn claim_renew(&self, task: &str, release: bool) -> Result<()> {
        let env = {
            let mut inner = self.inner.lock().unwrap();
            let me = self.id();
            let Some(rec) = inner.claims.mine(task, &me) else {
                return Ok(());
            };
            let prior = rec.claim.clone();
            let now = inner.clock.now(now_ms());
            ClaimSet::renew(&self.keypair, &prior, now, release)
        };
        self.ingest_claim(&env)?;
        self.emit(NodeEvent::OwnClaims);
        Ok(())
    }

    /// Our own live claims, for gossip publication.
    pub fn own_claim_envelopes(&self) -> Vec<(String, Envelope)> {
        let inner = self.inner.lock().unwrap();
        let me = self.id();
        let now = now_ms();
        inner
            .claims
            .live_envelopes(now)
            .into_iter()
            .filter_map(|env| {
                let c: rf_core::claim::Claim = env.open(None).ok()?;
                (c.holder == me).then(|| (c.task, env.clone()))
            })
            .collect()
    }

    pub fn claim_envelopes(&self) -> Vec<Envelope> {
        let inner = self.inner.lock().unwrap();
        inner
            .claims
            .live_envelopes(now_ms())
            .into_iter()
            .cloned()
            .collect()
    }

    // ---- kv ----

    pub fn kv_put(
        &self,
        ns: &str,
        key: &str,
        value: Option<Vec<u8>>,
        expires_at_ms: Option<u64>,
    ) -> Result<()> {
        self.kv_put_entry(ns, key, value, expires_at_ms)?;
        if !ns.starts_with("__rf") {
            self.kv_put_entry(&kv_metadata_namespace(ns), key, None, None)?;
        }
        Ok(())
    }

    pub fn kv_put_with_metadata(
        &self,
        ns: &str,
        key: &str,
        value: Option<Vec<u8>>,
        expires_at_ms: Option<u64>,
        metadata: Option<Vec<u8>>,
    ) -> Result<()> {
        self.kv_put_entry(ns, key, value, expires_at_ms)?;
        self.kv_put_entry(&kv_metadata_namespace(ns), key, metadata, expires_at_ms)
    }

    fn kv_put_entry(
        &self,
        ns: &str,
        key: &str,
        value: Option<Vec<u8>>,
        expires_at_ms: Option<u64>,
    ) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            let hlc = inner.clock.now(now_ms());
            let writer = self.id();
            let entry = inner.kv.entry(ns.to_string()).or_default().put(
                key,
                value,
                hlc,
                writer,
                expires_at_ms,
            );
            self.store.put_kv(ns, key, &entry)?;
        }
        self.emit(NodeEvent::Kv(ns.to_string()));
        Ok(())
    }

    pub fn kv_get(&self, ns: &str, key: &str) -> Option<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        inner.kv.get(ns)?.get(key, now_ms()).map(|v| v.to_vec())
    }

    pub fn kv_get_with_metadata(&self, ns: &str, key: &str) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let value = self.kv_get(ns, key)?;
        let metadata = self.kv_get(&kv_metadata_namespace(ns), key);
        Some((value, metadata))
    }

    pub fn kv_list(&self, ns: &str, prefix: &str, limit: usize) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        match inner.kv.get(ns) {
            Some(n) => n
                .list(prefix, now_ms(), limit)
                .map(|s| s.to_string())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Paged listing for the workerd KV binding: (name, expiration_ms)
    /// pairs after `cursor` (exclusive), plus list_complete + the next
    /// cursor. The cursor is simply the last key returned — opaque
    /// enough for CF parity, trivially resumable.
    pub fn kv_list_page(
        &self,
        ns: &str,
        prefix: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> KvListPage {
        self.kv_list_page_plain(ns, prefix, limit, cursor)
    }

    pub fn kv_list_page_with_metadata(
        &self,
        ns: &str,
        prefix: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> KvMetadataListPage {
        let (items, complete, cursor) = self.kv_list_page_plain(ns, prefix, limit, cursor);
        let metadata_ns = kv_metadata_namespace(ns);
        let items = items
            .into_iter()
            .map(|(key, expiration)| {
                let metadata = self.kv_get(&metadata_ns, &key);
                (key, expiration, metadata)
            })
            .collect();
        (items, complete, cursor)
    }

    fn kv_list_page_plain(
        &self,
        ns: &str,
        prefix: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> KvListPage {
        let inner = self.inner.lock().unwrap();
        let Some(namespace) = inner.kv.get(ns) else {
            return (Vec::new(), true, None);
        };
        let now = now_ms();
        let mut output = Vec::new();
        let mut more = false;
        for key in namespace.list(prefix, now, usize::MAX) {
            if cursor.is_some_and(|cursor| key <= cursor) {
                continue;
            }
            if output.len() == limit {
                more = true;
                break;
            }
            let expiration = namespace.entry(key).and_then(|entry| entry.expires_at_ms);
            output.push((key.to_string(), expiration));
        }
        let cursor = more
            .then(|| output.last().map(|(key, _)| key.clone()))
            .flatten();
        (output, !more, cursor)
    }

    pub fn kv_merge_remote(&self, ns: &str, items: Vec<(String, KvEntry)>) -> Result<usize> {
        let mut applied = 0;
        {
            let mut inner = self.inner.lock().unwrap();
            for (key, entry) in items {
                inner.clock.observe(entry.hlc, now_ms());
                if inner
                    .kv
                    .entry(ns.to_string())
                    .or_default()
                    .merge(&key, entry.clone())
                    == Merge::Applied
                {
                    self.store.put_kv(ns, &key, &entry)?;
                    applied += 1;
                }
            }
        }
        if applied > 0 {
            self.emit(NodeEvent::Kv(ns.to_string()));
        }
        Ok(applied)
    }

    pub fn kv_digests(&self) -> BTreeMap<String, String> {
        let inner = self.inner.lock().unwrap();
        inner
            .kv
            .iter()
            .map(|(ns, n)| (ns.clone(), hex::encode(n.digest())))
            .collect()
    }

    pub fn kv_dump(&self, ns: &str) -> Vec<(String, KvEntry)> {
        let inner = self.inner.lock().unwrap();
        match inner.kv.get(ns) {
            Some(n) => n.dump().map(|(k, e)| (k.clone(), e.clone())).collect(),
            None => Vec::new(),
        }
    }

    // ---- peers ----

    pub fn update_peers(&self, peers: BTreeMap<String, PeerView>) {
        self.inner.lock().unwrap().peers = peers;
    }

    pub fn peers(&self) -> BTreeMap<String, PeerView> {
        self.inner.lock().unwrap().peers.clone()
    }

    /// Consume this node's deterministic share of the cluster request budget.
    /// Live public node identities are sorted; any division remainder is given
    /// to the first identities, so a converged membership view sums exactly to
    /// the operator-signed global limit rather than multiplying it per node.
    pub fn admit_public_request(&self) -> Result<bool> {
        let limit = crate::quota::policy(self)?.max_requests_per_minute;
        let minute = now_ms() / 60_000;
        let mut inner = self.inner.lock().unwrap();
        let mut public_nodes = inner
            .peers
            .iter()
            .filter(|(_, peer)| peer.public)
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        if self.cfg.public {
            public_nodes.insert(self.id_hex());
        }
        if public_nodes.is_empty() {
            public_nodes.insert(self.id_hex());
        }
        let count = public_nodes.len() as u64;
        let base = limit / count;
        let remainder = limit % count;
        let rank = public_nodes
            .iter()
            .position(|id| id == &self.id_hex())
            .unwrap_or(0) as u64;
        let local_limit = base + u64::from(rank < remainder);
        if inner.quota_request_window.0 != minute {
            inner.quota_request_window = (minute, 0);
        }
        if inner.quota_request_window.1 >= local_limit {
            return Ok(false);
        }
        inner.quota_request_window.1 += 1;
        Ok(true)
    }

    /// Routing table: hostname → worker.
    pub fn routes(&self) -> BTreeMap<String, String> {
        let inner = self.inner.lock().unwrap();
        let mut routes = inner.manifests.routes();
        for record in inner.manifests.live() {
            if let Some(hostname) = self.cfg.default_worker_hostname(&record.manifest.name) {
                // A Worker's deterministic default route is reserved for that
                // Worker, even if another manifest lists it as a custom route.
                routes.insert(hostname, record.manifest.name.clone());
            }
        }
        routes
    }

    pub fn default_worker_hostname(&self, worker: &str) -> Option<String> {
        self.cfg.default_worker_hostname(worker)
    }

    pub fn default_r2_hostname(&self, bucket: &str) -> Option<String> {
        self.cfg
            .default_worker_domain()
            .map(|domain| format!("r2-{bucket}.{domain}"))
    }

    pub fn default_pipeline_hostname(&self, pipeline: &str) -> Option<String> {
        self.cfg
            .default_worker_domain()
            .map(|domain| format!("pipe-{pipeline}.{domain}"))
    }

    pub fn default_flow_hostname(&self, flow: &str) -> Option<String> {
        self.cfg
            .default_worker_domain()
            .map(|domain| format!("flow-{flow}.{domain}"))
    }

    pub fn effective_flow_hostnames(
        &self,
        flow: &str,
        spec: &crate::flow::FlowSpec,
    ) -> Vec<String> {
        let mut hostnames = Vec::with_capacity(spec.hostnames.len() + 1);
        if let Some(default) = self.default_flow_hostname(flow) {
            hostnames.push(default);
        }
        for hostname in &spec.hostnames {
            if !hostnames.contains(hostname) {
                hostnames.push(hostname.clone());
            }
        }
        hostnames
    }

    pub fn effective_pipeline_hostnames(
        &self,
        pipeline: &str,
        spec: &crate::pipeline::PipelineSpec,
    ) -> Vec<String> {
        let mut hostnames = Vec::with_capacity(spec.hostnames.len() + 1);
        if let Some(default) = self.default_pipeline_hostname(pipeline) {
            hostnames.push(default);
        }
        for hostname in &spec.hostnames {
            if !hostnames.contains(hostname) {
                hostnames.push(hostname.clone());
            }
        }
        hostnames
    }

    pub fn effective_r2_hostnames(
        &self,
        bucket: &str,
        spec: &crate::r2::BucketSpec,
    ) -> Vec<String> {
        let mut hostnames = Vec::with_capacity(spec.hostnames.len() + 1);
        if let Some(default) = self.default_r2_hostname(bucket) {
            hostnames.push(default);
        }
        for hostname in &spec.hostnames {
            if !hostnames.contains(hostname) {
                hostnames.push(hostname.clone());
            }
        }
        hostnames
    }

    pub fn effective_worker_hostnames(&self, manifest: &WorkerManifest) -> Vec<String> {
        let mut hostnames = Vec::with_capacity(manifest.hostnames.len() + 1);
        if let Some(default) = self.default_worker_hostname(&manifest.name) {
            hostnames.push(default);
        }
        for hostname in &manifest.hostnames {
            if !hostnames.contains(hostname) {
                hostnames.push(hostname.clone());
            }
        }
        hostnames
    }

    pub fn manifest(&self, name: &str) -> Option<WorkerManifest> {
        self.inner
            .lock()
            .unwrap()
            .manifests
            .get(name)
            .map(|r| r.manifest.clone())
    }

    pub fn live_manifests(&self) -> Vec<WorkerManifest> {
        self.inner
            .lock()
            .unwrap()
            .manifests
            .live()
            .map(|r| r.manifest.clone())
            .collect()
    }

    /// All known Worker identities, including deleted heads, for the signed
    /// transparency/audit surface.
    pub fn manifest_names(&self) -> Vec<String> {
        let mut names = self
            .inner
            .lock()
            .unwrap()
            .manifests
            .all()
            .map(|record| record.manifest.name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        names
    }

    /// Transparency log for one worker (version-ascending envelopes).
    pub fn manifest_log(&self, name: &str) -> Result<Vec<Envelope>> {
        self.store.load_log(name)
    }

    /// Head record (version + envelope digest) for the deploy CLI's
    /// hash-chain link.
    pub fn manifest_head(&self, name: &str) -> Option<(u64, [u8; 32])> {
        let inner = self.inner.lock().unwrap();
        inner
            .manifests
            .get(name)
            .map(|r| (r.manifest.version, r.digest))
    }

    /// Digest over all manifest heads — the anchoring payload. Stable
    /// across nodes with converged manifest sets.
    pub fn anchor_digest(&self) -> (String, usize) {
        use sha2::Digest;
        let inner = self.inner.lock().unwrap();
        let mut heads: Vec<(String, u64, [u8; 32])> = inner
            .manifests
            .all()
            .map(|r| (r.manifest.name.clone(), r.manifest.version, r.digest))
            .collect();
        heads.sort();
        let mut h = sha2::Sha256::new();
        for (name, version, digest) in &heads {
            h.update(name.as_bytes());
            h.update(version.to_le_bytes());
            h.update(digest);
        }
        (hex::encode(h.finalize()), heads.len())
    }

    pub fn set_worker_ports(&self, ports: HashMap<String, u16>) {
        let changed = {
            let mut inner = self.inner.lock().unwrap();
            if inner.worker_ports == ports {
                false
            } else {
                inner.worker_ports = ports;
                true
            }
        };
        if changed {
            self.emit(NodeEvent::Runtime);
        }
    }

    pub fn worker_port(&self, name: &str) -> Option<u16> {
        self.inner.lock().unwrap().worker_ports.get(name).copied()
    }

    pub fn set_runtime_status(
        &self,
        name: &str,
        version: u64,
        state: &str,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        let changed = {
            let mut inner = self.inner.lock().unwrap();
            let same = inner
                .runtime_status
                .get(name)
                .map(|prior| {
                    prior.version == version && prior.state == state && prior.detail == detail
                })
                .unwrap_or(false);
            if same {
                false
            } else {
                inner.runtime_status.insert(
                    name.to_string(),
                    DeploymentStatus {
                        version,
                        state: state.to_string(),
                        detail,
                        updated_at_ms: now_ms(),
                    },
                );
                true
            }
        };
        if changed {
            self.emit(NodeEvent::Runtime);
        }
    }

    pub fn append_runtime_log(&self, name: &str, version: u64, stream: &str, message: &str) {
        const MAX_LINES: usize = 1_000;
        let mut message = message.replace(['\r', '\0'], "");
        if message.len() > 4_000 {
            message.truncate(4_000);
            message.push('…');
        }
        let mut inner = self.inner.lock().unwrap();
        let lines = inner.runtime_logs.entry(name.to_string()).or_default();
        lines.push_back(RuntimeLogLine {
            at_ms: now_ms(),
            version,
            stream: stream.to_string(),
            message,
        });
        while lines.len() > MAX_LINES {
            lines.pop_front();
        }
    }

    pub fn runtime_logs(&self, name: &str, limit: usize) -> Vec<RuntimeLogLine> {
        let inner = self.inner.lock().unwrap();
        inner
            .runtime_logs
            .get(name)
            .map(|lines| {
                lines
                    .iter()
                    .skip(lines.len().saturating_sub(limit.min(1_000)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn enqueue_request_log(&self, entry: crate::observability::RequestLogEntry) {
        const MAX_PENDING: usize = 50_000;
        let mut inner = self.inner.lock().unwrap();
        inner.pending_request_logs.push_back(entry);
        while inner.pending_request_logs.len() > MAX_PENDING {
            inner.pending_request_logs.pop_front();
        }
    }

    pub(crate) fn take_pending_request_logs(&self) -> Vec<crate::observability::RequestLogEntry> {
        self.inner
            .lock()
            .unwrap()
            .pending_request_logs
            .drain(..)
            .collect()
    }

    pub(crate) fn requeue_request_logs(&self, entries: Vec<crate::observability::RequestLogEntry>) {
        const MAX_PENDING: usize = 50_000;
        let mut inner = self.inner.lock().unwrap();
        for entry in entries.into_iter().rev() {
            inner.pending_request_logs.push_front(entry);
        }
        while inner.pending_request_logs.len() > MAX_PENDING {
            inner.pending_request_logs.pop_front();
        }
    }

    pub(crate) fn pending_request_logs(
        &self,
        worker: &str,
    ) -> Vec<crate::observability::RequestLogEntry> {
        self.inner
            .lock()
            .unwrap()
            .pending_request_logs
            .iter()
            .filter(|entry| entry.worker == worker)
            .cloned()
            .collect()
    }

    /// Local, per-Worker materialization state advertised through gossip.
    pub fn deployment_statuses(&self) -> BTreeMap<String, DeploymentStatus> {
        let (manifests, ports, explicit) = {
            let inner = self.inner.lock().unwrap();
            (
                inner
                    .manifests
                    .live()
                    .map(|record| record.manifest.clone())
                    .collect::<Vec<_>>(),
                inner.worker_ports.clone(),
                inner.runtime_status.clone(),
            )
        };
        let mut statuses = manifests
            .into_iter()
            .map(|manifest| {
                let missing = manifest.blob_refs().any(|sha| !self.blobs.has(&sha));
                let eligible = crate::placement::eligible(self, &self.id_hex(), &manifest);
                let fenced_owner = !crate::deploy::durable_objects(&manifest).is_empty()
                    && ports.contains_key(&manifest.name);
                let status = if !eligible && !fenced_owner {
                    DeploymentStatus {
                        version: manifest.version,
                        state: "not_placed".into(),
                        detail: "node capability tags do not satisfy this Worker".into(),
                        updated_at_ms: now_ms(),
                    }
                } else if missing {
                    DeploymentStatus {
                        version: manifest.version,
                        state: "waiting_blobs".into(),
                        detail: "fetching immutable blobs from peers".into(),
                        updated_at_ms: now_ms(),
                    }
                } else if manifest.main.is_empty() {
                    DeploymentStatus {
                        version: manifest.version,
                        state: "ready".into(),
                        detail: "static assets ready".into(),
                        updated_at_ms: now_ms(),
                    }
                } else if let Some(port) = ports.get(&manifest.name) {
                    DeploymentStatus {
                        version: manifest.version,
                        state: "running".into(),
                        detail: if eligible {
                            format!("workerd on 127.0.0.1:{port}")
                        } else {
                            format!(
                                "fenced Durable Object owner on 127.0.0.1:{port}; retained for state safety"
                            )
                        },
                        updated_at_ms: explicit
                            .get(&manifest.name)
                            .map(|status| status.updated_at_ms)
                            .unwrap_or_else(now_ms),
                    }
                } else {
                    explicit
                        .get(&manifest.name)
                        .cloned()
                        .filter(|status| status.version == manifest.version)
                        .unwrap_or(DeploymentStatus {
                            version: manifest.version,
                            state: "starting".into(),
                            detail: "waiting for local runtime".into(),
                            updated_at_ms: now_ms(),
                        })
                };
                (manifest.name, status)
            })
            .collect::<BTreeMap<_, _>>();
        for (view, preview) in crate::preview::active_previews(self) {
            let manifest = preview.manifest;
            let runtime_id = view.resource.name;
            let missing = manifest.blob_refs().any(|sha| !self.blobs.has(&sha));
            let status = if !crate::placement::eligible(self, &self.id_hex(), &manifest) {
                DeploymentStatus {
                    version: view.resource.version,
                    state: "not_placed".into(),
                    detail: "node capability tags do not satisfy this Worker preview".into(),
                    updated_at_ms: now_ms(),
                }
            } else if missing {
                DeploymentStatus {
                    version: view.resource.version,
                    state: "waiting_blobs".into(),
                    detail: "fetching immutable preview blobs from peers".into(),
                    updated_at_ms: now_ms(),
                }
            } else if manifest.main.is_empty() {
                DeploymentStatus {
                    version: view.resource.version,
                    state: "ready".into(),
                    detail: "static preview assets ready".into(),
                    updated_at_ms: now_ms(),
                }
            } else if let Some(port) = ports.get(&runtime_id) {
                DeploymentStatus {
                    version: view.resource.version,
                    state: "running".into(),
                    detail: format!("preview workerd on 127.0.0.1:{port}"),
                    updated_at_ms: explicit
                        .get(&runtime_id)
                        .map(|status| status.updated_at_ms)
                        .unwrap_or_else(now_ms),
                }
            } else {
                explicit
                    .get(&runtime_id)
                    .cloned()
                    .filter(|status| status.version == view.resource.version)
                    .unwrap_or(DeploymentStatus {
                        version: view.resource.version,
                        state: "starting".into(),
                        detail: "waiting for local preview runtime".into(),
                        updated_at_ms: now_ms(),
                    })
            };
            statuses.insert(runtime_id, status);
        }
        statuses
    }

    pub fn set_kvbind_port(&self, port: u16) {
        self.inner.lock().unwrap().kvbind_port = port;
    }

    pub fn kvbind_port(&self) -> u16 {
        self.inner.lock().unwrap().kvbind_port
    }

    pub fn set_r2bind_port(&self, port: u16) {
        self.inner.lock().unwrap().r2bind_port = port;
    }

    pub fn r2bind_port(&self) -> u16 {
        self.inner.lock().unwrap().r2bind_port
    }

    pub fn set_d1bind_port(&self, port: u16) {
        self.inner.lock().unwrap().d1bind_port = port;
    }

    pub fn d1bind_port(&self) -> u16 {
        self.inner.lock().unwrap().d1bind_port
    }

    pub fn set_qbind_port(&self, port: u16) {
        self.inner.lock().unwrap().qbind_port = port;
    }

    pub fn qbind_port(&self) -> u16 {
        self.inner.lock().unwrap().qbind_port
    }

    pub fn set_analyticsbind_port(&self, port: u16) {
        self.inner.lock().unwrap().analyticsbind_port = port;
    }

    pub fn analyticsbind_port(&self) -> u16 {
        self.inner.lock().unwrap().analyticsbind_port
    }

    pub fn set_pbind_port(&self, port: u16) {
        self.inner.lock().unwrap().pbind_port = port;
    }

    pub fn pbind_port(&self) -> u16 {
        self.inner.lock().unwrap().pbind_port
    }

    pub fn set_workflowbind_port(&self, port: u16) {
        self.inner.lock().unwrap().workflowbind_port = port;
    }

    pub fn workflowbind_port(&self) -> u16 {
        self.inner.lock().unwrap().workflowbind_port
    }

    pub fn set_emailbind_port(&self, port: u16) {
        self.inner.lock().unwrap().emailbind_port = port;
    }

    pub fn emailbind_port(&self) -> u16 {
        self.inner.lock().unwrap().emailbind_port
    }

    pub fn set_servicebind_port(&self, port: u16) {
        self.inner.lock().unwrap().servicebind_port = port;
    }

    pub fn servicebind_port(&self) -> u16 {
        self.inner.lock().unwrap().servicebind_port
    }

    pub fn set_binarybind_port(&self, port: u16) {
        self.inner.lock().unwrap().binarybind_port = port;
    }

    pub fn binarybind_port(&self) -> u16 {
        self.inner.lock().unwrap().binarybind_port
    }

    pub fn set_worker_event_token(&self, worker: &str, token: String) {
        self.inner
            .lock()
            .unwrap()
            .worker_event_tokens
            .insert(worker.to_string(), token);
    }

    pub fn remove_worker_event_token(&self, worker: &str) {
        self.inner
            .lock()
            .unwrap()
            .worker_event_tokens
            .remove(worker);
    }

    pub fn worker_event_token(&self, worker: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .worker_event_tokens
            .get(worker)
            .cloned()
    }

    pub(crate) fn r2_schema_ready(&self, database: &str) -> bool {
        self.r2_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_r2_schema_ready(&self, database: String) {
        self.r2_schemas.lock().unwrap().insert(database);
    }

    pub(crate) fn queue_schema_ready(&self, database: &str) -> bool {
        self.queue_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_queue_schema_ready(&self, database: String) {
        self.queue_schemas.lock().unwrap().insert(database);
    }

    pub(crate) fn analytics_schema_ready(&self, database: &str) -> bool {
        self.analytics_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_analytics_schema_ready(&self, database: String) {
        self.analytics_schemas.lock().unwrap().insert(database);
    }

    pub(crate) fn pipeline_schema_ready(&self, database: &str) -> bool {
        self.pipeline_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_pipeline_schema_ready(&self, database: String) {
        self.pipeline_schemas.lock().unwrap().insert(database);
    }

    pub(crate) fn workflow_schema_ready(&self, database: &str) -> bool {
        self.workflow_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_workflow_schema_ready(&self, database: String) {
        self.workflow_schemas.lock().unwrap().insert(database);
    }

    pub(crate) fn flow_schema_ready(&self, database: &str) -> bool {
        self.flow_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_flow_schema_ready(&self, database: String) {
        self.flow_schemas.lock().unwrap().insert(database);
    }

    pub(crate) fn email_schema_ready(&self, database: &str) -> bool {
        self.email_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_email_schema_ready(&self, database: String) {
        self.email_schemas.lock().unwrap().insert(database);
    }

    pub(crate) fn cron_schema_ready(&self, database: &str) -> bool {
        self.cron_schemas.lock().unwrap().contains(database)
    }

    pub(crate) fn mark_cron_schema_ready(&self, database: String) {
        self.cron_schemas.lock().unwrap().insert(database);
    }

    /// Periodic GC of dead claims + KV tombstones.
    pub fn gc(&self) {
        let mut inner = self.inner.lock().unwrap();
        let now = now_ms();
        const HORIZON_MS: u64 = 24 * 3600 * 1000;
        inner.claims.gc(now, HORIZON_MS);
        for ns in inner.kv.values_mut() {
            ns.gc(now, HORIZON_MS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_core::envelope::Envelope;
    use std::collections::BTreeMap;

    fn manifest(name: &str, hostnames: &[&str]) -> WorkerManifest {
        WorkerManifest {
            name: name.into(),
            version: 1,
            prev: None,
            deleted: false,
            main: String::new(),
            modules: vec![],
            assets: vec![],
            hostnames: hostnames
                .iter()
                .map(|hostname| (*hostname).into())
                .collect(),
            env: BTreeMap::new(),
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-08-04".into(),
        }
    }

    #[test]
    fn default_worker_routes_are_deterministic_and_reserved() {
        let operator = Keypair::from_seed([41; 32]);
        let data_dir = std::env::temp_dir().join(format!(
            "rf-default-routes-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let cfg: NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {data_dir:?}
            operator = "{operator}"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:17381"
            [peer_api]
            listen = "127.0.0.1:17382"
            [ingress]
            default_domain = "workers.example"
            "#,
            data_dir = data_dir.display(),
            operator = operator.public(),
        ))
        .unwrap();
        let node = Node::open(cfg, Keypair::from_seed([42; 32])).unwrap();
        let alpha = manifest(
            "alpha",
            &[
                "alpha.workers.example",
                "beta.workers.example",
                "custom.example",
            ],
        );
        let beta = manifest("beta", &[]);
        node.ingest_manifest(&Envelope::seal(&alpha, &operator))
            .unwrap();
        node.ingest_manifest(&Envelope::seal(&beta, &operator))
            .unwrap();

        assert_eq!(
            node.effective_worker_hostnames(&alpha),
            vec![
                "alpha.workers.example".to_string(),
                "beta.workers.example".to_string(),
                "custom.example".to_string(),
            ]
        );
        let routes = node.routes();
        assert_eq!(routes["alpha.workers.example"], "alpha");
        assert_eq!(routes["beta.workers.example"], "beta");
        assert_eq!(routes["custom.example"], "alpha");

        drop(node);
        std::fs::remove_dir_all(data_dir).unwrap();
    }
}
