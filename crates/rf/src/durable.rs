//! Distributed ownership and persistence for workerd Durable Objects.
//!
//! Stock workerd stores each namespace as local SQLite files and does
//! not expose the storage protocol. rf therefore fences an entire
//! DO-bearing Worker with a dedicated D1 micro-quorum. Only that
//! quorum's leader runs workerd. After each request, the owner
//! checkpoints every DO SQLite file and commits a directory snapshot
//! through D1 before returning the response. A replacement owner
//! restores the latest majority-committed snapshot before it starts.

use crate::d1::{self, Leadership, Registry};
use crate::node::Node;
use crate::peers::PeerClient;
use anyhow::{Context, Result};
use base64::Engine;
use futures_util::StreamExt;
use rf_core::identity::PublicId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_PROXY_BODY: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileSnapshot {
    path: String,
    data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    generation: u64,
    files: Vec<FileSnapshot>,
}

#[derive(Clone)]
pub struct Coordinator {
    node: Arc<Node>,
    registry: Registry,
    leadership: Leadership,
    client: PeerClient,
    http: reqwest::Client,
    commit_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    committed_digests: Arc<Mutex<HashMap<String, [u8; 32]>>>,
}

impl Coordinator {
    pub fn new(node: Arc<Node>, registry: Registry, leadership: Leadership) -> Self {
        Self {
            client: PeerClient::new(node.cfg.cluster_secret_bytes().expect("validated config")),
            node,
            registry,
            leadership,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("DO proxy client"),
            commit_locks: Default::default(),
            committed_digests: Default::default(),
        }
    }

    pub fn db_name(worker: &str) -> String {
        let digest = Sha256::digest(worker.as_bytes());
        format!("rfdo-{}", &hex::encode(digest)[..24])
    }

    pub fn ensure_worker(&self, worker: &str) -> Result<Vec<PublicId>> {
        d1::ensure_database(&self.node, &Self::db_name(worker))
    }

    /// Upgrade path for DO manifests deployed before quorum ownership
    /// existed. Wait for gossip membership to settle so every node
    /// deterministically derives the same replica group.
    pub fn spawn_ensurer(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            loop {
                for manifest in this.node.live_manifests() {
                    if !crate::deploy::durable_objects(&manifest).is_empty()
                        && this
                            .node
                            .kv_get(crate::acme::NS, &d1::kv_key(&Self::db_name(&manifest.name)))
                            .is_none()
                    {
                        if let Err(e) = this.ensure_worker(&manifest.name) {
                            tracing::warn!("creating DO quorum for {}: {e:#}", manifest.name);
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    /// Capture mutations caused without an ingress request (alarms,
    /// WebSocket events). Unchanged directories are digest-deduped and
    /// do not create Raft entries.
    pub fn spawn_checkpointer(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                for manifest in this.node.live_manifests() {
                    if !crate::deploy::durable_objects(&manifest).is_empty()
                        && this.is_owner(&manifest.name)
                        && this.node.worker_port(&manifest.name).is_some()
                    {
                        if let Err(e) = this.commit(&manifest.name).await {
                            tracing::debug!("periodic DO checkpoint {}: {e:#}", manifest.name);
                        }
                    }
                }
            }
        });
    }

    pub fn leader(&self, worker: &str) -> Option<PublicId> {
        self.leadership
            .lock()
            .unwrap()
            .get(&Self::db_name(worker))
            .copied()
    }

    pub fn is_owner(&self, worker: &str) -> bool {
        self.leader(worker) == Some(self.node.id())
    }

    pub fn storage_dir(&self, worker: &str) -> PathBuf {
        self.node.cfg.data_dir.join("durable").join(worker)
    }

    /// Restore the latest committed workerd SQLite directory. Must be
    /// called before spawning workerd on a newly elected owner.
    pub async fn restore(&self, worker: &str) -> Result<()> {
        if !self.is_owner(worker) {
            anyhow::bail!("not Durable Object owner for {worker}");
        }
        let db = Self::db_name(worker);
        d1::exec_local(
            &self.registry,
            &db,
            "CREATE TABLE IF NOT EXISTS rf_do_snapshot (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, data TEXT NOT NULL)",
            vec![],
        )
        .await?;
        let result = d1::exec_local(
            &self.registry,
            &db,
            "SELECT generation, data FROM rf_do_snapshot WHERE id = 1",
            vec![],
        )
        .await?;
        let Some(row) = result.rows.and_then(|mut rows| rows.pop()) else {
            std::fs::create_dir_all(self.storage_dir(worker))?;
            return Ok(());
        };
        let encoded = row
            .get("data")
            .and_then(|v| v.as_str())
            .context("DO snapshot row missing data")?;
        let compressed = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let raw = zstd::stream::decode_all(compressed.as_slice())?;
        let snapshot: Snapshot = postcard::from_bytes(&raw)?;
        let digest = snapshot_digest(&snapshot)?;
        let dir = self.storage_dir(worker);
        tokio::task::spawn_blocking(move || install_snapshot(&dir, snapshot))
            .await
            .context("DO restore task")??;
        self.committed_digests
            .lock()
            .unwrap()
            .insert(worker.to_string(), digest);
        Ok(())
    }

    /// Majority-commit all local DO SQLite state. The request that
    /// caused the mutation must not be acknowledged until this returns.
    pub async fn commit(&self, worker: &str) -> Result<()> {
        if !self.is_owner(worker) {
            anyhow::bail!("lost Durable Object ownership for {worker}");
        }
        let lock = {
            let mut locks = self.commit_locks.lock().unwrap();
            locks
                .entry(worker.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        if !self.is_owner(worker) {
            anyhow::bail!("lost Durable Object ownership for {worker}");
        }
        let dir = self.storage_dir(worker);
        let generation = crate::node::now_ms();
        let snapshot = tokio::task::spawn_blocking(move || capture_snapshot(&dir, generation))
            .await
            .context("DO snapshot task")??;
        // `generation` is intentionally excluded: it changes on every
        // check, while the storage bytes only change after a mutation.
        let digest = snapshot_digest(&snapshot)?;
        if self.committed_digests.lock().unwrap().get(worker) == Some(&digest) {
            return Ok(());
        }
        let raw = postcard::to_stdvec(&snapshot)?;
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(compressed);
        d1::exec_local(
            &self.registry,
            &Self::db_name(worker),
            "INSERT INTO rf_do_snapshot (id, generation, data) VALUES (1, ?1, ?2) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation, data=excluded.data",
            vec![generation.into(), encoded.into()],
        )
        .await?;
        self.committed_digests
            .lock()
            .unwrap()
            .insert(worker.to_string(), digest);
        Ok(())
    }

    pub async fn dispatch(&self, worker: &str, request: ProxyRequest) -> Result<ProxyResponse> {
        for _ in 0..30 {
            let leader = self
                .leader(worker)
                .context("DO owner election in progress")?;
            if leader == self.node.id() {
                return self.proxy_on_owner(worker, request).await;
            }
            let addr = self
                .node
                .peers()
                .get(&leader.to_string())
                .and_then(|p| p.api_addr)
                .context("DO owner is not reachable")?;
            let path = format!("/v1/do/{worker}/proxy");
            match self
                .client
                .post(&addr.to_string(), &path, postcard::to_stdvec(&request)?)
                .await
            {
                Ok(raw) => return Ok(postcard::from_bytes(&raw)?),
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(300)).await,
            }
        }
        anyhow::bail!("no reachable Durable Object owner for {worker}")
    }

    pub async fn proxy_on_owner(
        &self,
        worker: &str,
        request: ProxyRequest,
    ) -> Result<ProxyResponse> {
        if !self.is_owner(worker) {
            anyhow::bail!("not Durable Object owner for {worker}");
        }
        let port = self
            .node
            .worker_port(worker)
            .context("Durable Object owner runtime is starting")?;
        let url = format!("http://127.0.0.1:{port}{}", request.path_and_query);
        let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
        let mut builder = self.http.request(method, url).body(request.body);
        for (name, value) in request.headers {
            if name.eq_ignore_ascii_case("host") {
                builder = builder.header("x-forwarded-host", value);
                continue;
            }
            if is_hop_header(&name) {
                continue;
            }
            builder = builder.header(&name, value);
        }
        let response = builder.send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| !is_hop_header(name.as_str()))
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > MAX_PROXY_BODY {
                anyhow::bail!("Durable Object response exceeds 64 MiB");
            }
            body.extend_from_slice(&chunk);
        }
        self.commit(worker).await?;
        Ok(ProxyResponse {
            status,
            headers,
            body,
        })
    }
}

fn snapshot_digest(snapshot: &Snapshot) -> Result<[u8; 32]> {
    Ok(Sha256::digest(postcard::to_stdvec(&snapshot.files)?).into())
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn capture_snapshot(root: &Path, generation: u64) -> Result<Snapshot> {
    std::fs::create_dir_all(root)?;
    let sqlite_files: Vec<PathBuf> = walk_files(root)?
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("sqlite"))
        .collect();
    for path in &sqlite_files {
        let conn = rusqlite::Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    }
    let mut files = Vec::new();
    for path in sqlite_files {
        let rel = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        files.push(FileSnapshot {
            path: rel,
            data: std::fs::read(path)?,
        });
    }
    Ok(Snapshot { generation, files })
}

fn install_snapshot(root: &Path, snapshot: Snapshot) -> Result<()> {
    std::fs::create_dir_all(root)?;
    for path in walk_files(root)? {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".sqlite")
            || name.ends_with(".sqlite-wal")
            || name.ends_with(".sqlite-shm")
        {
            std::fs::remove_file(path)?;
        }
    }
    for file in snapshot.files {
        let rel = Path::new(&file.path);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            anyhow::bail!("unsafe path in DO snapshot");
        }
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("sqlite.rf-tmp");
        std::fs::write(&tmp, file.data)?;
        std::fs::rename(tmp, path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_db_names_are_stable_and_valid() {
        assert_eq!(
            Coordinator::db_name("counter"),
            Coordinator::db_name("counter")
        );
        assert_ne!(
            Coordinator::db_name("counter"),
            Coordinator::db_name("chat")
        );
        assert!(rf_core::manifest::valid_name(&Coordinator::db_name(
            "counter"
        )));
    }

    #[test]
    fn snapshot_digest_ignores_generation_but_detects_storage_changes() {
        let snapshot = |generation, data| Snapshot {
            generation,
            files: vec![FileSnapshot {
                path: "object.sqlite".into(),
                data,
            }],
        };
        assert_eq!(
            snapshot_digest(&snapshot(1, vec![1, 2, 3])).unwrap(),
            snapshot_digest(&snapshot(2, vec![1, 2, 3])).unwrap()
        );
        assert_ne!(
            snapshot_digest(&snapshot(1, vec![1, 2, 3])).unwrap(),
            snapshot_digest(&snapshot(1, vec![1, 2, 4])).unwrap()
        );
    }
}
