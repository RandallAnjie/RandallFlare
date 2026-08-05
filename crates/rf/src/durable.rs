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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_PROXY_BODY: usize = 64 * 1024 * 1024;
const MAX_WEBSOCKET_HEADERS: usize = 256;
const MAX_WEBSOCKET_HEADER_BYTES: usize = 256 * 1024;
const MAX_WEBSOCKET_TARGET_BYTES: usize = 16 * 1024;
const TUNNEL_CHUNK: usize = 32 * 1024;
const MAX_TUNNEL_FRAME: usize = TUNNEL_CHUNK + 8 + 24 + 16;
pub const TUNNEL_UPGRADE: &str = "randallflare-worker-tunnel-v1";
pub const TUNNEL_PROOF_HEADER: &str = "x-rf-tunnel-proof";
pub const TUNNEL_PROOF: &[u8] = b"randallflare-worker-tunnel-accepted-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Open a real HTTP/1.1 WebSocket upgrade against a local workerd socket.
/// The returned stream starts immediately after the upstream 101 response;
/// callers decide whether it is connected directly to public ingress or to
/// the encrypted inter-node tunnel.
pub async fn open_worker_websocket(
    client: &reqwest::Client,
    request: &ProxyRequest,
    port: u16,
) -> Result<(axum::http::HeaderMap, reqwest::Upgraded)> {
    if request.method != "GET" || !request.body.is_empty() {
        anyhow::bail!("WebSocket upgrade must use GET");
    }
    if request.path_and_query.len() > MAX_WEBSOCKET_TARGET_BYTES
        || request.headers.len() > MAX_WEBSOCKET_HEADERS
        || request.headers.iter().fold(0usize, |total, (name, value)| {
            total.saturating_add(name.len()).saturating_add(value.len())
        }) > MAX_WEBSOCKET_HEADER_BYTES
    {
        anyhow::bail!("WebSocket request metadata exceeds its bound");
    }
    let connection_upgrade = request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            && std::str::from_utf8(value).ok().is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
    });
    let websocket_upgrade = request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade")
            && std::str::from_utf8(value)
                .ok()
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
    });
    if !connection_upgrade || !websocket_upgrade {
        anyhow::bail!("WebSocket upgrade headers are missing");
    }
    let uri = request
        .path_and_query
        .parse::<axum::http::Uri>()
        .context("invalid WebSocket request target")?;
    if uri.scheme().is_some() || uri.authority().is_some() || !uri.path().starts_with('/') {
        anyhow::bail!("invalid WebSocket request target");
    }
    let original_host = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone());
    let url = format!("http://127.0.0.1:{port}{}", request.path_and_query);
    let mut builder = client.get(url).body(request.body.clone());
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .context("invalid WebSocket header name")?;
        let value = reqwest::header::HeaderValue::from_bytes(value)
            .context("invalid WebSocket header value")?;
        builder = builder.header(name, value);
    }
    if let Some(host) = original_host {
        builder = builder.header("x-forwarded-host", host);
    }
    let response = builder.send().await.context("opening workerd WebSocket")?;
    if response.status() != reqwest::StatusCode::SWITCHING_PROTOCOLS {
        let status = response.status();
        let detail = response
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(512)
            .collect::<String>();
        anyhow::bail!("workerd rejected WebSocket upgrade with {status}: {detail}");
    }
    let headers = response.headers().clone();
    let upgraded = response
        .upgrade()
        .await
        .context("upgrading workerd WebSocket")?;
    Ok((headers, upgraded))
}

fn tunnel_aad(session: &str, direction: &str, sequence: u64) -> Vec<u8> {
    format!("rf-worker-tunnel-v1\n{session}\n{direction}\n{sequence}").into_bytes()
}

async fn copy_encrypted<R, W>(
    mut reader: R,
    mut writer: W,
    secret: &[u8; 32],
    session: &str,
    direction: &str,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use rand::RngCore;

    let mut buffer = vec![0u8; TUNNEL_CHUNK];
    let mut sequence = 0u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = crate::transport::seal_raw(
            secret,
            &nonce,
            &tunnel_aad(session, direction, sequence),
            &buffer[..read],
        )?;
        let frame_len = 8usize
            .saturating_add(nonce.len())
            .saturating_add(ciphertext.len());
        if frame_len > MAX_TUNNEL_FRAME {
            anyhow::bail!("encrypted tunnel frame exceeded its bound");
        }
        writer.write_u32(frame_len as u32).await?;
        writer.write_u64(sequence).await?;
        writer.write_all(&nonce).await?;
        writer.write_all(&ciphertext).await?;
        writer.flush().await?;
        sequence = sequence
            .checked_add(1)
            .context("encrypted tunnel sequence exhausted")?;
    }
}

async fn copy_decrypted<R, W>(
    mut reader: R,
    mut writer: W,
    secret: &[u8; 32],
    session: &str,
    direction: &str,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut expected_sequence = 0u64;
    loop {
        let frame_len = match reader.read_u32().await {
            Ok(frame_len) => frame_len as usize,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                writer.shutdown().await?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if !(8 + 24 + 16..=MAX_TUNNEL_FRAME).contains(&frame_len) {
            anyhow::bail!("invalid encrypted tunnel frame length");
        }
        let sequence = reader.read_u64().await?;
        if sequence != expected_sequence {
            anyhow::bail!("encrypted tunnel frame sequence mismatch");
        }
        let mut nonce = [0u8; 24];
        reader.read_exact(&mut nonce).await?;
        let mut ciphertext = vec![0u8; frame_len - 8 - nonce.len()];
        reader.read_exact(&mut ciphertext).await?;
        let plaintext = crate::transport::open_raw(
            secret,
            &nonce,
            &tunnel_aad(session, direction, sequence),
            &ciphertext,
        )?;
        writer.write_all(&plaintext).await?;
        writer.flush().await?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .context("encrypted tunnel sequence exhausted")?;
    }
}

/// Public-ingress side of a peer tunnel. Browser bytes are encrypted before
/// crossing the node network; owner bytes are authenticated and decrypted.
pub async fn relay_tunnel_ingress<I, P>(
    ingress: I,
    peer: P,
    secret: [u8; 32],
    session: String,
) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (ingress_read, ingress_write) = tokio::io::split(ingress);
    let (peer_read, peer_write) = tokio::io::split(peer);
    tokio::try_join!(
        copy_encrypted(
            ingress_read,
            peer_write,
            &secret,
            &session,
            "ingress-to-owner"
        ),
        copy_decrypted(
            peer_read,
            ingress_write,
            &secret,
            &session,
            "owner-to-ingress"
        )
    )?;
    Ok(())
}

/// Owner side of a peer tunnel. It reverses the two framed directions and
/// exposes an ordinary byte stream to workerd.
pub async fn relay_tunnel_owner<P, U>(
    peer: P,
    upstream: U,
    secret: [u8; 32],
    session: String,
) -> Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (peer_read, peer_write) = tokio::io::split(peer);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    tokio::try_join!(
        copy_decrypted(
            peer_read,
            upstream_write,
            &secret,
            &session,
            "ingress-to-owner"
        ),
        copy_encrypted(
            upstream_read,
            peer_write,
            &secret,
            &session,
            "owner-to-ingress"
        )
    )?;
    Ok(())
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
        let manifest = self
            .node
            .manifest(worker)
            .with_context(|| format!("Worker {worker} manifest is not available"))?;
        let mut universe = Vec::new();
        if crate::placement::eligible(&self.node, &self.node.id_hex(), &manifest) {
            universe.push(self.node.id());
        }
        for id in self.node.peers().keys() {
            if crate::placement::eligible(&self.node, id, &manifest) {
                if let Ok(id) = id.parse() {
                    universe.push(id);
                }
            }
        }
        if universe.is_empty() {
            anyhow::bail!(
                "no live node satisfies Durable Object Worker {worker} placement constraints"
            );
        }
        d1::ensure_database_on(&self.node, &Self::db_name(worker), universe)
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
            let path = format!("/v1/do/{worker}/proxy");
            let mut candidates = Vec::new();
            if let Some(leader) = self.leader(worker) {
                candidates.push(leader);
            }
            if let Some(raw) = self
                .node
                .kv_get(crate::acme::NS, &d1::kv_key(&Self::db_name(worker)))
            {
                if let Ok(meta) = serde_json::from_slice::<d1::DbMeta>(&raw) {
                    candidates.extend(meta.group);
                }
            }
            candidates.sort();
            candidates.dedup();
            // Prefer a locally observed leader, while still probing the fixed
            // replica group when this ingress node is not itself a member.
            if let Some(leader) = self.leader(worker) {
                if let Some(index) = candidates.iter().position(|id| *id == leader) {
                    candidates.swap(0, index);
                }
            }
            for candidate in candidates {
                if candidate == self.node.id() {
                    if self.is_owner(worker) {
                        if let Ok(response) = self.proxy_on_owner(worker, request.clone()).await {
                            return Ok(response);
                        }
                    }
                    continue;
                }
                let Some(addr) = self
                    .node
                    .peers()
                    .get(&candidate.to_string())
                    .and_then(|peer| peer.api_addr)
                else {
                    continue;
                };
                if let Ok(raw) = self
                    .client
                    .post(&addr.to_string(), &path, postcard::to_stdvec(&request)?)
                    .await
                {
                    return Ok(postcard::from_bytes(&raw)?);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
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

    #[tokio::test]
    async fn encrypted_tunnel_relays_both_directions() {
        let secret = [42u8; 32];
        let session = "00112233445566778899aabbccddeeff0011223344556677".to_string();
        let (mut browser, ingress_side) = tokio::io::duplex(128 * 1024);
        let (ingress_peer, owner_peer) = tokio::io::duplex(128 * 1024);
        let (owner_upstream, mut workerd) = tokio::io::duplex(128 * 1024);
        let ingress_session = session.clone();
        let ingress = tokio::spawn(async move {
            relay_tunnel_ingress(ingress_side, ingress_peer, secret, ingress_session).await
        });
        let owner = tokio::spawn(async move {
            relay_tunnel_owner(owner_peer, owner_upstream, secret, session).await
        });

        browser.write_all(b"masked websocket frame").await.unwrap();
        let mut received = vec![0u8; "masked websocket frame".len()];
        workerd.read_exact(&mut received).await.unwrap();
        assert_eq!(received, b"masked websocket frame");

        workerd.write_all(b"server websocket frame").await.unwrap();
        let mut received = vec![0u8; "server websocket frame".len()];
        browser.read_exact(&mut received).await.unwrap();
        assert_eq!(received, b"server websocket frame");

        drop(browser);
        drop(workerd);
        ingress.await.unwrap().unwrap();
        owner.await.unwrap().unwrap();
    }
}
