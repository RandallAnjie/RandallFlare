//! HTTP client for the peer API — used by gossip-driven anti-entropy
//! (manifest/claim/KV sync, blob fetch) and by the CLI (deploy, kv,
//! status). All requests carry the cluster-secret HMAC and an
//! XChaCha20-Poly1305 encrypted body; responses are encrypted too.

use crate::auth;
use crate::transport;
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rf_core::envelope::Envelope;
use rf_core::kv::KvEntry;
use sha2::Digest;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_PEER_RESPONSE: usize = crate::binary::MAX_BINARY_BYTES + 1024 * 1024 + 16;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct KvListItem {
    pub key: String,
    pub size: u64,
    pub expires_at_ms: Option<u64>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct KvListPage {
    pub entries: Vec<KvListItem>,
    pub list_complete: bool,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct KvValue {
    pub value_base64: String,
    pub expires_at_ms: Option<u64>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug)]
struct PeerHttpError {
    method: String,
    path: String,
    status: u16,
    body: String,
}

impl std::fmt::Display for PeerHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} → {}: {}",
            self.method, self.path, self.status, self.body
        )
    }
}

impl std::error::Error for PeerHttpError {}

fn component(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn peer_api_candidates(base: &str, status: &serde_json::Value) -> Vec<String> {
    let mut candidates = vec![base.to_string()];
    for api in status["peers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|peer| peer["api"].as_str())
        .filter(|api| !api.is_empty())
    {
        if !candidates.iter().any(|candidate| candidate == api) {
            candidates.push(api.to_string());
        }
    }
    candidates
}

#[derive(Clone)]
pub struct PeerClient {
    http: reqwest::Client,
    secret: [u8; 32],
    targets: Arc<Mutex<HashMap<String, String>>>,
}

impl PeerClient {
    pub fn new(secret: [u8; 32]) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        Self {
            http,
            secret,
            targets: Default::default(),
        }
    }

    async fn target_id(&self, base: &str) -> Result<String> {
        if let Some(target) = self.targets.lock().unwrap().get(base).cloned() {
            return Ok(target);
        }
        let ping = self
            .http
            .get(format!("http://{base}/v1/ping"))
            .send()
            .await
            .with_context(|| format!("discovering peer identity at {base}"))?
            .error_for_status()?
            .text()
            .await?;
        let target = ping
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("peer {base} returned an invalid identity ping"))?;
        target
            .parse::<rf_core::identity::PublicId>()
            .map_err(|e| anyhow::anyhow!("peer ping identity: {e}"))?;
        let target = target.to_string();
        self.targets
            .lock()
            .unwrap()
            .insert(base.to_string(), target.clone());
        Ok(target)
    }

    async fn get(&self, base: &str, path: &str) -> Result<Vec<u8>> {
        let target = self.target_id(base).await?;
        let ts = crate::node::now_ms();
        let mac = auth::mac_hex(&self.secret, ts, "GET", path, b"");
        let (nonce, body) = transport::seal(
            &self.secret,
            &transport::request_aad(&ts.to_string(), "GET", path, &target),
            b"",
        )?;
        let resp = self
            .http
            .get(format!("http://{base}{path}"))
            .header(auth::TS_HEADER, ts.to_string())
            .header(auth::MAC_HEADER, mac)
            .header(transport::ENC_HEADER, transport::VERSION)
            .header(transport::NONCE_HEADER, &nonce)
            .header(transport::TARGET_HEADER, target)
            .body(body)
            .send()
            .await
            .with_context(|| format!("GET {base}{path}"))?;
        self.decode_response("GET", path, &nonce, resp).await
    }

    pub async fn post(&self, base: &str, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let target = self.target_id(base).await?;
        let ts = crate::node::now_ms();
        let mac = auth::mac_hex(&self.secret, ts, "POST", path, &body);
        let (nonce, ciphertext) = transport::seal(
            &self.secret,
            &transport::request_aad(&ts.to_string(), "POST", path, &target),
            &body,
        )?;
        let resp = self
            .http
            .post(format!("http://{base}{path}"))
            .header(auth::TS_HEADER, ts.to_string())
            .header(auth::MAC_HEADER, mac)
            .header(transport::ENC_HEADER, transport::VERSION)
            .header(transport::NONCE_HEADER, &nonce)
            .header(transport::TARGET_HEADER, target)
            .body(ciphertext)
            .send()
            .await
            .with_context(|| format!("POST {base}{path}"))?;
        self.decode_response("POST", path, &nonce, resp).await
    }

    async fn delete(&self, base: &str, path: &str) -> Result<Vec<u8>> {
        let target = self.target_id(base).await?;
        let ts = crate::node::now_ms();
        let mac = auth::mac_hex(&self.secret, ts, "DELETE", path, b"");
        let (nonce, body) = transport::seal(
            &self.secret,
            &transport::request_aad(&ts.to_string(), "DELETE", path, &target),
            b"",
        )?;
        let resp = self
            .http
            .delete(format!("http://{base}{path}"))
            .header(auth::TS_HEADER, ts.to_string())
            .header(auth::MAC_HEADER, mac)
            .header(transport::ENC_HEADER, transport::VERSION)
            .header(transport::NONCE_HEADER, &nonce)
            .header(transport::TARGET_HEADER, target)
            .body(body)
            .send()
            .await
            .with_context(|| format!("DELETE {base}{path}"))?;
        self.decode_response("DELETE", path, &nonce, resp).await
    }

    async fn decode_response(
        &self,
        method: &str,
        path: &str,
        request_nonce: &str,
        resp: reqwest::Response,
    ) -> Result<Vec<u8>> {
        let status = resp.status();
        let encrypted = resp
            .headers()
            .get(transport::ENC_HEADER)
            .and_then(|v| v.to_str().ok())
            == Some(transport::VERSION);
        let nonce = resp
            .headers()
            .get(transport::NONCE_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut wire = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if wire.len().saturating_add(chunk.len()) > MAX_PEER_RESPONSE {
                bail!("{method} {path} response exceeds 64 MiB");
            }
            wire.extend_from_slice(&chunk);
        }
        if !encrypted {
            bail!("{method} response from peer was not encrypted (status {status})");
        }
        let bytes = transport::open(
            &self.secret,
            &nonce,
            &transport::response_aad(request_nonce, status.as_u16()),
            &wire,
        )?;
        if !status.is_success() {
            return Err(PeerHttpError {
                method: method.to_string(),
                path: path.to_string(),
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            }
            .into());
        }
        Ok(bytes)
    }

    pub async fn sync_manifests(&self, base: &str) -> Result<Vec<Envelope>> {
        let raw = self.get(base, "/v1/sync/manifests").await?;
        decode_envelopes(&raw)
    }

    pub async fn sync_claims(&self, base: &str) -> Result<Vec<Envelope>> {
        let raw = self.get(base, "/v1/sync/claims").await?;
        decode_envelopes(&raw)
    }

    pub async fn kv_digests(&self, base: &str) -> Result<BTreeMap<String, String>> {
        let raw = self.get(base, "/v1/sync/kv").await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn kv_dump(&self, base: &str, ns: &str) -> Result<Vec<(String, KvEntry)>> {
        let raw = self
            .get(base, &format!("/v1/sync/kv/{}", component(ns)))
            .await?;
        Ok(postcard::from_bytes(&raw)?)
    }

    pub async fn fetch_blob(&self, base: &str, sha: &[u8; 32]) -> Result<Vec<u8>> {
        self.get(base, &format!("/v1/blob/{}", hex::encode(sha)))
            .await
    }

    pub async fn put_blob(&self, base: &str, bytes: Vec<u8>) -> Result<String> {
        let resp = self.post(base, "/v1/blob", bytes).await?;
        Ok(String::from_utf8_lossy(&resp).trim().to_string())
    }

    pub async fn post_manifest(&self, base: &str, env: &Envelope) -> Result<()> {
        self.post(base, "/v1/manifest", env.to_bytes()).await?;
        Ok(())
    }

    pub async fn resource_heads(
        &self,
        base: &str,
        kind: Option<&str>,
    ) -> Result<Vec<crate::resource::ResourceView>> {
        let path = kind
            .map(|kind| format!("/v1/resources?kind={}", component(kind)))
            .unwrap_or_else(|| "/v1/resources".to_string());
        let raw = self.get(base, &path).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn resource_head(
        &self,
        base: &str,
        kind: &str,
        name: &str,
    ) -> Result<Option<crate::resource::ResourceView>> {
        let path = format!("/v1/resource/{}/{}", component(kind), component(name));
        match self.get(base, &path).await {
            Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn post_resource(&self, base: &str, envelope: &Envelope) -> Result<()> {
        self.post(base, "/v1/resource", envelope.to_bytes()).await?;
        Ok(())
    }

    pub async fn status(&self, base: &str) -> Result<serde_json::Value> {
        let raw = self.get(base, "/v1/status").await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn storage_status(&self, base: &str) -> Result<serde_json::Value> {
        let raw = self.get(base, "/v1/storage/status").await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn storage_probe(
        &self,
        base: &str,
    ) -> Result<Vec<crate::storage_policy::RemoteProbe>> {
        let raw = self.post(base, "/v1/storage/probe", Vec::new()).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    /// Peer API addresses currently visible from `base`, including `base`.
    pub async fn live_api_candidates(&self, base: &str) -> Result<Vec<String>> {
        let status = self.status(base).await?;
        Ok(peer_api_candidates(base, &status))
    }

    pub async fn authorization(
        &self,
        base: &str,
        code: &str,
    ) -> Result<crate::management::ApprovalView> {
        let raw = self
            .get(base, &format!("/v1/authorize/{}", component(code)))
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn approve_authorization(
        &self,
        base: &str,
        code: &str,
        approval: &crate::management::ApprovalSignature,
    ) -> Result<()> {
        self.post(
            base,
            &format!("/v1/authorize/{}", component(code)),
            serde_json::to_vec(approval)?,
        )
        .await?;
        Ok(())
    }

    pub async fn worker_version(&self, base: &str, name: &str) -> Result<Option<u64>> {
        Ok(self.worker_head(base, name).await?.map(|(v, _)| v))
    }

    /// (version, envelope digest) of a worker's head, for hash-chain
    /// linking on deploy.
    pub async fn worker_head(&self, base: &str, name: &str) -> Result<Option<(u64, [u8; 32])>> {
        match self.get(base, &format!("/v1/worker/{name}")).await {
            Ok(raw) => {
                let v: serde_json::Value = serde_json::from_slice(&raw)?;
                let Some(version) = v.get("version").and_then(|x| x.as_u64()) else {
                    return Ok(None);
                };
                let digest = v
                    .get("digest")
                    .and_then(|x| x.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or_else(|| anyhow::anyhow!("node returned head without digest"))?;
                Ok(Some((version, digest)))
            }
            Err(e)
                if e.downcast_ref::<PeerHttpError>()
                    .map(|e| e.status == 404)
                    .unwrap_or(false) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Full transparency log for a worker.
    pub async fn worker_log(&self, base: &str, name: &str) -> Result<Vec<Envelope>> {
        let raw = self.get(base, &format!("/v1/log/{name}")).await?;
        decode_envelopes(&raw)
    }

    pub async fn worker_request_logs(
        &self,
        base: &str,
        worker: &str,
        hostname: Option<&str>,
        status_class: Option<u16>,
        limit: usize,
    ) -> Result<crate::observability::RequestLogSnapshot> {
        let mut path = format!(
            "/v1/observability/{}/requests?limit={}",
            component(worker),
            limit.clamp(1, 1_000)
        );
        if let Some(hostname) = hostname.filter(|value| !value.is_empty()) {
            path.push_str("&hostname=");
            path.push_str(&component(hostname));
        }
        if let Some(status_class) = status_class {
            path.push_str(&format!("&status={status_class}"));
        }
        let raw = self.get(base, &path).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn worker_runtime_logs(
        &self,
        base: &str,
        worker: &str,
        limit: usize,
    ) -> Result<crate::observability::RuntimeLogSnapshot> {
        let path = format!(
            "/v1/observability/{}/runtime?limit={}",
            component(worker),
            limit.clamp(1, 1_000)
        );
        let raw = self.get(base, &path).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn kv_get(&self, base: &str, ns: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let path = format!("/v1/kv/{}/{}", component(ns), component(key));
        match self.get(base, &path).await {
            Ok(v) => Ok(Some(v)),
            Err(e)
                if e.downcast_ref::<PeerHttpError>()
                    .map(|e| e.status == 404)
                    .unwrap_or(false) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn kv_get_with_metadata(
        &self,
        base: &str,
        ns: &str,
        key: &str,
    ) -> Result<Option<KvValue>> {
        let path = format!(
            "/v1/kv/{}/{}?with_metadata=true",
            component(ns),
            component(key)
        );
        match self.get(base, &path).await {
            Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn kv_put(&self, base: &str, ns: &str, key: &str, value: Vec<u8>) -> Result<()> {
        self.kv_put_with_metadata(base, ns, key, value, None, None)
            .await
    }

    pub async fn kv_put_with_metadata(
        &self,
        base: &str,
        ns: &str,
        key: &str,
        value: Vec<u8>,
        expires_at_ms: Option<u64>,
        metadata: Option<&serde_json::Value>,
    ) -> Result<()> {
        let mut query = Vec::new();
        if let Some(expires_at_ms) = expires_at_ms {
            query.push(format!("expires_at_ms={expires_at_ms}"));
        }
        if let Some(metadata) = metadata {
            let encoded = serde_json::to_string(metadata)?;
            if encoded.len() > 1024 {
                bail!("KV metadata exceeds 1024 bytes");
            }
            query.push(format!("metadata={}", component(&encoded)));
        }
        let suffix = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        self.post(
            base,
            &format!("/v1/kv/{}/{}{}", component(ns), component(key), suffix),
            value,
        )
        .await?;
        Ok(())
    }

    pub async fn kv_delete(&self, base: &str, ns: &str, key: &str) -> Result<()> {
        self.delete(
            base,
            &format!("/v1/kv/{}/{}", component(ns), component(key)),
        )
        .await?;
        Ok(())
    }

    pub async fn kv_list(&self, base: &str, ns: &str, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .kv_list_page(base, ns, prefix, None, 10_000)
            .await?
            .entries
            .into_iter()
            .map(|entry| entry.key)
            .collect())
    }

    pub async fn kv_list_page(
        &self,
        base: &str,
        ns: &str,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<KvListPage> {
        let mut path = format!(
            "/v1/kv/{}?prefix={}&limit={}",
            component(ns),
            component(prefix),
            limit.clamp(1, 1_000)
        );
        if let Some(cursor) = cursor.filter(|cursor| !cursor.is_empty()) {
            path.push_str("&cursor=");
            path.push_str(&component(cursor));
        }
        let raw = self.get(base, &path).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn r2_list(
        &self,
        base: &str,
        bucket: &str,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<crate::r2::ObjectList> {
        let mut path = format!(
            "/v1/r2/{}?prefix={}&limit={}",
            component(bucket),
            component(prefix),
            limit.clamp(1, crate::r2::MAX_LIST_LIMIT)
        );
        if let Some(cursor) = cursor {
            path.push_str("&cursor=");
            path.push_str(&component(cursor));
        }
        let raw = self.get(base, &path).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn r2_head(
        &self,
        base: &str,
        bucket: &str,
        key: &str,
    ) -> Result<Option<crate::r2::ObjectMeta>> {
        let path = format!("/v1/r2/{}/meta/{}", component(bucket), component(key));
        match self.get(base, &path).await {
            Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn r2_get(
        &self,
        base: &str,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(crate::r2::ObjectMeta, Vec<u8>)>> {
        let path = format!("/v1/r2/{}/object/{}", component(bucket), component(key));
        match self.get(base, &path).await {
            Ok(raw) => Ok(Some(crate::r2::decode_get_response(&raw)?)),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn r2_put(
        &self,
        base: &str,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        options: &crate::r2::PutOptions,
    ) -> Result<crate::r2::ObjectMeta> {
        let path = format!("/v1/r2/{}/object/{}", component(bucket), component(key));
        let payload = crate::r2::encode_put_request(options, bytes)?;
        let raw = self.post(base, &path, payload).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn r2_delete(&self, base: &str, bucket: &str, key: &str) -> Result<bool> {
        let path = format!("/v1/r2/{}/object/{}", component(bucket), component(key));
        match self.delete(base, &path).await {
            Ok(_) => Ok(true),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn r2_upload_part(
        &self,
        base: &str,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<crate::r2::UploadedPart> {
        let path = format!(
            "/v1/r2/{}/multipart/{}/part/{}/{}",
            component(bucket),
            component(upload_id),
            part_number,
            component(key)
        );
        let raw = self.post(base, &path, bytes.to_vec()).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn r2_complete_multipart(
        &self,
        base: &str,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[crate::r2::PublishedPart],
    ) -> Result<crate::r2::ObjectMeta> {
        let path = format!(
            "/v1/r2/{}/multipart/{}/complete/{}",
            component(bucket),
            component(upload_id),
            component(key)
        );
        let raw = self.post(base, &path, serde_json::to_vec(parts)?).await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn r2_put_blob(&self, base: &str, bytes: &[u8]) -> Result<[u8; 32]> {
        let raw = self.post(base, "/v1/r2-blob", bytes.to_vec()).await?;
        hex::decode(String::from_utf8(raw)?.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("peer returned an invalid R2 blob digest"))
    }

    pub async fn binary_put_blob(
        &self,
        base: &str,
        bytes: &[u8],
        storage: &crate::objectstore::StorageLocation,
    ) -> Result<(String, u64, crate::objectstore::StorageLocation)> {
        let path = match storage {
            crate::objectstore::StorageLocation::Local => "/v1/binary-blob".to_string(),
            crate::objectstore::StorageLocation::Rclone { remote, prefix } => format!(
                "/v1/binary-blob?remote={}&prefix={}",
                component(remote),
                component(prefix)
            ),
            crate::objectstore::StorageLocation::RcloneShard { .. } => {
                anyhow::bail!("Binary Deliver 不能直接选择 R2 分片策略位置")
            }
        };
        let raw = self.post(base, &path, bytes.to_vec()).await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok((
            response["sha256"]
                .as_str()
                .context("node omitted Binary blob sha256")?
                .to_string(),
            response["size_bytes"]
                .as_u64()
                .context("node omitted Binary blob size")?,
            serde_json::from_value(response["storage"].clone())?,
        ))
    }

    pub async fn r2_fetch_blob(&self, base: &str, sha: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let path = format!("/v1/r2-blob/{}", hex::encode(sha));
        match self.get(base, &path).await {
            Ok(bytes) => {
                if sha2::Sha256::digest(&bytes).as_slice() != sha {
                    bail!("peer returned corrupt R2 object bytes");
                }
                Ok(Some(bytes))
            }
            Err(error) if peer_http_status(&error) == Some(404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn queue_send(
        &self,
        base: &str,
        queue: &str,
        messages: &[crate::queue::SendMessage],
    ) -> Result<Vec<String>> {
        let body = serde_json::to_vec(&serde_json::json!({ "messages": messages }))?;
        let raw = self
            .post(
                base,
                &format!("/v1/queue/{}/messages", component(queue)),
                body,
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(response["message_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|id| id.as_str().map(str::to_string))
            .collect())
    }

    pub async fn queue_stats(&self, base: &str, queue: &str) -> Result<crate::queue::QueueStats> {
        let raw = self
            .get(base, &format!("/v1/queue/{}/stats", component(queue)))
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn queue_dead_letters(
        &self,
        base: &str,
        queue: &str,
        limit: usize,
    ) -> Result<Vec<crate::queue::DeadLetter>> {
        let raw = self
            .get(
                base,
                &format!(
                    "/v1/queue/{}/dead?limit={}",
                    component(queue),
                    limit.clamp(1, 1_000)
                ),
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("dead_letters")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    pub async fn queue_redrive(&self, base: &str, queue: &str, id: &str) -> Result<bool> {
        let path = format!(
            "/v1/queue/{}/dead/{}/redrive",
            component(queue),
            component(id)
        );
        match self.post(base, &path, vec![]).await {
            Ok(_) => Ok(true),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn cron_runs(
        &self,
        base: &str,
        worker: &str,
        dlq: bool,
        limit: usize,
    ) -> Result<Vec<crate::cron_driver::CronRun>> {
        let raw = self
            .get(
                base,
                &format!(
                    "/v1/cron/{}/runs?dlq={}&limit={}",
                    component(worker),
                    dlq,
                    limit.clamp(1, 1_000)
                ),
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("runs")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    pub async fn cron_fire(
        &self,
        base: &str,
        worker: &str,
        expression: Option<&str>,
    ) -> Result<crate::cron_driver::CronRun> {
        let raw = self
            .post(
                base,
                &format!("/v1/cron/{}/fire", component(worker)),
                serde_json::to_vec(&serde_json::json!({ "expression": expression }))?,
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn cron_replay(
        &self,
        base: &str,
        worker: &str,
        id: &str,
    ) -> Result<Option<crate::cron_driver::CronRun>> {
        let path = format!(
            "/v1/cron/{}/runs/{}/replay",
            component(worker),
            component(id)
        );
        match self.post(base, &path, vec![]).await {
            Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn cron_delete_dlq(&self, base: &str, worker: &str, id: &str) -> Result<bool> {
        let path = format!("/v1/cron/{}/runs/{}", component(worker), component(id));
        match self.delete(base, &path).await {
            Ok(_) => Ok(true),
            Err(error) if peer_http_status(&error) == Some(404) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn analytics_write(
        &self,
        base: &str,
        dataset: &str,
        points: &[crate::analytics::DataPoint],
    ) -> Result<usize> {
        let raw = self
            .post(
                base,
                &format!("/v1/analytics/{}/events", component(dataset)),
                serde_json::to_vec(&serde_json::json!({ "points": points }))?,
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(response["written"].as_u64().unwrap_or(0) as usize)
    }

    pub async fn analytics_recent(
        &self,
        base: &str,
        dataset: &str,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<crate::analytics::AnalyticsEvent>> {
        let mut path = format!(
            "/v1/analytics/{}/events?limit={}",
            component(dataset),
            limit.clamp(1, 1_000)
        );
        if let Some(before) = before {
            path.push_str(&format!("&before={before}"));
        }
        let raw = self.get(base, &path).await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("events")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    pub async fn analytics_stats(
        &self,
        base: &str,
        dataset: &str,
    ) -> Result<crate::analytics::DatasetStats> {
        let raw = self
            .get(base, &format!("/v1/analytics/{}/stats", component(dataset)))
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn analytics_group(
        &self,
        base: &str,
        dataset: &str,
        dimension: &str,
        dimension_index: usize,
        double_index: Option<usize>,
        since: u64,
        limit: usize,
    ) -> Result<Vec<crate::analytics::DimensionGroup>> {
        let mut path = format!(
            "/v1/analytics/{}/group?dimension={}&dimension_index={}&since={}&limit={}",
            component(dataset),
            component(dimension),
            dimension_index,
            since,
            limit.clamp(1, 100)
        );
        if let Some(index) = double_index {
            path.push_str(&format!("&double_index={index}"));
        }
        let raw = self.get(base, &path).await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("groups")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    pub async fn pipeline_ingest(
        &self,
        base: &str,
        pipeline: &str,
        events: &[serde_json::Value],
    ) -> Result<usize> {
        let raw = self
            .post(
                base,
                &format!("/v1/pipeline/{}/events", component(pipeline)),
                serde_json::to_vec(&serde_json::json!({ "events": events }))?,
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(response["accepted"].as_u64().unwrap_or(0) as usize)
    }

    pub async fn pipeline_status(
        &self,
        base: &str,
        pipeline: &str,
    ) -> Result<crate::pipeline::PipelineStatus> {
        let raw = self
            .get(
                base,
                &format!("/v1/pipeline/{}/status", component(pipeline)),
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn pipeline_batches(
        &self,
        base: &str,
        pipeline: &str,
        limit: usize,
    ) -> Result<Vec<crate::pipeline::PipelineBatch>> {
        let raw = self
            .get(
                base,
                &format!(
                    "/v1/pipeline/{}/batches?limit={}",
                    component(pipeline),
                    limit.clamp(1, 1_000)
                ),
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("batches")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    pub async fn pipeline_flush(
        &self,
        base: &str,
        pipeline: &str,
    ) -> Result<Option<crate::pipeline::PipelineBatch>> {
        let raw = self
            .post(
                base,
                &format!("/v1/pipeline/{}/flush", component(pipeline)),
                vec![],
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("batch")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )?)
    }

    pub async fn workflow_create(
        &self,
        base: &str,
        workflow: &str,
        instance_key: Option<&str>,
        input: serde_json::Value,
    ) -> Result<crate::workflow::WorkflowInstance> {
        let raw = self
            .post(
                base,
                &format!("/v1/workflow/{}/instances", component(workflow)),
                serde_json::to_vec(&serde_json::json!({
                    "instance_key": instance_key,
                    "input": input,
                }))?,
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn workflow_instances(
        &self,
        base: &str,
        workflow: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::workflow::WorkflowInstance>> {
        let mut path = format!(
            "/v1/workflow/{}/instances?limit={}",
            component(workflow),
            limit.clamp(1, 1_000)
        );
        if let Some(status) = status {
            path.push_str("&status=");
            path.push_str(&component(status));
        }
        let raw = self.get(base, &path).await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("instances")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    pub async fn workflow_instance(
        &self,
        base: &str,
        workflow: &str,
        id: &str,
    ) -> Result<serde_json::Value> {
        let raw = self
            .get(
                base,
                &format!(
                    "/v1/workflow/{}/instances/{}",
                    component(workflow),
                    component(id)
                ),
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn workflow_signal(
        &self,
        base: &str,
        workflow: &str,
        id: &str,
        name: &str,
        payload: serde_json::Value,
    ) -> Result<String> {
        let raw = self
            .post(
                base,
                &format!(
                    "/v1/workflow/{}/instances/{}/signal",
                    component(workflow),
                    component(id)
                ),
                serde_json::to_vec(&serde_json::json!({ "name": name, "payload": payload }))?,
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        response["signal_id"]
            .as_str()
            .map(str::to_string)
            .context("Workflow 信号响应缺少 signal_id")
    }

    pub async fn workflow_action(
        &self,
        base: &str,
        workflow: &str,
        id: &str,
        action: &str,
    ) -> Result<()> {
        if !matches!(action, "pause" | "resume" | "terminate" | "restart") {
            anyhow::bail!("Workflow 操作无效");
        }
        self.post(
            base,
            &format!(
                "/v1/workflow/{}/instances/{}/{}",
                component(workflow),
                component(id),
                action
            ),
            vec![],
        )
        .await?;
        Ok(())
    }

    pub async fn workflow_stats(
        &self,
        base: &str,
        workflow: &str,
    ) -> Result<crate::workflow::WorkflowStats> {
        let raw = self
            .get(base, &format!("/v1/workflow/{}/stats", component(workflow)))
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn flow_create(
        &self,
        base: &str,
        flow: &str,
        run_key: Option<&str>,
        input: serde_json::Value,
    ) -> Result<crate::flow::FlowRun> {
        let raw = self
            .post(
                base,
                &format!("/v1/flow/{}/runs", component(flow)),
                serde_json::to_vec(&serde_json::json!({
                    "run_key": run_key,
                    "input": input,
                }))?,
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn flow_runs(
        &self,
        base: &str,
        flow: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::flow::FlowRun>> {
        let mut path = format!(
            "/v1/flow/{}/runs?limit={}",
            component(flow),
            limit.clamp(1, 1_000)
        );
        if let Some(status) = status {
            path.push_str("&status=");
            path.push_str(&component(status));
        }
        Ok(serde_json::from_slice(&self.get(base, &path).await?)?)
    }

    pub async fn flow_run(&self, base: &str, flow: &str, id: &str) -> Result<serde_json::Value> {
        let raw = self
            .get(
                base,
                &format!("/v1/flow/{}/runs/{}", component(flow), component(id)),
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn flow_action(
        &self,
        base: &str,
        flow: &str,
        id: &str,
        action: &str,
    ) -> Result<serde_json::Value> {
        if !matches!(action, "cancel" | "retry") {
            anyhow::bail!("Flow 操作无效");
        }
        let raw = self
            .post(
                base,
                &format!(
                    "/v1/flow/{}/runs/{}/{}",
                    component(flow),
                    component(id),
                    action
                ),
                vec![],
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn flow_stats(&self, base: &str, flow: &str) -> Result<crate::flow::FlowStats> {
        let raw = self
            .get(base, &format!("/v1/flow/{}/stats", component(flow)))
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn email_verification(
        &self,
        base: &str,
        domain: &str,
    ) -> Result<Option<crate::email::EmailVerification>> {
        let raw = self
            .get(
                base,
                &format!("/v1/email/{}/verification", component(domain)),
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        serde_json::from_value(response.get("verification").cloned().unwrap_or_default())
            .context("邮件域验证状态响应无效")
    }

    pub async fn email_verify(
        &self,
        base: &str,
        domain: &str,
    ) -> Result<crate::email::EmailVerification> {
        let raw = self
            .post(
                base,
                &format!("/v1/email/{}/verification", component(domain)),
                vec![],
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn email_messages(
        &self,
        base: &str,
        domain: &str,
        limit: usize,
    ) -> Result<Vec<crate::email::EmailMessage>> {
        let raw = self
            .get(
                base,
                &format!(
                    "/v1/email/{}/messages?limit={}",
                    component(domain),
                    limit.clamp(1, 500)
                ),
            )
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(
            response
                .get("messages")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    pub async fn email_message(
        &self,
        base: &str,
        domain: &str,
        id: &str,
    ) -> Result<crate::email::EmailMessage> {
        let raw = self
            .get(
                base,
                &format!("/v1/email/{}/messages/{}", component(domain), component(id)),
            )
            .await?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub async fn email_message_raw(&self, base: &str, domain: &str, id: &str) -> Result<Vec<u8>> {
        self.get(
            base,
            &format!(
                "/v1/email/{}/messages/{}/raw",
                component(domain),
                component(id)
            ),
        )
        .await
    }

    pub async fn email_send(
        &self,
        base: &str,
        domain: &str,
        metadata: &crate::email::EmailSendMetadata,
        raw: &[u8],
    ) -> Result<Vec<crate::email::QueuedMessage>> {
        let body = crate::email::encode_send_request(metadata, raw)?;
        let response = self
            .post(base, &format!("/v1/email/{}/send", component(domain)), body)
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&response)?;
        Ok(serde_json::from_value(
            response
                .get("queued")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )?)
    }

    /// Execute SQL against a D1 database, following leader hints
    /// (bounded) — callers can point at ANY cluster node.
    pub async fn d1_exec(
        &self,
        base: &str,
        db: &str,
        sql: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({ "sql": sql, "params": params })
            .to_string()
            .into_bytes();
        self.d1_request(base, db, body).await
    }

    pub async fn d1_batch(
        &self,
        base: &str,
        db: &str,
        statements: &[crate::d1::Statement],
    ) -> Result<serde_json::Value> {
        if statements.is_empty() || statements.len() > 100 {
            bail!("D1 atomic batch accepts 1..100 statements");
        }
        let body = serde_json::to_vec(&serde_json::json!({ "statements": statements }))?;
        self.d1_request(base, db, body).await
    }

    pub async fn d1_export(&self, base: &str, db: &str) -> Result<Vec<u8>> {
        let mut target = base.to_string();
        let mut candidates = vec![target.clone()];
        let mut candidate_cursor = 0usize;
        let mut candidates_loaded = false;
        for _ in 0..25 {
            match self
                .get(&target, &format!("/v1/d1/{}/export", component(db)))
                .await
            {
                Ok(raw) => return Ok(raw),
                Err(error) => {
                    if let Some(http_error) = error.downcast_ref::<PeerHttpError>() {
                        if http_error.status == 421 {
                            if let Ok(value) =
                                serde_json::from_str::<serde_json::Value>(&http_error.body)
                            {
                                if let Some(hint) = value["leader_hint"]
                                    .as_str()
                                    .filter(|hint| !hint.is_empty())
                                {
                                    target = hint.to_string();
                                    tokio::time::sleep(Duration::from_millis(300)).await;
                                    continue;
                                }
                            }
                        }
                        if http_error.status != 404 && http_error.status != 421 {
                            return Err(error);
                        }
                    } else {
                        return Err(error);
                    }
                    if !candidates_loaded {
                        if let Ok(status) = self.status(base).await {
                            candidates = peer_api_candidates(base, &status);
                        }
                        candidates_loaded = true;
                    }
                    candidate_cursor = (candidate_cursor + 1) % candidates.len();
                    target = candidates[candidate_cursor].clone();
                    tokio::time::sleep(Duration::from_millis(700)).await;
                }
            }
        }
        bail!("no leader found for D1 export {db} after retries")
    }

    async fn d1_request(&self, base: &str, db: &str, body: Vec<u8>) -> Result<serde_json::Value> {
        let mut target = base.to_string();
        let mut candidates = vec![target.clone()];
        let mut candidate_cursor = 0usize;
        let mut candidates_loaded = false;
        for _ in 0..25 {
            match self
                .post(&target, &format!("/v1/d1/{db}/exec"), body.clone())
                .await
            {
                Ok(raw) => return Ok(serde_json::from_slice(&raw)?),
                Err(e) => {
                    if let Some(http_error) = e.downcast_ref::<PeerHttpError>() {
                        // 421 responses carry a structured leader hint.
                        if http_error.status == 421 {
                            if let Ok(value) =
                                serde_json::from_str::<serde_json::Value>(&http_error.body)
                            {
                                if let Some(hint) =
                                    value["leader_hint"].as_str().filter(|h| !h.is_empty())
                                {
                                    target = hint.to_string();
                                    candidate_cursor = match candidates
                                        .iter()
                                        .position(|candidate| candidate == &target)
                                    {
                                        Some(position) => position,
                                        None => {
                                            candidates.push(target.clone());
                                            candidates.len() - 1
                                        }
                                    };
                                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                                    continue;
                                }
                            }
                            // Election in progress and no useful hint:
                            // probe another known node below.
                        }
                        if http_error.status != 404 && http_error.status != 421 {
                            return Err(e);
                        }
                    } else {
                        // A hinted-at node may just have died. Only
                        // retry connection failures; application errors
                        // must not replay a possibly mutating statement.
                        let cause = format!("{e:#}");
                        if !cause.contains("tcp connect error")
                            && !cause.contains("error sending request")
                        {
                            return Err(e);
                        }
                    }

                    // A 404 means this node has not learned the
                    // database catalog yet. Discover its encrypted
                    // membership view once and rotate candidates,
                    // rather than retrying the same stale node 25 times.
                    if !candidates_loaded {
                        if let Ok(status) = self.status(base).await {
                            candidates = peer_api_candidates(base, &status);
                        }
                        candidates_loaded = true;
                    }
                    candidate_cursor = (candidate_cursor + 1) % candidates.len();
                    target = candidates[candidate_cursor].clone();
                    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                }
            }
        }
        anyhow::bail!("no leader found for {db} after retries")
    }
}

fn peer_http_status(error: &anyhow::Error) -> Option<u16> {
    error
        .downcast_ref::<PeerHttpError>()
        .map(|error| error.status)
}

pub fn encode_envelopes(envs: &[Envelope]) -> Vec<u8> {
    let raw: Vec<Vec<u8>> = envs.iter().map(|e| e.to_bytes()).collect();
    postcard::to_stdvec(&raw).expect("postcard encode")
}

pub fn decode_envelopes(bytes: &[u8]) -> Result<Vec<Envelope>> {
    let raw: Vec<Vec<u8>> = postcard::from_bytes(bytes).context("envelope list decode")?;
    raw.iter().map(|b| Ok(Envelope::from_bytes(b)?)).collect()
}

#[cfg(test)]
mod tests {
    use super::peer_api_candidates;

    #[test]
    fn d1_fallback_candidates_are_deduplicated() {
        let status = serde_json::json!({
            "peers": [
                {"api": "127.0.0.1:7383"},
                {"api": "127.0.0.1:7382"},
                {"api": null}
            ]
        });
        assert_eq!(
            peer_api_candidates("127.0.0.1:7382", &status),
            vec!["127.0.0.1:7382", "127.0.0.1:7383"]
        );
    }
}
