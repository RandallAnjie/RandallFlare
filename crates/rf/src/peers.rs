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
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_PEER_RESPONSE: usize = 64 * 1024 * 1024 + 16;

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

    pub async fn status(&self, base: &str) -> Result<serde_json::Value> {
        let raw = self.get(base, "/v1/status").await?;
        Ok(serde_json::from_slice(&raw)?)
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

    pub async fn kv_put(&self, base: &str, ns: &str, key: &str, value: Vec<u8>) -> Result<()> {
        self.post(
            base,
            &format!("/v1/kv/{}/{}", component(ns), component(key)),
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
        let path = format!("/v1/kv/{}?prefix={}", component(ns), component(prefix));
        let raw = self.get(base, &path).await?;
        let response: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(response["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|key| key.as_str().map(str::to_string))
            .collect())
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
        let mut target = base.to_string();
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
                                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                                    continue;
                                }
                            }
                            // Election in progress and no useful hint.
                            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                            continue;
                        }
                        // A hinted node may not have learned the DB's
                        // membership record yet.
                        if http_error.status == 404 {
                            target = base.to_string();
                            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                            continue;
                        }
                    }
                    // A hinted-at node may not have synced the db's
                    // existence yet, or may just have died.
                    let cause = format!("{e:#}");
                    if cause.contains("tcp connect error")
                        || cause.contains("error sending request")
                    {
                        target = base.to_string();
                        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        anyhow::bail!("no leader found for {db} after retries")
    }
}

pub fn encode_envelopes(envs: &[Envelope]) -> Vec<u8> {
    let raw: Vec<Vec<u8>> = envs.iter().map(|e| e.to_bytes()).collect();
    postcard::to_stdvec(&raw).expect("postcard encode")
}

pub fn decode_envelopes(bytes: &[u8]) -> Result<Vec<Envelope>> {
    let raw: Vec<Vec<u8>> = postcard::from_bytes(bytes).context("envelope list decode")?;
    raw.iter().map(|b| Ok(Envelope::from_bytes(b)?)).collect()
}
