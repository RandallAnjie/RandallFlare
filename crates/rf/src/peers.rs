//! HTTP client for the peer API — used by gossip-driven anti-entropy
//! (manifest/claim/KV sync, blob fetch) and by the CLI (deploy, kv,
//! status). All requests carry the cluster-secret HMAC.

use crate::auth;
use anyhow::{bail, Context, Result};
use rf_core::envelope::Envelope;
use rf_core::kv::KvEntry;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone)]
pub struct PeerClient {
    http: reqwest::Client,
    secret: [u8; 32],
}

impl PeerClient {
    pub fn new(secret: [u8; 32]) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        Self { http, secret }
    }

    async fn get(&self, base: &str, path: &str) -> Result<Vec<u8>> {
        let ts = crate::node::now_ms();
        let mac = auth::mac_hex(&self.secret, ts, "GET", path, b"");
        let resp = self
            .http
            .get(format!("http://{base}{path}"))
            .header(auth::TS_HEADER, ts.to_string())
            .header(auth::MAC_HEADER, mac)
            .send()
            .await
            .with_context(|| format!("GET {base}{path}"))?;
        if !resp.status().is_success() {
            bail!("GET {base}{path} → {}", resp.status());
        }
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn post(&self, base: &str, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let ts = crate::node::now_ms();
        let mac = auth::mac_hex(&self.secret, ts, "POST", path, &body);
        let resp = self
            .http
            .post(format!("http://{base}{path}"))
            .header(auth::TS_HEADER, ts.to_string())
            .header(auth::MAC_HEADER, mac)
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {base}{path}"))?;
        let status = resp.status();
        let bytes = resp.bytes().await?.to_vec();
        if !status.is_success() {
            bail!("POST {base}{path} → {status}: {}", String::from_utf8_lossy(&bytes));
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
        let raw = self.get(base, &format!("/v1/sync/kv/{ns}")).await?;
        Ok(postcard::from_bytes(&raw)?)
    }

    pub async fn fetch_blob(&self, base: &str, sha: &[u8; 32]) -> Result<Vec<u8>> {
        self.get(base, &format!("/v1/blob/{}", hex::encode(sha))).await
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
    pub async fn worker_head(
        &self,
        base: &str,
        name: &str,
    ) -> Result<Option<(u64, [u8; 32])>> {
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
            Err(_) => Ok(None),
        }
    }

    /// Full transparency log for a worker.
    pub async fn worker_log(&self, base: &str, name: &str) -> Result<Vec<Envelope>> {
        let raw = self.get(base, &format!("/v1/log/{name}")).await?;
        decode_envelopes(&raw)
    }

    pub async fn kv_get(&self, base: &str, ns: &str, key: &str) -> Result<Option<Vec<u8>>> {
        match self.get(base, &format!("/v1/kv/{ns}/{key}")).await {
            Ok(v) => Ok(Some(v)),
            Err(_) => Ok(None),
        }
    }

    pub async fn kv_put(&self, base: &str, ns: &str, key: &str, value: Vec<u8>) -> Result<()> {
        self.post(base, &format!("/v1/kv/{ns}/{key}"), value).await?;
        Ok(())
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
        let body =
            serde_json::json!({ "sql": sql, "params": params }).to_string().into_bytes();
        let mut target = base.to_string();
        for _ in 0..20 {
            match self.post(&target, &format!("/v1/d1/{db}/exec"), body.clone()).await {
                Ok(raw) => return Ok(serde_json::from_slice(&raw)?),
                Err(e) => {
                    // 421 responses carry a leader hint to retry.
                    let text = e.to_string();
                    if let Some(idx) = text.find("leader_hint") {
                        if let Some(hint) = text[idx..]
                            .split('"')
                            .nth(2)
                            .filter(|h| !h.is_empty() && *h != "null")
                        {
                            target = hint.to_string();
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                            continue;
                        }
                    }
                    // No hint (election in progress) — brief retry.
                    if text.contains("421") || text.contains("Misdirected") {
                        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                        continue;
                    }
                    // A hinted-at node may not have synced the db's
                    // existence yet, or the hint may point at a node
                    // that just died (stale leader) — back to the
                    // original target and let the election finish.
                    let cause = format!("{e:#}");
                    if text.contains("no such database")
                        || cause.contains("tcp connect error")
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
