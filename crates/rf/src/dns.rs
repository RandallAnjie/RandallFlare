//! DNS reconciliation as a claimed task (抢单版 reconciler).
//!
//! Two mechanisms, both idempotent:
//!
//! 1. Self-registration: every public node directly ensures its own
//!    A record each tick. No claim needed — duplicate ensures are
//!    no-ops, and a node is the authority on its own liveness.
//! 2. The standing "dns/reconcile" task: whichever node holds the
//!    lease diffs the zone's A records for the rotation hostname
//!    against the gossip-live set of public node IPs and removes
//!    strays (dead nodes' records). Lease TTL + renewal: the holder
//!    dying just lets someone else claim it.
//!
//! Partition guard: a node that sees zero live public peers does not
//! delete anything — it is at least as likely to be the isolated one.
//! Its own record stays fresh via mechanism 1 regardless.

use crate::config::DnsConfig;
use crate::node::Node;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

const RECONCILE_TASK: &str = "dns/reconcile";
const LEASE_TTL_MS: u64 = 120_000;

#[derive(Clone)]
pub struct DnsApi {
    http: reqwest::Client,
    base: String,
    token: String,
    zone_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARecord {
    pub id: String,
    pub content: String, // the IP
}

impl DnsApi {
    pub fn new(base: String, token: String, zone_name: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("reqwest client");
        Self { http, base, token, zone_name }
    }

    pub fn cloudflare(token: String, zone_name: String) -> Self {
        Self::new("https://api.cloudflare.com/client/v4".into(), token, zone_name)
    }

    async fn zone_id(&self) -> Result<String> {
        let v: serde_json::Value = self
            .http
            .get(format!("{}/zones?name={}", self.base, self.zone_name))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        v["result"][0]["id"]
            .as_str()
            .map(|s| s.to_string())
            .context("zone not found")
    }

    pub async fn list_a_records(&self, hostname: &str) -> Result<Vec<ARecord>> {
        let zone = self.zone_id().await?;
        let v: serde_json::Value = self
            .http
            .get(format!(
                "{}/zones/{zone}/dns_records?type=A&name={hostname}&per_page=100",
                self.base
            ))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut out = Vec::new();
        if let Some(items) = v["result"].as_array() {
            for r in items {
                if let (Some(id), Some(content)) = (r["id"].as_str(), r["content"].as_str()) {
                    out.push(ARecord { id: id.into(), content: content.into() });
                }
            }
        }
        Ok(out)
    }

    pub async fn create_a_record(&self, hostname: &str, ip: &str) -> Result<()> {
        let zone = self.zone_id().await?;
        self.http
            .post(format!("{}/zones/{zone}/dns_records", self.base))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "type": "A",
                "name": hostname,
                "content": ip,
                "ttl": 60,
                "proxied": false,
            }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn delete_record(&self, id: &str) -> Result<()> {
        let zone = self.zone_id().await?;
        self.http
            .delete(format!("{}/zones/{zone}/dns_records/{id}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// Pure diff logic, unit-testable: which record ids to delete, and
/// whether our own ip needs creating.
pub fn plan(
    records: &[ARecord],
    my_ip: Option<&str>,
    live_public_ips: &BTreeSet<String>,
    i_see_peers: bool,
) -> (Vec<String>, bool) {
    let mut desired: BTreeSet<&str> = live_public_ips.iter().map(|s| s.as_str()).collect();
    if let Some(ip) = my_ip {
        desired.insert(ip);
    }
    let deletions = if i_see_peers {
        records
            .iter()
            .filter(|r| !desired.contains(r.content.as_str()))
            .map(|r| r.id.clone())
            .collect()
    } else {
        Vec::new() // partition guard
    };
    let need_create = match my_ip {
        Some(ip) => !records.iter().any(|r| r.content == ip),
        None => false,
    };
    (deletions, need_create)
}

pub fn spawn(node: Arc<Node>, api: DnsApi, cfg: DnsConfig) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if let Err(e) = tick(&node, &api, &cfg).await {
                tracing::warn!("dns tick: {e:#}");
            }
        }
    });
}

async fn tick(node: &Arc<Node>, api: &DnsApi, cfg: &DnsConfig) -> Result<()> {
    let my_ip = if node.cfg.public { cfg.my_ipv4.clone() } else { None };

    // Mechanism 2: hold (or try to grab) the reconcile lease.
    let holding = if node.holds(RECONCILE_TASK) {
        node.claim_renew(RECONCILE_TASK, false)?;
        true
    } else if node.claim_try(RECONCILE_TASK, LEASE_TTL_MS)? {
        // Wait out a gossip settle window before acting on the lease.
        tokio::time::sleep(Duration::from_millis(
            (node.cfg.gossip.interval_ms * 2).clamp(500, 5000),
        ))
        .await;
        node.holds(RECONCILE_TASK)
    } else {
        false
    };

    let peers = node.peers();
    let live_public_ips: BTreeSet<String> =
        peers.values().filter(|p| p.public).filter_map(|p| p.ipv4.clone()).collect();
    let i_see_peers = !live_public_ips.is_empty();

    let records = api.list_a_records(&cfg.hostname).await?;
    let (deletions, need_create) =
        plan(&records, my_ip.as_deref(), &live_public_ips, i_see_peers);

    // Mechanism 1: my own record, no claim needed.
    if need_create {
        if let Some(ip) = &my_ip {
            api.create_a_record(&cfg.hostname, ip).await?;
            tracing::info!("dns: created A {} → {ip}", cfg.hostname);
        }
    }

    // Stray removal only under the lease.
    if holding {
        for id in deletions {
            api.delete_record(&id).await?;
            tracing::info!("dns: removed stray record {id}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{delete as axum_delete, get};
    use std::sync::Mutex;

    fn rec(id: &str, ip: &str) -> ARecord {
        ARecord { id: id.into(), content: ip.into() }
    }

    /// Minimal in-memory Cloudflare API double.
    async fn mock_cf() -> (String, Arc<Mutex<Vec<ARecord>>>) {
        let records: Arc<Mutex<Vec<ARecord>>> = Arc::new(Mutex::new(vec![]));
        let r1 = records.clone();
        let r2 = records.clone();
        let r3 = records.clone();
        let app = axum::Router::new()
            .route(
                "/zones",
                get(|| async {
                    axum::Json(serde_json::json!({"result": [{"id": "z1"}]}))
                }),
            )
            .route(
                "/zones/z1/dns_records",
                get(move || {
                    let r = r1.clone();
                    async move {
                        let items: Vec<_> = r
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|x| serde_json::json!({"id": x.id, "content": x.content}))
                            .collect();
                        axum::Json(serde_json::json!({"result": items}))
                    }
                })
                .post(move |axum::Json(v): axum::Json<serde_json::Value>| {
                    let r = r2.clone();
                    async move {
                        let mut g = r.lock().unwrap();
                        let id = format!("r{}", g.len() + 1);
                        g.push(ARecord {
                            id,
                            content: v["content"].as_str().unwrap().to_string(),
                        });
                        axum::Json(serde_json::json!({"result": {}}))
                    }
                }),
            )
            .route(
                "/zones/z1/dns_records/{id}",
                axum_delete(move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let r = r3.clone();
                    async move {
                        r.lock().unwrap().retain(|x| x.id != id);
                        axum::Json(serde_json::json!({"result": {}}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), records)
    }

    #[tokio::test]
    async fn dns_api_roundtrip_against_mock() {
        let (base, records) = mock_cf().await;
        let api = DnsApi::new(base, "tok".into(), "example.com".into());
        api.create_a_record("edge.example.com", "10.0.0.1").await.unwrap();
        api.create_a_record("edge.example.com", "10.0.0.2").await.unwrap();
        let listed = api.list_a_records("edge.example.com").await.unwrap();
        assert_eq!(listed.len(), 2);
        let stray = listed.iter().find(|r| r.content == "10.0.0.2").unwrap();
        api.delete_record(&stray.id).await.unwrap();
        assert_eq!(records.lock().unwrap().len(), 1);
        assert_eq!(records.lock().unwrap()[0].content, "10.0.0.1");
    }

    #[test]
    fn creates_own_ip_when_missing() {
        let (del, create) =
            plan(&[rec("1", "10.0.0.1")], Some("10.0.0.2"), &BTreeSet::new(), false);
        assert!(create);
        assert!(del.is_empty()); // partition guard: no peers seen
    }

    #[test]
    fn removes_dead_ip_when_peers_visible() {
        let live: BTreeSet<String> = ["10.0.0.3".to_string()].into();
        let (del, create) = plan(
            &[rec("1", "10.0.0.1"), rec("2", "10.0.0.2"), rec("3", "10.0.0.3")],
            Some("10.0.0.1"),
            &live,
            true,
        );
        assert_eq!(del, vec!["2".to_string()]);
        assert!(!create);
    }

    #[test]
    fn partition_guard_blocks_deletions() {
        let (del, _) = plan(
            &[rec("1", "10.0.0.1"), rec("2", "10.0.0.9")],
            Some("10.0.0.1"),
            &BTreeSet::new(),
            false,
        );
        assert!(del.is_empty());
    }

    #[test]
    fn inner_node_never_creates() {
        let (_, create) = plan(&[], None, &BTreeSet::new(), false);
        assert!(!create);
    }
}
