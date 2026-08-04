//! Gossip: chitchat (SWIM-style scuttlebutt) carries membership plus a
//! small per-node key-value surface. We publish:
//!
//!   rf:api          peer API advertise address
//!   rf:public       "1" if this node terminates ingress / joins DNS
//!   rf:label        human label
//!   rf:ip4          public IPv4 (for DNS records)
//!   rf:mdig         manifest-set digest (hex)
//!   rf:kdig:<ns>    KV namespace digest (hex)
//!   rf:claim:<task> base64 claim envelope (our own live claims)
//!   rf:deploy:<worker> compact JSON local deployment/runtime state
//!
//! Digest mismatch against a peer triggers an HTTP anti-entropy pull;
//! claim keys are ingested directly off the gossip state. Claims and
//! manifests are self-authenticating (signed). The UDP transport is
//! additionally encrypted and authenticated with the cluster PSK.

use crate::node::{Node, NodeEvent, PeerView};
use crate::peers::PeerClient;
use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use chitchat::transport::{Socket, Transport};
use chitchat::{spawn_chitchat, ChitchatConfig, ChitchatHandle, ChitchatId, FailureDetectorConfig};
use chitchat::{ChitchatMessage, Deserializable, Serializable};
use rf_core::envelope::Envelope;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

pub const K_API: &str = "rf:api";
pub const K_PUBLIC: &str = "rf:public";
pub const K_LABEL: &str = "rf:label";
pub const K_IP4: &str = "rf:ip4";
pub const K_MDIG: &str = "rf:mdig";
pub const K_KDIG_PREFIX: &str = "rf:kdig:";
pub const K_CLAIM_PREFIX: &str = "rf:claim:";
pub const K_DEPLOY_PREFIX: &str = "rf:deploy:";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub struct Gossip {
    pub handle: ChitchatHandle,
}

const GOSSIP_MAGIC: &[u8; 4] = b"RFG1";
const GOSSIP_AAD: &[u8] = b"randallflare/gossip/xchacha20poly1305/v1";

struct EncryptedUdpTransport {
    secret: [u8; 32],
}

struct EncryptedUdpSocket {
    secret: [u8; 32],
    socket: tokio::net::UdpSocket,
    recv: Vec<u8>,
}

#[async_trait]
impl Transport for EncryptedUdpTransport {
    async fn open(&self, listen: std::net::SocketAddr) -> Result<Box<dyn Socket>> {
        let socket = tokio::net::UdpSocket::bind(listen).await?;
        Ok(Box::new(EncryptedUdpSocket {
            secret: self.secret,
            socket,
            recv: vec![0u8; 65_507],
        }))
    }
}

#[async_trait]
impl Socket for EncryptedUdpSocket {
    async fn send(&mut self, to: std::net::SocketAddr, message: ChitchatMessage) -> Result<()> {
        let mut plaintext = Vec::new();
        message.serialize(&mut plaintext);
        let nonce: [u8; 24] = rand::random();
        let ciphertext = crate::transport::seal_raw(&self.secret, &nonce, GOSSIP_AAD, &plaintext)?;
        let mut packet = Vec::with_capacity(4 + 24 + ciphertext.len());
        packet.extend_from_slice(GOSSIP_MAGIC);
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);
        if packet.len() > 65_507 {
            anyhow::bail!("encrypted gossip datagram exceeds UDP maximum");
        }
        self.socket.send_to(&packet, to).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<(std::net::SocketAddr, ChitchatMessage)> {
        loop {
            let (len, from) = self.socket.recv_from(&mut self.recv).await?;
            if len < 4 + 24 + 16 || &self.recv[..4] != GOSSIP_MAGIC {
                continue;
            }
            let nonce: [u8; 24] = self.recv[4..28].try_into().expect("checked length");
            let Ok(plaintext) =
                crate::transport::open_raw(&self.secret, &nonce, GOSSIP_AAD, &self.recv[28..len])
            else {
                continue;
            };
            let mut slice = plaintext.as_slice();
            if let Ok(message) = ChitchatMessage::deserialize(&mut slice) {
                if slice.is_empty() {
                    return Ok((from, message));
                }
            }
        }
    }
}

pub async fn start(node: Arc<Node>) -> Result<Gossip> {
    let generation = crate::node::now_ms() / 1000;
    let chitchat_id = ChitchatId::new(node.id_hex(), generation, node.cfg.gossip_advertise());
    let mut initial: Vec<(String, String)> = vec![
        (K_API.into(), node.cfg.peer_api_advertise().to_string()),
        (
            K_PUBLIC.into(),
            if node.cfg.public { "1" } else { "0" }.into(),
        ),
        (K_LABEL.into(), node.cfg.label.clone()),
        (K_MDIG.into(), node.manifest_digest_hex()),
    ];
    if let Some(dns) = &node.cfg.dns {
        if let Some(ip) = &dns.my_ipv4 {
            initial.push((K_IP4.into(), ip.clone()));
        }
    }
    for (ns, dig) in node.kv_digests() {
        initial.push((format!("{K_KDIG_PREFIX}{ns}"), dig));
    }
    for (task, env) in node.own_claim_envelopes() {
        initial.push((
            format!("{K_CLAIM_PREFIX}{task}"),
            b64().encode(env.to_bytes()),
        ));
    }
    for (worker, status) in node.deployment_statuses() {
        initial.push((
            format!("{K_DEPLOY_PREFIX}{worker}"),
            serde_json::to_string(&status)?,
        ));
    }

    let config = ChitchatConfig {
        chitchat_id,
        cluster_id: node.cfg.cluster_id.clone(),
        gossip_interval: Duration::from_millis(node.cfg.gossip.interval_ms),
        listen_addr: node.cfg.gossip.listen,
        seed_nodes: node.cfg.gossip.seeds.clone(),
        failure_detector_config: FailureDetectorConfig::default(),
        marked_for_deletion_grace_period: Duration::from_secs(3600),
        catchup_callback: None,
        extra_liveness_predicate: None,
    };
    let transport = EncryptedUdpTransport {
        secret: node.cfg.cluster_secret_bytes()?,
    };
    let handle = spawn_chitchat(config, initial, &transport).await?;

    tokio::spawn(publisher(node.clone(), handle.chitchat()));
    tokio::spawn(observer(node, handle.chitchat()));
    Ok(Gossip { handle })
}

/// Push local state changes into our chitchat node state.
async fn publisher(node: Arc<Node>, chitchat: Arc<tokio::sync::Mutex<chitchat::Chitchat>>) {
    let mut rx = node.subscribe();
    loop {
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => return,
        };
        // Debounce bursts (deploys touch manifests+claims together).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut cc = chitchat.lock().await;
        let state = cc.self_node_state();
        let publish_deployments = matches!(&ev, NodeEvent::Manifests | NodeEvent::Runtime);
        match ev {
            NodeEvent::Manifests => {
                state.set(K_MDIG, node.manifest_digest_hex());
            }
            NodeEvent::Kv(ns) => {
                if let Some(dig) = node.kv_digests().get(&ns) {
                    state.set(format!("{K_KDIG_PREFIX}{ns}"), dig.clone());
                }
            }
            NodeEvent::OwnClaims => {
                let own: BTreeMap<String, String> = node
                    .own_claim_envelopes()
                    .into_iter()
                    .map(|(task, env)| {
                        (
                            format!("{K_CLAIM_PREFIX}{task}"),
                            b64().encode(env.to_bytes()),
                        )
                    })
                    .collect();
                let stale: Vec<String> = state
                    .iter_prefix(K_CLAIM_PREFIX)
                    .filter(|(k, _)| !own.contains_key(*k))
                    .map(|(k, _)| k.to_string())
                    .collect();
                for k in stale {
                    state.delete(&k);
                }
                for (k, v) in own {
                    if state.get(&k) != Some(v.as_str()) {
                        state.set(k, v);
                    }
                }
            }
            NodeEvent::Runtime => {}
        }
        if publish_deployments {
            let deployments: BTreeMap<String, String> = node
                .deployment_statuses()
                .into_iter()
                .filter_map(|(worker, status)| {
                    serde_json::to_string(&status)
                        .ok()
                        .map(|value| (format!("{K_DEPLOY_PREFIX}{worker}"), value))
                })
                .collect();
            let stale: Vec<String> = state
                .iter_prefix(K_DEPLOY_PREFIX)
                .filter(|(key, _)| !deployments.contains_key(*key))
                .map(|(key, _)| key.to_string())
                .collect();
            for key in stale {
                state.delete(&key);
            }
            for (key, value) in deployments {
                if state.get(&key) != Some(value.as_str()) {
                    state.set(key, value);
                }
            }
        }
    }
}

/// Scrape peers' chitchat state: membership view, claim ingestion,
/// digest-triggered anti-entropy pulls.
async fn observer(node: Arc<Node>, chitchat: Arc<tokio::sync::Mutex<chitchat::Chitchat>>) {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes().expect("validated at load"));
    // Highest chitchat version already processed per (node, generation),
    // so we only decode/verify new claim keys.
    let mut seen: HashMap<(Arc<str>, u64), u64> = HashMap::new();
    let self_id: Arc<str> = node.id_hex().into();
    let interval = Duration::from_millis(node.cfg.gossip.interval_ms.max(250));
    loop {
        tokio::time::sleep(interval).await;
        // (peer api addr, digests) to reconcile after the lock drops.
        let mut peers: BTreeMap<String, PeerView> = BTreeMap::new();
        let mut claim_blobs: Vec<String> = Vec::new();
        {
            let cc = chitchat.lock().await;
            let live: Vec<ChitchatId> = cc.live_nodes().cloned().collect();
            for id in live {
                if id.node_id == self_id {
                    continue;
                }
                let Some(state) = cc.node_state(&id) else {
                    continue;
                };
                let mut view = PeerView {
                    generation: id.generation_id,
                    ..Default::default()
                };
                if let Some(v) = state.get(K_API) {
                    view.api_addr = v.parse().ok();
                }
                view.public = state.get(K_PUBLIC) == Some("1");
                view.label = state.get(K_LABEL).unwrap_or_default().to_string();
                view.ipv4 = state.get(K_IP4).map(|s| s.to_string());
                view.manifest_digest = state.get(K_MDIG).unwrap_or_default().to_string();
                for (k, v) in state.key_values() {
                    if let Some(ns) = k.strip_prefix(K_KDIG_PREFIX) {
                        view.kv_digests.insert(ns.to_string(), v.to_string());
                    }
                    if let Some(worker) = k.strip_prefix(K_DEPLOY_PREFIX) {
                        if let Ok(status) = serde_json::from_str(v) {
                            view.deployments.insert(worker.to_string(), status);
                        }
                    }
                }
                let seen_key = (id.node_id.clone(), id.generation_id);
                let mut max_seen = seen.get(&seen_key).copied().unwrap_or(0);
                for (k, vv) in state.iter_prefix(K_CLAIM_PREFIX) {
                    let _ = k;
                    if vv.version > max_seen && !vv.is_deleted() {
                        claim_blobs.push(vv.value.clone());
                    }
                    max_seen = max_seen.max(vv.version);
                }
                seen.insert(seen_key, max_seen);
                peers.insert(id.node_id.to_string(), view);
            }
        }

        for blob in claim_blobs {
            if let Ok(bytes) = b64().decode(blob.as_bytes()) {
                if let Ok(env) = Envelope::from_bytes(&bytes) {
                    let _ = node.ingest_claim(&env);
                }
            }
        }

        // Anti-entropy pulls, outside the chitchat lock.
        let my_mdig = node.manifest_digest_hex();
        let my_kdigs = node.kv_digests();
        for view in peers.values() {
            let Some(api) = view.api_addr else { continue };
            let base = api.to_string();
            if !view.manifest_digest.is_empty() && view.manifest_digest != my_mdig {
                match client.sync_manifests(&base).await {
                    Ok(envs) => {
                        for env in envs {
                            let _ = node.ingest_manifest(&env);
                        }
                    }
                    Err(e) => tracing::debug!("manifest sync from {base}: {e}"),
                }
                // Also pull claims wholesale on manifest drift — a
                // node that was down may have missed short-lived keys.
                if let Ok(envs) = client.sync_claims(&base).await {
                    for env in envs {
                        let _ = node.ingest_claim(&env);
                    }
                }
            }
            for (ns, dig) in &view.kv_digests {
                if my_kdigs.get(ns) != Some(dig) {
                    match client.kv_dump(&base, ns).await {
                        Ok(items) => {
                            let _ = node.kv_merge_remote(ns, items);
                        }
                        Err(e) => tracing::debug!("kv sync {ns} from {base}: {e}"),
                    }
                }
            }
        }
        node.update_peers(peers);
    }
}

/// Blob repair: whenever manifests change (and on a slow tick), fetch
/// referenced blobs we don't have from any live peer.
pub fn spawn_blob_fetcher(node: Arc<Node>) {
    tokio::spawn(async move {
        let client = PeerClient::new(node.cfg.cluster_secret_bytes().expect("validated at load"));
        let mut rx = node.subscribe();
        loop {
            // Wake on manifest change or every 15s.
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(NodeEvent::Manifests) => {}
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                },
                _ = tokio::time::sleep(Duration::from_secs(15)) => {}
            }
            let missing = node.missing_blobs();
            if missing.is_empty() {
                continue;
            }
            let peers = node.peers();
            'blobs: for sha in missing {
                for view in peers.values() {
                    let Some(api) = view.api_addr else { continue };
                    match client.fetch_blob(&api.to_string(), &sha).await {
                        Ok(bytes) => match node.blobs.put_verified(&sha, &bytes) {
                            Ok(()) => {
                                tracing::info!("fetched blob {}", hex::encode(sha));
                                node.notify_blobs_changed();
                                continue 'blobs;
                            }
                            Err(e) => tracing::warn!("peer sent bad blob: {e}"),
                        },
                        Err(e) => tracing::debug!("blob fetch: {e}"),
                    }
                }
            }
        }
    });
}
