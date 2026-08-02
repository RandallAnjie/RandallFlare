//! Node configuration: one TOML file, everything else is derived.

use anyhow::{Context, Result};
use rf_core::identity::SignerId;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Where keys, redb, blobs, workerd state live.
    pub data_dir: PathBuf,
    /// Cluster name — nodes only gossip within one cluster id.
    #[serde(default = "default_cluster_id")]
    pub cluster_id: String,
    /// Human label for status output ("hk-1").
    #[serde(default)]
    pub label: String,
    /// Operator identity — an ed25519 public key (64 hex chars) or an
    /// Ethereum wallet address ("0x…"). The only identity allowed to
    /// deploy.
    pub operator: SignerId,
    /// Shared cluster secret (hex, 32 bytes) — authenticates the peer
    /// API and gates gossip membership.
    pub cluster_secret: String,
    /// Public node: participates in DNS rotation + terminates ingress.
    /// Inner node: gossip/storage/claims only.
    #[serde(default)]
    pub public: bool,

    pub gossip: GossipConfig,
    pub peer_api: PeerApiConfig,
    #[serde(default)]
    pub ingress: IngressConfig,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub anchor: AnchorConfig,
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    #[serde(default)]
    pub d1: D1Config,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1Config {
    /// Compact a database's Raft log once it exceeds this many
    /// entries…
    #[serde(default = "default_compact_threshold")]
    pub compact_threshold: u64,
    /// …keeping this many recent entries for cheap follower catch-up
    /// (older laggards get a full snapshot).
    #[serde(default = "default_keep_tail")]
    pub keep_tail: u64,
}

impl Default for D1Config {
    fn default() -> Self {
        Self {
            compact_threshold: default_compact_threshold(),
            keep_tail: default_keep_tail(),
        }
    }
}

fn default_compact_threshold() -> u64 {
    4096
}

fn default_keep_tail() -> u64 {
    256
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// Contact email for the ACME account.
    pub email: String,
    /// Hostnames to keep certified; "*.edge.example.com" works
    /// (wildcards need DNS-01, which is what we do anyway).
    pub hostnames: Vec<String>,
    /// Cloudflare zone the TXT challenges live in. Falls back to
    /// [dns].zone when unset.
    #[serde(default)]
    pub zone: Option<String>,
    /// Env var with the CF token; defaults to [dns]'s token env or
    /// CF_API_TOKEN.
    #[serde(default)]
    pub api_token_env: Option<String>,
    /// ACME directory; default Let's Encrypt production.
    #[serde(default)]
    pub directory_url: Option<String>,
    /// Extra trust root PEM for the ACME server (pebble in tests).
    #[serde(default)]
    pub ca_root: Option<PathBuf>,
    /// Override the DNS API base (mock server in tests).
    #[serde(default)]
    pub dns_api_base: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AnchorConfig {
    /// Periodically publish a digest of all manifest heads (claimed
    /// task — one node per period wins).
    #[serde(default)]
    pub enabled: bool,
    /// Hours between anchors (default 24).
    #[serde(default = "default_anchor_hours")]
    pub interval_hours: u64,
    /// Optional webhook POSTed {period, digest, heads, node, ts_ms} —
    /// point it at anything, including an on-chain relayer.
    #[serde(default)]
    pub webhook: Option<String>,
}

fn default_anchor_hours() -> u64 {
    24
}

fn default_cluster_id() -> String {
    "randallflare".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipConfig {
    /// UDP listen, e.g. "0.0.0.0:7381".
    pub listen: SocketAddr,
    /// Address peers dial — must be reachable from the cluster.
    /// Defaults to `listen` (fine when listen is a routable IP).
    #[serde(default)]
    pub advertise: Option<SocketAddr>,
    /// Seed nodes ("host:port"); empty on the first node.
    #[serde(default)]
    pub seeds: Vec<String>,
    /// Gossip interval in ms. 1000 is a good default for small VPS
    /// fleets; lower = faster convergence, more packets.
    #[serde(default = "default_gossip_interval_ms")]
    pub interval_ms: u64,
}

fn default_gossip_interval_ms() -> u64 {
    1000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerApiConfig {
    /// TCP listen for the node-to-node + CLI HTTP API.
    pub listen: SocketAddr,
    /// Address peers dial; defaults to `listen`.
    #[serde(default)]
    pub advertise: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
    /// HTTP listen ("0.0.0.0:80"); None = ingress off (inner node).
    #[serde(default)]
    pub http: Option<SocketAddr>,
    /// HTTPS listen; requires certs (v0.2 — ACME via claims).
    #[serde(default)]
    pub https: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// The rotation hostname, e.g. "edge.example.com".
    pub hostname: String,
    /// Cloudflare zone name, e.g. "example.com".
    pub zone: String,
    /// Env var holding the CF API token (never the token itself —
    /// config files travel through dotfiles repos).
    #[serde(default = "default_cf_token_env")]
    pub api_token_env: String,
    /// This node's public IPv4 for its own A record. None = derive
    /// from the first non-private interface... not yet; explicit for v0.1.
    #[serde(default)]
    pub my_ipv4: Option<String>,
}

fn default_cf_token_env() -> String {
    "CF_API_TOKEN".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Path to the workerd binary. None = auto-detect on PATH;
    /// module workers are 503 when absent (assets still serve).
    #[serde(default)]
    pub workerd: Option<PathBuf>,
    /// First local port for per-worker workerd sockets.
    #[serde(default = "default_port_base")]
    pub port_base: u16,
    /// Permit native workerd local-disk Durable Objects. This is
    /// intentionally opt-in until quorum fencing is wired: enabling
    /// it on more than one node would create split-brain objects.
    #[serde(default)]
    pub allow_local_durable_objects: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            workerd: None,
            port_base: default_port_base(),
            allow_local_durable_objects: false,
        }
    }
}

fn default_port_base() -> u16 {
    30100
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: NodeConfig = toml::from_str(&raw).context("parsing config TOML")?;
        cfg.cluster_secret_bytes().context("cluster_secret")?;
        Ok(cfg)
    }

    pub fn cluster_secret_bytes(&self) -> Result<[u8; 32]> {
        let b = hex::decode(self.cluster_secret.trim()).context("hex decode")?;
        b.try_into().map_err(|_| anyhow::anyhow!("cluster_secret must be 32 hex-encoded bytes"))
    }

    pub fn gossip_advertise(&self) -> SocketAddr {
        self.gossip.advertise.unwrap_or(self.gossip.listen)
    }

    pub fn peer_api_advertise(&self) -> SocketAddr {
        self.peer_api.advertise.unwrap_or(self.peer_api.listen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_parses() {
        let cfg: NodeConfig = toml::from_str(
            r#"
            data_dir = "/var/lib/rf"
            operator = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "0.0.0.0:7381"
            [peer_api]
            listen = "0.0.0.0:7382"
            "#,
        )
        .unwrap();
        assert!(!cfg.public);
        assert_eq!(cfg.gossip_advertise().port(), 7381);
        cfg.cluster_secret_bytes().unwrap();
    }

    #[test]
    fn bad_secret_rejected() {
        let cfg: NodeConfig = toml::from_str(
            r#"
            data_dir = "/var/lib/rf"
            operator = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            cluster_secret = "beef"
            [gossip]
            listen = "0.0.0.0:7381"
            [peer_api]
            listen = "0.0.0.0:7382"
            "#,
        )
        .unwrap();
        assert!(cfg.cluster_secret_bytes().is_err());
    }
}
