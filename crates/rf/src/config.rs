//! Node configuration: one TOML file, everything else is derived.

use anyhow::{Context, Result};
use rf_core::identity::SignerId;
use rf_core::manifest::valid_hostname;
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
    #[serde(default)]
    pub update: UpdateConfig,
    /// Node-local Git checkout and sandboxed Worker build settings.
    /// Repository definitions and deploy artifacts replicate through the
    /// cluster, but credentials and build processes deliberately do not.
    #[serde(default)]
    pub build: BuildConfig,
    /// Node-local object storage settings. Remote credentials live only in
    /// the referenced rclone config and are never replicated.
    #[serde(default)]
    pub storage: StorageConfig,
    /// Optional SMTP receive/send capability. Nodes without this section do
    /// not open port 25 and never claim mail-delivery leases.
    #[serde(default)]
    pub email: EmailConfig,
    /// Optional TLS-encrypted device egress role. Client devices authenticate
    /// with one-way signed device tokens and never receive the cluster PSK.
    #[serde(default)]
    pub exit: ExitConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitConfig {
    #[serde(default)]
    pub enabled: bool,
    /// TLS SOCKS egress listener. Required only on selected exit nodes.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// Public `hostname:port` returned to enrolled devices. The hostname must
    /// have a certificate in `<data_dir>/certs`.
    #[serde(default)]
    pub advertise: Option<String>,
    #[serde(default = "default_exit_sessions")]
    pub max_sessions: u32,
    #[serde(default = "default_exit_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
}

impl Default for ExitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: None,
            advertise: None,
            max_sessions: default_exit_sessions(),
            connect_timeout_seconds: default_exit_connect_timeout_seconds(),
        }
    }
}

fn default_exit_sessions() -> u32 {
    512
}

fn default_exit_connect_timeout_seconds() -> u64 {
    15
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    /// Join the capability-selected SMTP pool.
    #[serde(default)]
    pub enabled: bool,
    /// Public SMTP listener. Required when enabled; normally 0.0.0.0:25.
    #[serde(default)]
    pub smtp_listen: Option<SocketAddr>,
    /// EHLO name, MX verification target and STARTTLS certificate stem.
    #[serde(default)]
    pub mx_hostname: Option<String>,
    /// Whether this node may claim outbound SMTP delivery leases.
    #[serde(default = "default_true")]
    pub outbound: bool,
    /// Maximum simultaneous inbound SMTP sessions.
    #[serde(default = "default_email_sessions")]
    pub max_sessions: u32,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_listen: None,
            mx_hostname: None,
            outbound: true,
            max_sessions: default_email_sessions(),
        }
    }
}

fn default_email_sessions() -> u32 {
    32
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Local content-addressed object root. Defaults to `<data_dir>/objects`.
    #[serde(default)]
    pub local_dir: Option<PathBuf>,
    /// rclone executable and config. Both must be set to enable rclone-backed
    /// R2 buckets on this node.
    #[serde(default)]
    pub rclone_binary: Option<PathBuf>,
    #[serde(default)]
    pub rclone_config: Option<PathBuf>,
    #[serde(default = "default_rclone_timeout_seconds")]
    pub rclone_timeout_seconds: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            local_dir: None,
            rclone_binary: None,
            rclone_config: None,
            rclone_timeout_seconds: default_rclone_timeout_seconds(),
        }
    }
}

fn default_rclone_timeout_seconds() -> u64 {
    30 * 60
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    /// Accept build jobs on this node.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// git executable. None = discover it on PATH.
    #[serde(default)]
    pub git: Option<PathBuf>,
    /// bubblewrap executable used for every custom build command.
    /// None = discover `bwrap` on PATH.
    #[serde(default)]
    pub sandbox: Option<PathBuf>,
    /// Name of the node-local environment variable containing a read-only
    /// GitHub token. Its value is never persisted or replicated.
    #[serde(default = "default_github_token_env")]
    pub github_token_env: String,
    /// Hard wall-clock limit for clone + build.
    #[serde(default = "default_build_timeout")]
    pub timeout_seconds: u64,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            git: None,
            sandbox: None,
            github_token_env: default_github_token_env(),
            timeout_seconds: default_build_timeout(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_github_token_env() -> String {
    "RF_GITHUB_TOKEN".into()
}

fn default_build_timeout() -> u64 {
    20 * 60
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_update_repo")]
    pub repo: String,
    #[serde(default = "default_update_api")]
    pub api_base: String,
    #[serde(default = "default_update_interval")]
    pub interval_minutes: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            repo: default_update_repo(),
            api_base: default_update_api(),
            interval_minutes: default_update_interval(),
        }
    }
}

fn default_update_repo() -> String {
    "RandallAnjie/RandallFlare".into()
}

fn default_update_api() -> String {
    "https://api.github.com".into()
}

fn default_update_interval() -> u64 {
    30
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
    /// Also issue certificates for exact hostnames attached to live Worker
    /// manifests. Only names inside `zone` are accepted. Disabled by default
    /// so an imported manifest cannot unexpectedly consume CA rate limits.
    #[serde(default)]
    pub include_worker_hostnames: bool,
    /// Seconds to wait after publishing the DNS-01 TXT record before
    /// notifying the CA. Cloudflare's API can acknowledge a write slightly
    /// before every authoritative nameserver serves it.
    #[serde(default = "default_acme_dns_propagation_seconds")]
    pub dns_propagation_seconds: u64,
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

fn default_acme_dns_propagation_seconds() -> u64 {
    20
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
    /// HTTPS listen; ACME/manual certs hot-load, with a self-signed
    /// fallback while no matching certificate exists.
    #[serde(default)]
    pub https: Option<SocketAddr>,
    /// Optional suffix used to give every live Worker a deterministic
    /// `<worker>.<domain>` route. The route is derived locally rather than
    /// written into the signed manifest, so every node reaches the same
    /// result without central allocation state.
    #[serde(default)]
    pub default_domain: Option<String>,
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
    /// from a public-IP discovery service when omitted.
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
    /// Bypass distributed DO fencing and use local disk directly.
    /// Development/emergency escape hatch only; never enable on more
    /// than one node serving the same Worker.
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
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.cluster_id.trim().is_empty() {
            anyhow::bail!("cluster_id must not be empty");
        }
        if self.gossip.interval_ms == 0 {
            anyhow::bail!("gossip.interval_ms must be greater than zero");
        }
        if self
            .gossip
            .advertise
            .map(|a| a.ip().is_unspecified())
            .unwrap_or_else(|| self.gossip.listen.ip().is_unspecified())
        {
            anyhow::bail!("gossip.advertise is required when gossip.listen uses 0.0.0.0 or [::]");
        }
        if self
            .peer_api
            .advertise
            .map(|a| a.ip().is_unspecified())
            .unwrap_or_else(|| self.peer_api.listen.ip().is_unspecified())
        {
            anyhow::bail!(
                "peer_api.advertise is required when peer_api.listen uses 0.0.0.0 or [::]"
            );
        }
        if self.runtime.port_base > u16::MAX - 999 {
            anyhow::bail!("runtime.port_base must be at most {}", u16::MAX - 999);
        }
        if let Some(domain) = &self.ingress.default_domain {
            if !valid_hostname(domain) || !valid_hostname(&format!("{}.{}", "a".repeat(63), domain))
            {
                anyhow::bail!(
                    "ingress.default_domain must be a lowercase DNS name that can fit a Worker prefix"
                );
            }
        }
        if self.d1.compact_threshold == 0 || self.d1.keep_tail >= self.d1.compact_threshold {
            anyhow::bail!("d1.keep_tail must be smaller than a non-zero d1.compact_threshold");
        }
        if self.update.enabled
            && (self.update.repo.trim().is_empty() || self.update.api_base.trim().is_empty())
        {
            anyhow::bail!("enabled update.repo and update.api_base must not be empty");
        }
        if self
            .acme
            .as_ref()
            .is_some_and(|acme| acme.dns_propagation_seconds > 600)
        {
            anyhow::bail!("acme.dns_propagation_seconds must not exceed 600");
        }
        if self.build.timeout_seconds == 0 || self.build.timeout_seconds > 6 * 60 * 60 {
            anyhow::bail!("build.timeout_seconds must be between 1 and 21600");
        }
        if self.build.github_token_env.trim().is_empty()
            || !self
                .build
                .github_token_env
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            anyhow::bail!("build.github_token_env must be a valid environment variable name");
        }
        if self.storage.rclone_binary.is_some() != self.storage.rclone_config.is_some() {
            anyhow::bail!(
                "storage.rclone_binary and storage.rclone_config must be configured together"
            );
        }
        if self.storage.rclone_timeout_seconds == 0
            || self.storage.rclone_timeout_seconds > 24 * 60 * 60
        {
            anyhow::bail!("storage.rclone_timeout_seconds must be between 1 and 86400");
        }
        if self.email.max_sessions == 0 || self.email.max_sessions > 1024 {
            anyhow::bail!("email.max_sessions must be between 1 and 1024");
        }
        if self.email.enabled {
            if self.email.smtp_listen.is_none() {
                anyhow::bail!("email.smtp_listen is required when email.enabled=true");
            }
            let hostname = self.email.mx_hostname.as_deref().ok_or_else(|| {
                anyhow::anyhow!("email.mx_hostname is required when email.enabled=true")
            })?;
            if !valid_hostname(hostname) {
                anyhow::bail!("email.mx_hostname must be a lowercase DNS hostname");
            }
        }
        if self.exit.max_sessions == 0 || self.exit.max_sessions > 16_384 {
            anyhow::bail!("exit.max_sessions must be between 1 and 16384");
        }
        if self.exit.connect_timeout_seconds == 0 || self.exit.connect_timeout_seconds > 300 {
            anyhow::bail!("exit.connect_timeout_seconds must be between 1 and 300");
        }
        if self.exit.enabled {
            self.exit
                .listen
                .context("exit.listen is required when exit.enabled=true")?;
            let advertise = self
                .exit
                .advertise
                .as_deref()
                .context("exit.advertise is required when exit.enabled=true")?;
            validate_host_port(advertise).context("exit.advertise")?;
            if advertise.parse::<SocketAddr>().is_ok() {
                anyhow::bail!("exit.advertise must use a DNS hostname so TLS clients can send SNI");
            }
        }
        Ok(())
    }

    pub fn cluster_secret_bytes(&self) -> Result<[u8; 32]> {
        let b = hex::decode(self.cluster_secret.trim()).context("hex decode")?;
        b.try_into()
            .map_err(|_| anyhow::anyhow!("cluster_secret must be 32 hex-encoded bytes"))
    }

    pub fn gossip_advertise(&self) -> SocketAddr {
        self.gossip.advertise.unwrap_or(self.gossip.listen)
    }

    pub fn peer_api_advertise(&self) -> SocketAddr {
        self.peer_api.advertise.unwrap_or(self.peer_api.listen)
    }

    pub fn default_worker_domain(&self) -> Option<&str> {
        self.ingress.default_domain.as_deref()
    }

    pub fn default_worker_hostname(&self, worker: &str) -> Option<String> {
        self.default_worker_domain()
            .map(|domain| format!("{worker}.{domain}"))
    }
}

fn validate_host_port(value: &str) -> Result<()> {
    if value.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    let (host, port) = value
        .rsplit_once(':')
        .context("must be hostname:port or an IP socket address")?;
    if !valid_hostname(host) {
        anyhow::bail!("hostname is invalid");
    }
    let port: u16 = port.parse().context("port is invalid")?;
    if port == 0 {
        anyhow::bail!("port must be non-zero");
    }
    Ok(())
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

    #[test]
    fn acme_dns_propagation_wait_defaults_and_is_bounded() {
        let raw = r#"
            data_dir = "/var/lib/rf"
            operator = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:7381"
            [peer_api]
            listen = "127.0.0.1:7382"
            [acme]
            email = "ops@example.com"
            hostnames = ["example.com"]
            zone = "example.com"
        "#;
        let mut cfg: NodeConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.acme.as_ref().unwrap().dns_propagation_seconds, 20);
        cfg.acme.as_mut().unwrap().dns_propagation_seconds = 601;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn wildcard_listeners_require_dialable_advertise_addresses() {
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
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn default_worker_domain_is_validated_and_derived() {
        let raw = r#"
            data_dir = "/var/lib/rf"
            operator = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:7381"
            [peer_api]
            listen = "127.0.0.1:7382"
            [ingress]
            default_domain = "workers.example.com"
        "#;
        let cfg: NodeConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.default_worker_hostname("hello"),
            Some("hello.workers.example.com".into())
        );

        let mut invalid = cfg.clone();
        invalid.ingress.default_domain = Some("Workers.Example.com".into());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn email_node_is_explicit_and_bounded() {
        let raw = r#"
            data_dir = "/var/lib/rf"
            operator = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:7381"
            [peer_api]
            listen = "127.0.0.1:7382"
            [email]
            enabled = true
            smtp_listen = "0.0.0.0:25"
            mx_hostname = "mx.example.com"
            outbound = false
            max_sessions = 64
        "#;
        let cfg: NodeConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.email.enabled);
        assert!(!cfg.email.outbound);

        let mut invalid = cfg.clone();
        invalid.email.mx_hostname = Some("MX.Example.com".into());
        assert!(invalid.validate().is_err());
        invalid.email.mx_hostname = Some("mx.example.com".into());
        invalid.email.max_sessions = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn exit_node_requires_a_dialable_tls_endpoint() {
        let raw = r#"
            data_dir = "/var/lib/rf"
            operator = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:7381"
            [peer_api]
            listen = "127.0.0.1:7382"
            [exit]
            enabled = true
            listen = "0.0.0.0:51821"
            advertise = "exit.example.com:51821"
        "#;
        let cfg: NodeConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.exit.enabled);
        let mut invalid = cfg;
        invalid.exit.advertise = Some("https://bad.example.com".into());
        assert!(invalid.validate().is_err());
        invalid.exit.advertise = Some("192.0.2.1:51821".into());
        assert!(invalid.validate().is_err());
    }
}
