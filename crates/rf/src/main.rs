//! rf — RandallFlare node daemon + operator CLI in one binary.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rf::config::NodeConfig;
use rf::node::Node;
use rf::peers::PeerClient;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "rf", version, about = "RandallFlare — an edge platform with no control plane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an operator keypair (+ a suggested cluster secret).
    Keygen {
        /// Directory for operator.key (default ~/.rf)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Generate an Ethereum-style secp256k1 key — the operator
        /// identity becomes a 0x wallet address.
        #[arg(long)]
        eth: bool,
    },
    /// Run the node daemon.
    Run {
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Deploy a worker directory (rf.json + modules + assets).
    Deploy {
        dir: PathBuf,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Cluster status as seen by one node.
    Status {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Delete (tombstone) a worker.
    WorkerDelete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// KV operations against any node.
    Kv {
        #[command(subcommand)]
        cmd: KvCmd,
    },
    /// Fetch and verify a worker's transparency log (hash chain).
    Log {
        worker: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
        /// Operator identity to verify against (default: derived from
        /// your operator key file).
        #[arg(long)]
        operator: Option<String>,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KvCmd {
    Get {
        ns: String,
        key: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    Put {
        ns: String,
        key: String,
        value: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

fn secret_bytes(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim()).context("cluster secret must be hex")?;
    b.try_into().map_err(|_| anyhow::anyhow!("cluster secret must be 32 bytes"))
}

fn operator_key(path: Option<PathBuf>) -> Result<rf_core::identity::AnyKeypair> {
    let path = path.unwrap_or_else(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        home.join(".rf").join("operator.key")
    });
    rf::keys::load_any(&path)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Two worker threads: the coordination layer must stay tiny; the
    // real work happens in workerd children.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen { dir, eth } => keygen(dir, eth),
        Cmd::Run { config } => run(config).await,
        Cmd::Deploy { dir, node, key, secret } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let op = operator_key(key)?;
            let bundle = rf::deploy::read_bundle(&dir)?;
            let version = rf::deploy::deploy(&bundle, &client, &node, &op).await?;
            println!("deployed {} v{version}", bundle.spec.name);
            Ok(())
        }
        Cmd::Status { node, secret } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let status = client.status(&node).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Cmd::WorkerDelete { name, node, key, secret } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let op = operator_key(key)?;
            let v = rf::deploy::delete_worker(&name, &client, &node, &op).await?;
            println!("tombstoned {name} at v{v}");
            Ok(())
        }
        Cmd::Kv { cmd } => match cmd {
            KvCmd::Get { ns, key, node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                match client.kv_get(&node, &ns, &key).await? {
                    Some(v) => {
                        use std::io::Write;
                        std::io::stdout().write_all(&v)?;
                        Ok(())
                    }
                    None => {
                        eprintln!("(not found)");
                        std::process::exit(1);
                    }
                }
            }
            KvCmd::Put { ns, key, value, node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                client.kv_put(&node, &ns, &key, value.into_bytes()).await?;
                Ok(())
            }
        },
        Cmd::Log { worker, node, secret, operator, key } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let operator_id: rf_core::identity::SignerId = match operator {
                Some(s) => s.parse().map_err(|e| anyhow::anyhow!("--operator: {e}"))?,
                None => operator_key(key)?.signer_id(),
            };
            let envs = client.worker_log(&node, &worker).await?;
            let chain = rf_core::manifest::verify_chain(&envs, &operator_id)
                .map_err(|e| anyhow::anyhow!("chain verification FAILED: {e}"))?;
            println!("transparency log for {worker} — {} entries, chain OK", chain.len());
            for (m, env) in chain.iter().zip(&envs) {
                println!(
                    "  v{:<4} {}  {}{}",
                    m.version,
                    hex::encode(&env.digest()[..8]),
                    if m.deleted { "[tombstone] " } else { "" },
                    m.hostnames.join(",")
                );
            }
            Ok(())
        }
    }
}

fn keygen(dir: Option<PathBuf>, eth: bool) -> Result<()> {
    let dir = dir.unwrap_or_else(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        home.join(".rf")
    });
    let path = dir.join("operator.key");
    if path.exists() {
        anyhow::bail!("{} already exists — refusing to overwrite", path.display());
    }
    let kp = if eth {
        rf_core::identity::AnyKeypair::Eth(rf::keys::generate_eth())
    } else {
        rf_core::identity::AnyKeypair::Ed(rf::keys::generate())
    };
    rf::keys::save_any(&path, &kp)?;
    let mut secret = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut secret);
    println!("operator key   : {}", path.display());
    println!("operator id    : {}", kp.signer_id());
    println!();
    println!("suggested cluster_secret (same on every node):");
    println!("  {}", hex::encode(secret));
    println!();
    println!("node config gets:  operator = \"{}\"", kp.signer_id());
    Ok(())
}

async fn run(config_path: PathBuf) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,chitchat=warn".into()),
        )
        .init();

    let cfg = NodeConfig::load(&config_path)?;
    let keypair = rf::keys::load_or_create(&cfg.data_dir.join("node.key"))?;
    tracing::info!("node {} ({})", keypair.public().short(), cfg.label);

    let node = Arc::new(Node::open(cfg, keypair)?);

    let api_addr = rf::peerapi::serve(node.clone()).await?;
    tracing::info!("peer api on {api_addr}");

    let _gossip = rf::gossip::start(node.clone()).await?;
    rf::gossip::spawn_blob_fetcher(node.clone());
    tracing::info!("gossip on {}", node.cfg.gossip.listen);

    tokio::spawn(rf::runtime::Runtime::new(node.clone()).run());

    if let Some(http) = node.cfg.ingress.http {
        let addr = rf::ingress::serve(node.clone(), http).await?;
        tracing::info!("ingress on {addr}");
    }

    rf::cron_driver::spawn(node.clone());

    if let Some(dns_cfg) = node.cfg.dns.clone() {
        match std::env::var(&dns_cfg.api_token_env) {
            Ok(token) if !token.is_empty() => {
                let api = rf::dns::DnsApi::cloudflare(token, dns_cfg.zone.clone());
                rf::dns::spawn(node.clone(), api, dns_cfg);
                tracing::info!("dns reconciler armed");
            }
            _ => tracing::warn!(
                "dns configured but {} is empty — dns disabled",
                dns_cfg.api_token_env
            ),
        }
    }

    rf::anchor::spawn(node.clone(), node.cfg.anchor.clone());

    rf::selfupdate::spawn(false); // flips on once the repo is public

    // Periodic GC.
    {
        let node = node.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                node.gc();
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
