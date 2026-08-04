//! rf — RandallFlare node daemon + operator CLI in one binary.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rf::config::NodeConfig;
use rf::node::Node;
use rf::peers::PeerClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "rf",
    version,
    about = "RandallFlare — an edge platform with no control plane"
)]
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
    /// Validate a node config and inspect runtime prerequisites.
    Doctor {
        #[arg(long, short)]
        config: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check the public identity/health endpoint of a node.
    Health {
        #[arg(long, env = "RF_NODE")]
        node: String,
    },
    /// Run the local, credential-isolating management console.
    Console {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        /// Loopback address for the browser UI.
        #[arg(long, default_value = "127.0.0.1:7390")]
        listen: SocketAddr,
    },
    /// Approve a browser login or Worker change with the operator key.
    Authorize {
        /// One-time code displayed by the management interface.
        code: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
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
    /// Replicated SQLite (D1) operations.
    D1 {
        #[command(subcommand)]
        cmd: D1Cmd,
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
enum D1Cmd {
    /// Create a database (replica group picked by rendezvous hash).
    Create {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Execute SQL (writes replicate through the quorum; SELECTs run
    /// on the leader).
    Exec {
        name: String,
        sql: String,
        /// JSON params, e.g. --params '[1, "two"]'
        #[arg(long, default_value = "[]")]
        params: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum KvCmd {
    List {
        ns: String,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
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
    Delete {
        ns: String,
        key: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

fn secret_bytes(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim()).context("cluster secret must be hex")?;
    b.try_into()
        .map_err(|_| anyhow::anyhow!("cluster secret must be 32 bytes"))
}

fn operator_key(path: Option<PathBuf>) -> Result<rf_core::identity::AnyKeypair> {
    let path = path.unwrap_or_else(default_operator_key_path);
    rf::keys::load_any(&path)
}

fn default_operator_key_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".rf").join("operator.key")
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
        Cmd::Doctor { config, json } => doctor(config, json),
        Cmd::Health { node } => health(&node).await,
        Cmd::Console {
            node,
            secret,
            key,
            listen,
        } => {
            let operator = match key {
                Some(path) => Some(operator_key(Some(path))?),
                None => {
                    let path = default_operator_key_path();
                    if path.is_file() {
                        Some(operator_key(Some(path))?)
                    } else {
                        None
                    }
                }
            };
            rf::console::serve(listen, node, secret_bytes(&secret)?, operator).await
        }
        Cmd::Authorize {
            code,
            node,
            key,
            secret,
        } => {
            use base64::Engine as _;

            let client = PeerClient::new(secret_bytes(&secret)?);
            let approval = client.authorization(&node, &code).await?;
            let status = client.status(&node).await?;
            let cluster_id = status
                .get("cluster_id")
                .and_then(serde_json::Value::as_str)
                .context("节点状态中缺少 cluster_id")?;
            let configured_operator: rf_core::identity::SignerId = status
                .get("operator")
                .and_then(serde_json::Value::as_str)
                .context("节点状态中缺少 operator")?
                .parse()
                .map_err(|error| anyhow::anyhow!("节点返回的管理员身份无效：{error}"))?;
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&approval.payload_base64)
                .context("节点返回的审批载荷无效")?;
            let operator = operator_key(key)?;
            if operator.signer_id() != configured_operator {
                anyhow::bail!("管理员密钥与节点 {node} 配置的管理员身份不匹配");
            }
            let description = describe_approval(approval.kind, &payload, cluster_id, &node)?;
            println!("{description}");
            let request = rf::management::ApprovalSignature {
                signer: operator.signer_id(),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(operator.sign(&payload)),
            };
            client.approve_authorization(&node, &code, &request).await?;
            println!("已批准 {}", approval.code);
            Ok(())
        }
        Cmd::Deploy {
            dir,
            node,
            key,
            secret,
        } => {
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
        Cmd::WorkerDelete {
            name,
            node,
            key,
            secret,
        } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let op = operator_key(key)?;
            let v = rf::deploy::delete_worker(&name, &client, &node, &op).await?;
            println!("tombstoned {name} at v{v}");
            Ok(())
        }
        Cmd::Kv { cmd } => match cmd {
            KvCmd::List {
                ns,
                prefix,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                for key in client.kv_list(&node, &ns, &prefix).await? {
                    println!("{key}");
                }
                Ok(())
            }
            KvCmd::Get {
                ns,
                key,
                node,
                secret,
            } => {
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
            KvCmd::Put {
                ns,
                key,
                value,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                client.kv_put(&node, &ns, &key, value.into_bytes()).await?;
                Ok(())
            }
            KvCmd::Delete {
                ns,
                key,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                client.kv_delete(&node, &ns, &key).await?;
                Ok(())
            }
        },
        Cmd::D1 { cmd } => match cmd {
            D1Cmd::Create { name, node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let resp = client
                    .post(
                        &node,
                        "/v1/d1/create",
                        serde_json::json!({ "name": name }).to_string().into_bytes(),
                    )
                    .await?;
                println!("{}", String::from_utf8_lossy(&resp));
                Ok(())
            }
            D1Cmd::Exec {
                name,
                sql,
                params,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let params: serde_json::Value = serde_json::from_str(&params)?;
                let out = client.d1_exec(&node, &name, &sql, params).await?;
                println!("{}", serde_json::to_string_pretty(&out)?);
                Ok(())
            }
        },
        Cmd::Log {
            worker,
            node,
            secret,
            operator,
            key,
        } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let operator_id: rf_core::identity::SignerId = match operator {
                Some(s) => s.parse().map_err(|e| anyhow::anyhow!("--operator: {e}"))?,
                None => operator_key(key)?.signer_id(),
            };
            let envs = client.worker_log(&node, &worker).await?;
            let chain = rf_core::manifest::verify_chain(&envs, &operator_id)
                .map_err(|e| anyhow::anyhow!("chain verification FAILED: {e}"))?;
            println!(
                "transparency log for {worker} — {} entries, chain OK",
                chain.len()
            );
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

fn describe_approval(
    kind: rf::management::ApprovalKind,
    payload: &[u8],
    expected_cluster_id: &str,
    node: &str,
) -> Result<String> {
    match kind {
        rf::management::ApprovalKind::Login => {
            let grant: rf::management::ConsoleGrant =
                postcard::from_bytes(payload).context("节点返回的控制台授权凭证无效")?;
            grant
                .validate(expected_cluster_id, rf::node::now_ms())
                .context("已拒绝无效的控制台授权凭证")?;
            Ok(format!(
                "通过节点 {node} 登录 RandallFlare 集群 {}",
                grant.cluster_id
            ))
        }
        rf::management::ApprovalKind::Manifest => {
            let manifest: rf_core::manifest::WorkerManifest =
                postcard::from_bytes(payload).context("节点返回的 Worker 部署清单无效")?;
            manifest
                .validate()
                .map_err(|error| anyhow::anyhow!("已拒绝无效的部署清单：{error}"))?;
            if manifest.deleted {
                return Ok(format!(
                    "删除 Worker {}（生成版本 v{}）",
                    manifest.name, manifest.version
                ));
            }
            let routes = if manifest.hostnames.is_empty() {
                "无".to_string()
            } else {
                manifest.hostnames.join(", ")
            };
            let env_keys = if manifest.env.is_empty() {
                "无".to_string()
            } else {
                manifest.env.keys().cloned().collect::<Vec<_>>().join(", ")
            };
            Ok(format!(
                "部署 Worker {} v{}（{} 个模块，{} 项静态资源）\n  路由：{}\n  环境变量键：{}\n  KV 绑定：{}\n  定时触发器：{}",
                manifest.name,
                manifest.version,
                manifest.modules.len(),
                manifest.assets.len(),
                routes,
                env_keys,
                manifest.kv_bindings.len(),
                manifest.crons.len(),
            ))
        }
        rf::management::ApprovalKind::Source => {
            let source: rf::build::WorkerSource =
                postcard::from_bytes(payload).context("节点返回的 Worker 源码配置无效")?;
            source.validate().context("已拒绝无效的 Worker 源码配置")?;
            if source.deleted {
                Ok(format!(
                    "断开 Worker {} 与 GitHub 仓库的连接（源码配置 v{}）",
                    source.worker, source.version
                ))
            } else {
                Ok(format!(
                    "将 Worker {} 连接至 {} 的 {} 分支（源码配置 v{}）\n  项目目录：{}\n  构建命令：{}\n  产物目录：{}\n  使用私有令牌：{}\n  Webhook：{}",
                    source.worker,
                    source.repository,
                    source.branch,
                    source.version,
                    source.root,
                    if source.build_command.is_empty() { "零配置构建" } else { &source.build_command },
                    source.output_dir,
                    if source.use_github_token { "是" } else { "否" },
                    if source.webhook { "已启用" } else { "未启用" },
                ))
            }
        }
    }
}

fn doctor(config: PathBuf, json: bool) -> Result<()> {
    let cfg = NodeConfig::load(&config)?;
    let configured_workerd = cfg.runtime.workerd.clone();
    let workerd = configured_workerd
        .clone()
        .or_else(rf::runtime::find_workerd);
    if let Some(path) = configured_workerd.as_ref() {
        if !path.is_file() {
            anyhow::bail!("configured workerd does not exist: {}", path.display());
        }
    }
    let workerd_version = workerd.as_ref().and_then(|path| {
        std::process::Command::new(path)
            .arg("--version")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
    });
    let git = rf::build::configured_binary(cfg.build.git.as_deref(), "git");
    let sandbox = rf::build::configured_binary(cfg.build.sandbox.as_deref(), "bwrap");
    if let (Some(path), None) = (&configured_workerd, &workerd_version) {
        anyhow::bail!(
            "configured workerd could not be executed successfully: {}",
            path.display()
        );
    }
    let mut warnings = Vec::new();
    if workerd_version.is_none() {
        warnings.push("workerd not found; module workers and Durable Objects will be unavailable");
    }
    if cfg.build.enabled && git.is_none() {
        warnings.push("Git builds are enabled but git was not found");
    }
    if cfg.build.enabled && sandbox.is_none() {
        warnings.push(
            "bubblewrap was not found; zero-config builds work, custom build commands do not",
        );
    }
    if cfg.public && cfg.ingress.http.is_none() && cfg.ingress.https.is_none() {
        warnings.push("public node has no HTTP or HTTPS ingress listener");
    }
    if !cfg.public && (cfg.ingress.http.is_some() || cfg.ingress.https.is_some()) {
        warnings.push("ingress is configured but public=false disables it");
    }
    if let Some(dns) = &cfg.dns {
        if std::env::var_os(&dns.api_token_env).is_none() {
            warnings.push("DNS is configured but its API token environment variable is absent");
        }
    }
    if let Some(acme) = &cfg.acme {
        let token_env = acme
            .api_token_env
            .as_deref()
            .or_else(|| cfg.dns.as_ref().map(|dns| dns.api_token_env.as_str()))
            .unwrap_or("CF_API_TOKEN");
        if std::env::var_os(token_env).is_none() {
            warnings.push("ACME is configured but its API token environment variable is absent");
        }
        if acme.zone.is_none() && cfg.dns.is_none() {
            warnings.push("ACME is configured but neither acme.zone nor dns.zone is set");
        }
    }
    if cfg.update.enabled {
        warnings.push(
            "self-update is enabled; the hardened systemd service intentionally cannot replace /usr/local/bin/rf",
        );
    }
    let report = serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "config": config,
        "data_dir": cfg.data_dir,
        "label": cfg.label,
        "operator": cfg.operator.to_string(),
        "public": cfg.public,
        "gossip_listen": cfg.gossip.listen,
        "gossip_advertise": cfg.gossip_advertise(),
        "peer_api_listen": cfg.peer_api.listen,
        "peer_api_advertise": cfg.peer_api_advertise(),
        "ingress_http": cfg.ingress.http,
        "ingress_https": cfg.ingress.https,
        "workerd": workerd,
        "workerd_version": workerd_version,
        "build_enabled": cfg.build.enabled,
        "git": git,
        "build_sandbox": sandbox,
        "github_token_configured": std::env::var_os(&cfg.build.github_token_env).is_some(),
        "warnings": warnings,
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("configuration OK: {}", config.display());
        println!(
            "node: {} ({})",
            report["label"].as_str().unwrap_or(""),
            report["operator"].as_str().unwrap_or("unknown")
        );
        println!(
            "gossip: {} -> {}",
            report["gossip_listen"], report["gossip_advertise"]
        );
        println!(
            "peer API: {} -> {}",
            report["peer_api_listen"], report["peer_api_advertise"]
        );
        match report["workerd_version"].as_str() {
            Some(version) => println!("runtime: {version}"),
            None => println!("runtime: unavailable (assets-only mode)"),
        }
        if cfg.build.enabled {
            println!(
                "builds: git={} sandbox={}",
                report["git"].as_str().unwrap_or("unavailable"),
                report["build_sandbox"].as_str().unwrap_or("unavailable")
            );
        } else {
            println!("builds: disabled");
        }
        for warning in report["warnings"].as_array().into_iter().flatten() {
            println!("warning: {}", warning.as_str().unwrap_or("unknown warning"));
        }
    }
    Ok(())
}

async fn health(node: &str) -> Result<()> {
    let response = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(5))
        .build()?
        .get(format!("http://{node}/v1/ping"))
        .send()
        .await?
        .error_for_status()?;
    let body = response.text().await?;
    let id = parse_ping(&body)?;
    println!("healthy {node} node={id}");
    Ok(())
}

fn parse_ping(body: &str) -> Result<rf_core::identity::PublicId> {
    let mut parts = body.split_whitespace();
    if parts.next() != Some("rf") {
        anyhow::bail!("invalid health response");
    }
    parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("health response omitted node identity"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid node identity in health response: {e}"))
}

async fn detect_public_ipv4() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    for url in ["https://api.ipify.org", "https://ipv4.icanhazip.com"] {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(text) = resp.text().await {
                let ip = text.trim().to_string();
                if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Ok(ip);
                }
            }
        }
    }
    anyhow::bail!("no detector reachable")
}

fn keygen(dir: Option<PathBuf>, eth: bool) -> Result<()> {
    let dir = dir.unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
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
    // Both ring and aws-lc-rs sit in the dep tree (reqwest vs our
    // rustls) — pick ring explicitly or rustls panics at first use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("rustls crypto provider already installed"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,chitchat=warn".into()),
        )
        .init();

    let mut cfg = NodeConfig::load(&config_path)?;
    // Public nodes need their IPv4 for DNS self-registration; detect
    // it when the config doesn't pin one.
    if let Some(dns) = cfg.dns.as_mut() {
        if dns.my_ipv4.is_none() && cfg.public {
            match detect_public_ipv4().await {
                Ok(ip) => {
                    tracing::info!("detected public ipv4: {ip}");
                    dns.my_ipv4 = Some(ip);
                }
                Err(e) => tracing::warn!("public ipv4 detection failed: {e} — set dns.my_ipv4"),
            }
        }
    }
    let cfg = cfg;
    let keypair = rf::keys::load_or_create(&cfg.data_dir.join("node.key"))?;
    tracing::info!("node {} ({})", keypair.public().short(), cfg.label);

    let node = Arc::new(Node::open(cfg, keypair)?);
    rf::build::recover_interrupted(&node);

    let d1_registry: rf::d1::Registry = Default::default();
    let d1_leadership: rf::d1::Leadership = Default::default();
    let durable =
        rf::durable::Coordinator::new(node.clone(), d1_registry.clone(), d1_leadership.clone());
    let api_addr = rf::peerapi::serve(node.clone(), d1_registry.clone(), durable.clone()).await?;
    tracing::info!("peer api on {api_addr}");
    rf::d1::spawn_manager(node.clone(), d1_registry, d1_leadership);

    // KV binding backend for workerd — must be up before the runtime
    // writes any workerd config.
    let kvbind_port = rf::kvbind::serve(node.clone()).await?;
    node.set_kvbind_port(kvbind_port);
    tracing::info!("kvbind on 127.0.0.1:{kvbind_port}");

    let _gossip = rf::gossip::start(node.clone()).await?;
    durable.spawn_ensurer();
    durable.spawn_checkpointer();
    rf::gossip::spawn_blob_fetcher(node.clone());
    tracing::info!("gossip on {}", node.cfg.gossip.listen);

    tokio::spawn(rf::runtime::Runtime::new(node.clone(), durable.clone()).run());

    if node.cfg.public {
        if let Some(http) = node.cfg.ingress.http {
            let addr = rf::ingress::serve(node.clone(), durable.clone(), http).await?;
            tracing::info!("ingress on {addr}");
        }
        if let Some(https) = node.cfg.ingress.https {
            rf::ingress::serve_tls(node.clone(), durable.clone(), https).await?;
            tracing::info!("tls ingress on {https}");
        }
    } else if node.cfg.ingress.http.is_some() || node.cfg.ingress.https.is_some() {
        tracing::warn!("ingress is configured but disabled because public = false");
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

    // Certs issued anywhere in the cluster materialize on every node.
    rf::acme::spawn_materializer(node.clone());
    if let Some(mut acme_cfg) = node.cfg.acme.clone() {
        let zone = acme_cfg
            .zone
            .clone()
            .or_else(|| node.cfg.dns.as_ref().map(|d| d.zone.clone()));
        let token_env = acme_cfg
            .api_token_env
            .clone()
            .or_else(|| node.cfg.dns.as_ref().map(|d| d.api_token_env.clone()))
            .unwrap_or_else(|| "CF_API_TOKEN".into());
        match (
            zone,
            std::env::var(&token_env).ok().filter(|t| !t.is_empty()),
        ) {
            (Some(zone), Some(token)) => {
                acme_cfg.zone = Some(zone.clone());
                let dns_api = match &acme_cfg.dns_api_base {
                    Some(base) => rf::dns::DnsApi::new(base.clone(), token, zone),
                    None => rf::dns::DnsApi::cloudflare(token, zone),
                };
                rf::acme::spawn_renewer(node.clone(), acme_cfg, dns_api);
                tracing::info!("acme renewer armed");
            }
            _ => {
                tracing::warn!("acme configured but zone or {token_env} missing — renewer disabled")
            }
        }
    }

    rf::anchor::spawn(node.clone(), node.cfg.anchor.clone());

    rf::selfupdate::spawn(node.cfg.update.clone());

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

#[cfg(test)]
mod cli_tests {
    use super::{describe_approval, parse_ping};
    use rf::management::{ApprovalKind, ConsoleGrant, CONSOLE_GRANT_VERSION};

    #[test]
    fn parses_health_identity() {
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(parse_ping(&format!("rf {id}\n")).unwrap().to_string(), id);
    }

    #[test]
    fn rejects_invalid_health_response() {
        assert!(parse_ping("ok").is_err());
        assert!(parse_ping("rf not-an-id").is_err());
    }

    #[test]
    fn login_approval_is_bound_to_reported_cluster() {
        let now = rf::node::now_ms();
        let grant = ConsoleGrant {
            version: CONSOLE_GRANT_VERSION,
            cluster_id: "cluster-a".into(),
            session_id: [1; 32],
            csrf: [2; 32],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
        };
        let payload = postcard::to_stdvec(&grant).unwrap();
        assert!(describe_approval(ApprovalKind::Login, &payload, "cluster-b", "node-a").is_err());
        assert_eq!(
            describe_approval(ApprovalKind::Login, &payload, "cluster-a", "node-a").unwrap(),
            "通过节点 node-a 登录 RandallFlare 集群 cluster-a"
        );
    }
}
