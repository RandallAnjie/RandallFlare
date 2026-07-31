//! Two-node end-to-end: real `rf` binaries on loopback.
//!
//! Proves the three core properties:
//!  1. deploy-to-one is deploy-to-all (manifest gossip + blob sync)
//!  2. KV written on node A reads on node B (anti-entropy)
//!  3. static stability: node A dies, node B keeps serving

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rf::peers::PeerClient;
use rf_core::identity::{AnyKeypair, Keypair};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

const SECRET: [u8; 32] = [42u8; 32];

struct TestNode {
    child: Child,
    api: String,
    ingress: u16,
    gossip: u16,
    _dir: PathBuf,
}

fn write_config(
    dir: &Path,
    operator: &Keypair,
    gossip_port: u16,
    api_port: u16,
    ingress_port: u16,
    seeds: &[u16],
    label: &str,
) -> PathBuf {
    let seeds_toml: Vec<String> =
        seeds.iter().map(|p| format!("\"127.0.0.1:{p}\"")).collect();
    let cfg = format!(
        r#"
data_dir = "{data}"
label = "{label}"
operator = "{op}"
cluster_secret = "{secret}"
public = true

[gossip]
listen = "127.0.0.1:{gossip_port}"
seeds = [{seeds}]
interval_ms = 150

[peer_api]
listen = "127.0.0.1:{api_port}"

[ingress]
http = "127.0.0.1:{ingress_port}"
"#,
        data = dir.join("data").display(),
        op = operator.public(),
        secret = hex::encode(SECRET),
        seeds = seeds_toml.join(", "),
    );
    let path = dir.join("rf.toml");
    std::fs::write(&path, cfg).unwrap();
    path
}

fn spawn_node(dir: &Path, config: &Path) -> Child {
    // tracing writes to stdout; workerd children inherit stderr —
    // both land in node.log.
    let log = std::fs::File::create(dir.join("node.log")).unwrap();
    let log2 = log.try_clone().unwrap();
    Command::new(env!("CARGO_BIN_EXE_rf"))
        .arg("run")
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .spawn()
        .expect("spawn rf")
}

async fn wait_ping(api: &str, budget: Duration) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + budget;
    loop {
        if let Ok(resp) = client.get(format!("http://{api}/v1/ping")).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        assert!(Instant::now() < deadline, "node at {api} never answered ping");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn start(label: &str, operator: &Keypair, seeds: &[u16]) -> TestNode {
    let dir = std::env::temp_dir().join(format!("rf-e2e-{label}-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (gossip, api, ingress) = (free_port(), free_port(), free_port());
    let config = write_config(&dir, operator, gossip, api, ingress, seeds, label);
    let child = spawn_node(&dir, &config);
    TestNode { child, api: format!("127.0.0.1:{api}"), ingress, gossip, _dir: dir }
}

fn make_bundle(hostname: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rf-e2e-bundle-{}", rand::random::<u32>()));
    std::fs::create_dir_all(dir.join("public/docs")).unwrap();
    let mut f = std::fs::File::create(dir.join("rf.json")).unwrap();
    write!(
        f,
        r#"{{"name":"site","assets":"public","hostnames":["{hostname}"]}}"#
    )
    .unwrap();
    std::fs::write(dir.join("public/index.html"), "<h1>hello from rf</h1>").unwrap();
    std::fs::write(dir.join("public/docs/index.html"), "<h1>docs</h1>").unwrap();
    std::fs::write(dir.join("public/404.html"), "custom 404").unwrap();
    dir
}

/// Full module-worker path against REAL workerd: deploy JS, runtime
/// spawns workerd, ingress proxies to it, KV binding URL works from
/// inside the worker. Skips (with a loud note) when workerd isn't on
/// PATH — CI boxes without it still run the rest of the suite.
#[tokio::test(flavor = "multi_thread")]
async fn module_worker_on_real_workerd() {
    let workerd_present = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("workerd").is_file()))
        .unwrap_or(false);
    if !workerd_present {
        eprintln!("SKIP: workerd not on PATH — module-worker e2e not exercised");
        return;
    }

    let operator = Keypair::from_seed([8u8; 32]);
    let op_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();

    let mut n = start("wd", &operator, &[]);
    wait_ping(&n.api, Duration::from_secs(15)).await;

    // Seed a KV value the worker will read through its binding.
    client.kv_put(&n.api, "ns1", "greet", b"kv-through-binding".to_vec()).await.unwrap();

    // A module worker that echoes env + fetches its KV binding URL.
    let dir = std::env::temp_dir().join(format!("rf-e2e-mod-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("rf.json"),
        r#"{"name":"api","main":"index.js","hostnames":["api.test"],
            "env":{"GREETING":"hi from env"},"kv":{"CACHE":"ns1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("index.js"),
        r#"export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/env") return new Response(env.GREETING);
    if (url.pathname === "/kv") return new Response(await env.CACHE.get("greet"));
    if (url.pathname === "/kv-rw") {
      await env.CACHE.put("written-by-worker", "worker-wrote-this", {expirationTtl: 3600});
      const listed = await env.CACHE.list({prefix: "written"});
      const val = await env.CACHE.get("written-by-worker");
      const missing = await env.CACHE.get("no-such-key");
      return new Response(JSON.stringify({val, missing, names: listed.keys.map(k => k.name)}));
    }
    return new Response("module worker up");
  }
};"#,
    )
    .unwrap();
    let bundle = rf::deploy::read_bundle(&dir).unwrap();
    rf::deploy::deploy(&bundle, &client, &n.api, &op_any).await.unwrap();

    // Runtime reconciles on the manifest event; workerd needs a
    // moment to boot. Poll through ingress.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let ok = http
            .get(format!("http://127.0.0.1:{}/", n.ingress))
            .header("host", "api.test")
            .send()
            .await
            .map(|r| r.status() == 200)
            .unwrap_or(false);
        if ok {
            break;
        }
        assert!(Instant::now() < deadline, "module worker never came up via ingress");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let env_resp = http
        .get(format!("http://127.0.0.1:{}/env", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap();
    assert_eq!(env_resp.text().await.unwrap(), "hi from env");

    let kv_resp = http
        .get(format!("http://127.0.0.1:{}/kv", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap();
    assert_eq!(kv_resp.text().await.unwrap(), "kv-through-binding");

    // Worker-side put/list/miss through the native binding.
    let rw: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/kv-rw", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rw["val"], "worker-wrote-this");
    assert_eq!(rw["missing"], serde_json::Value::Null);
    assert_eq!(rw["names"][0], "written-by-worker");
    // The worker's write is a real cluster KV write, visible via the
    // peer API too.
    assert_eq!(
        client.kv_get(&n.api, "ns1", "written-by-worker").await.unwrap().unwrap(),
        b"worker-wrote-this"
    );

    n.child.kill().unwrap();
    n.child.wait().unwrap();
}

/// HTTPS ingress: drop a PEM pair into <data>/certs, boot, serve an
/// assets worker over TLS with correct SNI resolution.
#[tokio::test(flavor = "multi_thread")]
async fn tls_ingress_serves_with_sni_cert() {
    let operator = Keypair::from_seed([9u8; 32]);
    let op_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);

    let dir = std::env::temp_dir().join(format!("rf-e2e-tls-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (gossip, api, ingress) = (free_port(), free_port(), free_port());
    let https = free_port();
    let mut cfg = std::fs::read_to_string(write_config(
        &dir, &operator, gossip, api, ingress, &[], "tls",
    ))
    .unwrap();
    cfg.push_str(&format!("https = \"127.0.0.1:{https}\"\n"));
    std::fs::write(dir.join("rf.toml"), cfg).unwrap();

    // Pre-drop a self-signed cert for the site hostname.
    let certs_dir = dir.join("data").join("certs");
    std::fs::create_dir_all(&certs_dir).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["tls.test".to_string()]).unwrap();
    std::fs::write(certs_dir.join("tls.test.crt"), cert.cert.pem()).unwrap();
    std::fs::write(certs_dir.join("tls.test.key"), cert.signing_key.serialize_pem()).unwrap();

    let mut child = spawn_node(&dir, &dir.join("rf.toml"));
    wait_ping(&format!("127.0.0.1:{api}"), Duration::from_secs(15)).await;

    let bundle_dir = make_bundle("tls.test");
    let bundle = rf::deploy::read_bundle(&bundle_dir).unwrap();
    rf::deploy::deploy(&bundle, &client, &format!("127.0.0.1:{api}"), &op_any)
        .await
        .unwrap();

    let https_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // self-signed in test
        .resolve("tls.test", format!("127.0.0.1:{https}").parse().unwrap())
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match https_client.get(format!("https://tls.test:{https}/")).send().await {
            Ok(r) if r.status() == 200 => {
                assert!(r.text().await.unwrap().contains("hello from rf"));
                break;
            }
            _ => {}
        }
        assert!(Instant::now() < deadline, "tls ingress never served the site");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    child.kill().unwrap();
    child.wait().unwrap();
}

/// Full ACME flow against a real pebble server (Let's Encrypt's test
/// CA, PEBBLE_VA_ALWAYS_VALID=1): the node claims the renewal task,
/// runs a DNS-01 order (TXT via a mock Cloudflare API), stores the
/// cert in cluster KV, and the materializer writes it to <data>/certs.
/// Skips when pebble isn't on PATH.
#[tokio::test(flavor = "multi_thread")]
async fn acme_issues_via_pebble_and_materializes() {
    let pebble_present = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("pebble").is_file()))
        .unwrap_or(false);
    if !pebble_present {
        eprintln!("SKIP: pebble not on PATH — ACME e2e not exercised");
        return;
    }

    let dir = std::env::temp_dir().join(format!("rf-e2e-acme-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();

    // --- CA + server cert for pebble's own HTTPS endpoint ---
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_cert = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .unwrap()
    .signed_by(&server_key, &ca)
    .unwrap();
    std::fs::write(dir.join("pebble.crt"), server_cert.pem()).unwrap();
    std::fs::write(dir.join("pebble.key"), server_key.serialize_pem()).unwrap();

    // --- pebble ---
    let pebble_port = free_port();
    let pebble_mgmt = free_port();
    std::fs::write(
        dir.join("pebble-config.json"),
        serde_json::json!({
            "pebble": {
                "listenAddress": format!("127.0.0.1:{pebble_port}"),
                "managementListenAddress": format!("127.0.0.1:{pebble_mgmt}"),
                "certificate": dir.join("pebble.crt"),
                "privateKey": dir.join("pebble.key"),
                "httpPort": 5002,
                "tlsPort": 5001,
                "ocspResponderURL": "",
                "externalAccountBindingRequired": false,
            }
        })
        .to_string(),
    )
    .unwrap();
    let mut pebble = Command::new("pebble")
        .arg("-config")
        .arg(dir.join("pebble-config.json"))
        .env("PEBBLE_VA_ALWAYS_VALID", "1")
        .env("PEBBLE_WFE_NONCEREJECT", "0")
        .stdout(Stdio::from(std::fs::File::create(dir.join("pebble.log")).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(dir.join("pebble.err")).unwrap()))
        .spawn()
        .expect("spawn pebble");
    // Wait for pebble's socket.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", pebble_port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "pebble never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // --- mock Cloudflare API (TXT records in memory) ---
    use std::sync::Mutex;
    let txt: std::sync::Arc<Mutex<Vec<(String, String, String)>>> =
        std::sync::Arc::new(Mutex::new(vec![])); // (id, name, content)
    let (t1, t2, t3) = (txt.clone(), txt.clone(), txt.clone());
    let cf_app = axum::Router::new()
        .route(
            "/zones",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"result": [{"id": "z1"}]}))
            }),
        )
        .route(
            "/zones/z1/dns_records",
            axum::routing::get(move || {
                let t = t1.clone();
                async move {
                    let items: Vec<_> = t
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(id, name, content)| {
                            serde_json::json!({"id": id, "name": name, "content": content})
                        })
                        .collect();
                    axum::Json(serde_json::json!({"result": items}))
                }
            })
            .post(move |axum::Json(v): axum::Json<serde_json::Value>| {
                let t = t2.clone();
                async move {
                    let mut g = t.lock().unwrap();
                    let id = format!("r{}", g.len() + 1);
                    g.push((
                        id,
                        v["name"].as_str().unwrap_or_default().to_string(),
                        v["content"].as_str().unwrap_or_default().to_string(),
                    ));
                    axum::Json(serde_json::json!({"result": {}}))
                }
            }),
        )
        .route(
            "/zones/z1/dns_records/{id}",
            axum::routing::delete(
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let t = t3.clone();
                    async move {
                        t.lock().unwrap().retain(|(i, _, _)| *i != id);
                        axum::Json(serde_json::json!({"result": {}}))
                    }
                },
            ),
        );
    let cf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cf_base = format!("http://{}", cf_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(cf_listener, cf_app).await.unwrap();
    });

    // --- rf node with [acme] ---
    let operator = Keypair::from_seed([11u8; 32]);
    let (gossip, api, ingress) = (free_port(), free_port(), free_port());
    let mut cfg = std::fs::read_to_string(write_config(
        &dir, &operator, gossip, api, ingress, &[], "acme",
    ))
    .unwrap();
    cfg.push_str(&format!(
        r#"
[acme]
email = "test@example.com"
hostnames = ["acme.test"]
zone = "test.zone"
api_token_env = "RF_TEST_CF_TOKEN"
directory_url = "https://localhost:{pebble_port}/dir"
ca_root = "{ca}"
dns_api_base = "{cf_base}"
"#,
        ca = dir.join("ca.pem").display(),
    ));
    std::fs::write(dir.join("rf.toml"), cfg).unwrap();
    std::env::set_var("RF_TEST_CF_TOKEN", "test-token");
    let mut child = spawn_node(&dir, &dir.join("rf.toml"));
    wait_ping(&format!("127.0.0.1:{api}"), Duration::from_secs(15)).await;

    // Cert must appear in <data>/certs via claim → order → KV →
    // materializer.
    let crt = dir.join("data").join("certs").join("acme.test.crt");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if crt.exists() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cert never materialized; node log: {}",
            std::fs::read_to_string(dir.join("node.log")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let pem = std::fs::read_to_string(&crt).unwrap();
    assert!(pem.contains("BEGIN CERTIFICATE"));
    assert!(crt.with_extension("key").exists());
    // Challenge TXT records were cleaned up.
    assert!(txt.lock().unwrap().is_empty(), "TXT records not cleaned: {:?}", txt.lock().unwrap());

    child.kill().unwrap();
    child.wait().unwrap();
    pebble.kill().unwrap();
    pebble.wait().unwrap();
}

/// D1 micro-quorum: three nodes, one replicated SQLite database.
/// Writes commit through the per-db Raft group; killing one replica
/// (possibly the leader) must not lose acknowledged rows, and writes
/// must keep working through the surviving majority.
#[tokio::test(flavor = "multi_thread")]
async fn d1_quorum_replicates_and_survives_replica_loss() {
    let operator = Keypair::from_seed([13u8; 32]);
    let client = PeerClient::new(SECRET);

    // Three-node cluster: b and c seed off a.
    let mut a = start("d1a", &operator, &[]);
    wait_ping(&a.api, Duration::from_secs(15)).await;
    let mut b = start("d1b", &operator, &[a.gossip]);
    let mut c = start("d1c", &operator, &[a.gossip]);
    wait_ping(&b.api, Duration::from_secs(15)).await;
    wait_ping(&c.api, Duration::from_secs(15)).await;
    // Let membership settle so the replica group sees all three.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = client.status(&a.api).await.unwrap_or_default();
        if status["peers"].as_array().map(|p| p.len()).unwrap_or(0) >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "membership never converged");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    client
        .post(&a.api, "/v1/d1/create", br#"{"name":"appdb"}"#.to_vec())
        .await
        .unwrap();

    // Schema + rows (leader election happens under the hood; the
    // client follows hints/retries).
    client
        .d1_exec(&a.api, "appdb", "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", serde_json::json!([]))
        .await
        .unwrap();
    client
        .d1_exec(&a.api, "appdb", "INSERT INTO t (v) VALUES (?1)", serde_json::json!(["one"]))
        .await
        .unwrap();
    client
        .d1_exec(&b.api, "appdb", "INSERT INTO t (v) VALUES (?1)", serde_json::json!(["two"]))
        .await
        .unwrap();

    let count = client
        .d1_exec(&a.api, "appdb", "SELECT COUNT(*) AS n FROM t", serde_json::json!([]))
        .await
        .unwrap();
    assert_eq!(count["rows"][0]["n"], 2, "both writes visible: {count}");

    // Find the LEADER (the node that answers a direct SELECT without
    // a hint) and kill precisely it — the harshest failover case.
    let mut leader_idx = None;
    let probe = br#"{"sql":"SELECT 1 AS ok","params":[]}"#.to_vec();
    for (i, n) in [&a, &b, &c].iter().enumerate() {
        if let Ok(raw) = client.post(&n.api, "/v1/d1/appdb/exec", probe.clone()).await {
            let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            if v["rows"][0]["ok"] == 1 {
                leader_idx = Some(i);
                break;
            }
        }
    }
    let leader_idx = leader_idx.expect("some node must be leader");
    let mut nodes = [a, b, c];
    nodes[leader_idx].child.kill().unwrap();
    nodes[leader_idx].child.wait().unwrap();
    let survivor = &nodes[(leader_idx + 1) % 3];

    // The surviving majority elects a new leader and accepts writes;
    // every acknowledged row is still there.
    client
        .d1_exec(&survivor.api, "appdb", "INSERT INTO t (v) VALUES (?1)", serde_json::json!(["three"]))
        .await
        .expect("write after leader loss");
    let count = client
        .d1_exec(&survivor.api, "appdb", "SELECT COUNT(*) AS n FROM t", serde_json::json!([]))
        .await
        .unwrap();
    assert_eq!(count["rows"][0]["n"], 3, "acked writes survive leader loss: {count}");

    for mut n in nodes {
        n.child.kill().ok();
        n.child.wait().ok();
    }
}

/// Snapshot catch-up: a replica misses enough writes that the leader
/// compacts its log past what the laggard needs; on rejoin it must be
/// brought current via InstallSnapshot — then prove it's a real voter
/// by killing the leader and writing through the recovered node's
/// majority.
#[tokio::test(flavor = "multi_thread")]
async fn d1_laggard_recovers_via_snapshot() {
    let operator = Keypair::from_seed([17u8; 32]);
    let client = PeerClient::new(SECRET);

    let mk = |label: &str, seeds: &[u16]| -> TestNode {
        let dir =
            std::env::temp_dir().join(format!("rf-e2e-{label}-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let (gossip, api, ingress) = (free_port(), free_port(), free_port());
        let mut cfg = std::fs::read_to_string(write_config(
            &dir, &operator, gossip, api, ingress, seeds, label,
        ))
        .unwrap();
        cfg.push_str("\n[d1]\ncompact_threshold = 12\nkeep_tail = 3\n");
        std::fs::write(dir.join("rf.toml"), cfg).unwrap();
        let child = spawn_node(&dir, &dir.join("rf.toml"));
        TestNode { child, api: format!("127.0.0.1:{api}"), ingress, gossip, _dir: dir }
    };

    let mut a = mk("snapa", &[]);
    wait_ping(&a.api, Duration::from_secs(15)).await;
    let mut b = mk("snapb", &[a.gossip]);
    let mut c = mk("snapc", &[a.gossip]);
    wait_ping(&b.api, Duration::from_secs(15)).await;
    wait_ping(&c.api, Duration::from_secs(15)).await;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = client.status(&a.api).await.unwrap_or_default();
        if status["peers"].as_array().map(|p| p.len()).unwrap_or(0) >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "membership never converged");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    client.post(&a.api, "/v1/d1/create", br#"{"name":"snapdb"}"#.to_vec()).await.unwrap();
    client
        .d1_exec(&a.api, "snapdb", "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", serde_json::json!([]))
        .await
        .unwrap();
    // Make sure C's driver has joined (first write replicated) before
    // taking it down — we want it BEHIND, not UNKNOWN.
    client
        .d1_exec(&a.api, "snapdb", "INSERT INTO t (v) VALUES ('seed')", serde_json::json!([]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    c.child.kill().unwrap();
    c.child.wait().unwrap();

    // 30 writes >> compact_threshold(12): survivors compact past
    // anything C still has.
    for i in 0..30 {
        client
            .d1_exec(
                &a.api,
                "snapdb",
                "INSERT INTO t (v) VALUES (?1)",
                serde_json::json!([format!("row{i}")]),
            )
            .await
            .unwrap();
    }

    // C rejoins with its stale state; snapshot must bring it current.
    let c_dir = c._dir.clone();
    let mut c2 = spawn_node(&c_dir, &c_dir.join("rf.toml"));
    wait_ping(&c.api, Duration::from_secs(15)).await;
    // Give replication a moment, then verify C actually holds the data
    // by making it part of the only available majority: kill the
    // current leader.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let probe = br#"{"sql":"SELECT 1 AS ok","params":[]}"#.to_vec();
    let mut leader_is_a = false;
    if let Ok(raw) = client.post(&a.api, "/v1/d1/snapdb/exec", probe.clone()).await {
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        leader_is_a = v["rows"][0]["ok"] == 1;
    }
    let (dead, survivor) = if leader_is_a { (&mut a, &b) } else { (&mut b, &a) };
    dead.child.kill().unwrap();
    dead.child.wait().unwrap();

    // Quorum now requires C. Writes + reads must still work, with all
    // 31 acknowledged rows present.
    client
        .d1_exec(&survivor.api, "snapdb", "INSERT INTO t (v) VALUES ('post-recovery')", serde_json::json!([]))
        .await
        .expect("write with recovered laggard in the majority");
    let count = client
        .d1_exec(&survivor.api, "snapdb", "SELECT COUNT(*) AS n FROM t", serde_json::json!([]))
        .await
        .unwrap();
    assert_eq!(count["rows"][0]["n"], 32, "all rows incl. snapshot-recovered: {count}");

    for mut n in [a, b] {
        n.child.kill().ok();
        n.child.wait().ok();
    }
    c2.kill().ok();
    c2.wait().ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn two_node_deploy_kv_and_static_stability() {
    let operator = Keypair::from_seed([7u8; 32]);
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();

    // Boot A, then B seeded on A.
    let mut a = start("a", &operator, &[]);
    wait_ping(&a.api, Duration::from_secs(15)).await;
    let mut b = start("b", &operator, &[a.gossip]);
    wait_ping(&b.api, Duration::from_secs(15)).await;

    // Deploy an assets-only worker (a pure static site) to A.
    let op_any = AnyKeypair::Ed(operator.clone());
    let bundle_dir = make_bundle("site.test");
    let bundle = rf::deploy::read_bundle(&bundle_dir).unwrap();
    let version = rf::deploy::deploy(&bundle, &client, &a.api, &op_any).await.unwrap();
    assert_eq!(version, 1);

    // Second deploy: exercises the hash chain (prev link) and version
    // bump; then verify the transparency log end-to-end.
    std::fs::write(bundle_dir.join("public/index.html"), "<h1>hello from rf v2</h1>").unwrap();
    let bundle2 = rf::deploy::read_bundle(&bundle_dir).unwrap();
    let v2 = rf::deploy::deploy(&bundle2, &client, &a.api, &op_any).await.unwrap();
    assert_eq!(v2, 2);
    let log = client.worker_log(&a.api, "site").await.unwrap();
    let chain =
        rf_core::manifest::verify_chain(&log, &op_any.signer_id()).expect("chain verifies");
    assert_eq!(chain.iter().map(|m| m.version).collect::<Vec<_>>(), vec![1, 2]);

    // The manifest + blobs must reach B via gossip anti-entropy.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(Some(2)) = client.worker_version(&b.api, "site").await {
            // also require blobs to have arrived
            if let Ok(status) = client.status(&b.api).await {
                if status["missing_blobs"].as_u64() == Some(0) {
                    break;
                }
            }
        }
        assert!(Instant::now() < deadline, "manifest/blobs never reached node B");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // B serves the site on its own ingress.
    let resp = http
        .get(format!("http://127.0.0.1:{}/", b.ingress))
        .header("host", "site.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("hello from rf"));

    // Directory index + custom 404 for static assets.
    let docs = http
        .get(format!("http://127.0.0.1:{}/docs/", b.ingress))
        .header("host", "site.test")
        .send()
        .await
        .unwrap();
    assert_eq!(docs.status(), 200);
    let missing = http
        .get(format!("http://127.0.0.1:{}/nope", b.ingress))
        .header("host", "site.test")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert!(missing.text().await.unwrap().contains("custom 404"));

    // KV: write on A, converge to B.
    client.kv_put(&a.api, "ns1", "greet", b"hola".to_vec()).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(Some(v)) = client.kv_get(&b.api, "ns1", "greet").await {
            assert_eq!(v, b"hola");
            break;
        }
        assert!(Instant::now() < deadline, "kv write never reached node B");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Static stability: kill A entirely; B keeps serving.
    a.child.kill().unwrap();
    a.child.wait().unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let resp = http
        .get(format!("http://127.0.0.1:{}/", b.ingress))
        .header("host", "site.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("hello from rf"));

    // And a restart of B must serve with A still gone (boot from disk).
    b.child.kill().unwrap();
    b.child.wait().unwrap();
    let b_dir = b._dir.clone();
    let config = b_dir.join("rf.toml");
    let mut b2 = spawn_node(&b_dir, &config);
    wait_ping(&b.api, Duration::from_secs(15)).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ok = http
            .get(format!("http://127.0.0.1:{}/", b.ingress))
            .header("host", "site.test")
            .send()
            .await
            .map(|r| r.status() == 200)
            .unwrap_or(false);
        if ok {
            break;
        }
        assert!(Instant::now() < deadline, "restarted B never served from disk");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    b2.kill().unwrap();
    b2.wait().unwrap();
}
