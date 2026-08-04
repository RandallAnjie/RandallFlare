//! Multi-process end-to-end tests with real `rf` binaries on loopback.
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

#[tokio::test(flavor = "multi_thread")]
async fn default_ingress_console_uses_operator_approved_cluster_session() {
    use base64::Engine as _;

    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([31u8; 32]);
    let operator_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();
    let node = start("admin", &operator, &[]);
    wait_ping(&node.api, Duration::from_secs(15)).await;
    let ingress = format!("http://127.0.0.1:{}", node.ingress);

    let page = http.get(&ingress).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let page = page.text().await.unwrap();
    assert!(page.contains("RandallFlare 管理控制台"));
    assert!(page.contains("去中心化身份验证"));
    assert!(!page.contains(&hex::encode(SECRET)));

    let denied = http
        .get(format!("{ingress}/api/session"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);

    let challenge: serde_json::Value = http
        .post(format!("{ingress}/api/auth/challenge"))
        .header("origin", &ingress)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = challenge["id"].as_str().unwrap();
    let code = challenge["code"].as_str().unwrap();
    let approval = client.authorization(&node.api, code).await.unwrap();
    assert_eq!(approval.kind, rf::management::ApprovalKind::Login);
    let payload = base64::engine::general_purpose::STANDARD
        .decode(approval.payload_base64)
        .unwrap();
    client
        .approve_authorization(
            &node.api,
            code,
            &rf::management::ApprovalSignature {
                signer: operator_any.signer_id(),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(operator_any.sign(&payload)),
            },
        )
        .await
        .unwrap();

    let authorized = http
        .get(format!("{ingress}/api/auth/challenge/{id}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let set_cookie = authorized
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    let session: serde_json::Value = http
        .get(format!("{ingress}/api/session"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["auth_mode"], "operator_grant");
    let csrf = session["csrf"].as_str().unwrap();

    http.put(format!("{ingress}/api/kv/value"))
        .header("cookie", &cookie)
        .header("origin", &ingress)
        .header("x-rf-csrf", csrf)
        .json(&serde_json::json!({
            "namespace": "admin-e2e",
            "key": "verified",
            "value": "yes"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        client
            .kv_get(&node.api, "admin-e2e", "verified")
            .await
            .unwrap()
            .as_deref(),
        Some(b"yes".as_slice())
    );

    let deploy: serde_json::Value = http
        .post(format!("{ingress}/api/workers/deploy"))
        .header("cookie", &cookie)
        .header("origin", &ingress)
        .header("x-rf-csrf", csrf)
        .json(&serde_json::json!({
            "files": [
                {
                    "path": "rf.json",
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(
                        br#"{"name":"admin-worker","assets":"public","hostnames":["admin-worker.test"]}"#
                    )
                },
                {
                    "path": "public/index.html",
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(
                        b"<h1>deployed through decentralized console</h1>"
                    )
                }
            ]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deploy["pending_approval"], true);
    let deploy_code = deploy["approval"]["code"].as_str().unwrap();
    let deploy_id = deploy["approval"]["id"].as_str().unwrap();
    let manifest_approval = client.authorization(&node.api, deploy_code).await.unwrap();
    assert_eq!(
        manifest_approval.kind,
        rf::management::ApprovalKind::Manifest
    );
    let manifest_payload = base64::engine::general_purpose::STANDARD
        .decode(manifest_approval.payload_base64)
        .unwrap();
    client
        .approve_authorization(
            &node.api,
            deploy_code,
            &rf::management::ApprovalSignature {
                signer: operator_any.signer_id(),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(operator_any.sign(&manifest_payload)),
            },
        )
        .await
        .unwrap();
    let committed: serde_json::Value = http
        .get(format!("{ingress}/api/approvals/{deploy_id}"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(committed["state"], "completed");
    let worker = http
        .get(format!("{ingress}/?access_token=must-not-be-recorded"))
        .header("host", "admin-worker.test")
        .send()
        .await
        .unwrap();
    assert_eq!(worker.status(), 200);
    assert!(worker
        .text()
        .await
        .unwrap()
        .contains("deployed through decentralized console"));
    let file: serde_json::Value = http
        .get(format!(
            "{ingress}/api/workers/admin-worker/files/index.html"
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        file["text"],
        "<h1>deployed through decentralized console</h1>"
    );
    let edited_html = b"<h1>edited as a signed Worker version</h1>";
    let edit: serde_json::Value = http
        .post(format!("{ingress}/api/workers/admin-worker/files"))
        .header("cookie", &cookie)
        .header("origin", &ingress)
        .header("x-rf-csrf", csrf)
        .json(&serde_json::json!({
            "changes": [{
                "operation": "put",
                "path": "index.html",
                "content_base64": base64::engine::general_purpose::STANDARD.encode(edited_html),
                "file_type": "asset"
            }]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(edit["pending_approval"], true);
    let edit_code = edit["approval"]["code"].as_str().unwrap();
    let edit_id = edit["approval"]["id"].as_str().unwrap();
    let edit_approval = client.authorization(&node.api, edit_code).await.unwrap();
    let edit_payload = base64::engine::general_purpose::STANDARD
        .decode(edit_approval.payload_base64)
        .unwrap();
    client
        .approve_authorization(
            &node.api,
            edit_code,
            &rf::management::ApprovalSignature {
                signer: operator_any.signer_id(),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(operator_any.sign(&edit_payload)),
            },
        )
        .await
        .unwrap();
    let edited: serde_json::Value = http
        .get(format!("{ingress}/api/approvals/{edit_id}"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(edited["state"], "completed");
    let worker = http
        .get(&ingress)
        .header("host", "admin-worker.test")
        .send()
        .await
        .unwrap();
    assert_eq!(worker.status(), 200);
    assert_eq!(worker.bytes().await.unwrap().as_ref(), edited_html);
    let log = client.worker_log(&node.api, "admin-worker").await.unwrap();
    assert!(rf_core::manifest::verify_chain(&log, &operator_any.signer_id()).is_ok());
    assert_eq!(log.len(), 2);

    // A historical preview is a separately signed resource: production stays
    // on v2 while the deterministic preview host serves the immutable v1
    // bytes. Deleting it writes a tombstone and immediately releases routing.
    let preview: serde_json::Value = http
        .post(format!("{ingress}/api/workers/admin-worker/previews"))
        .header("cookie", &cookie)
        .header("origin", &ingress)
        .header("x-rf-csrf", csrf)
        .json(&serde_json::json!({"version": 1, "ttl_days": 7}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(preview["pending_approval"], true);
    assert_eq!(preview["name"], "v1-admin-worker");
    let preview_code = preview["approval"]["code"].as_str().unwrap();
    let preview_id = preview["approval"]["id"].as_str().unwrap();
    let preview_approval = client.authorization(&node.api, preview_code).await.unwrap();
    assert_eq!(
        preview_approval.kind,
        rf::management::ApprovalKind::Resource
    );
    let preview_payload = base64::engine::general_purpose::STANDARD
        .decode(preview_approval.payload_base64)
        .unwrap();
    client
        .approve_authorization(
            &node.api,
            preview_code,
            &rf::management::ApprovalSignature {
                signer: operator_any.signer_id(),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(operator_any.sign(&preview_payload)),
            },
        )
        .await
        .unwrap();
    let committed: serde_json::Value = http
        .get(format!("{ingress}/api/approvals/{preview_id}"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(committed["state"], "completed");
    let historical = http
        .get(&ingress)
        .header("host", "v1-admin-worker.workers.test")
        .send()
        .await
        .unwrap();
    assert_eq!(historical.status(), 200);
    assert!(historical
        .text()
        .await
        .unwrap()
        .contains("deployed through decentralized console"));
    let production = http
        .get(&ingress)
        .header("host", "admin-worker.test")
        .send()
        .await
        .unwrap();
    assert_eq!(production.bytes().await.unwrap().as_ref(), edited_html);

    let remove_preview: serde_json::Value = http
        .delete(format!(
            "{ingress}/api/workers/admin-worker/previews/v1-admin-worker"
        ))
        .header("cookie", &cookie)
        .header("origin", &ingress)
        .header("x-rf-csrf", csrf)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let remove_code = remove_preview["approval"]["code"].as_str().unwrap();
    let remove_id = remove_preview["approval"]["id"].as_str().unwrap();
    let remove_approval = client.authorization(&node.api, remove_code).await.unwrap();
    let remove_payload = base64::engine::general_purpose::STANDARD
        .decode(remove_approval.payload_base64)
        .unwrap();
    client
        .approve_authorization(
            &node.api,
            remove_code,
            &rf::management::ApprovalSignature {
                signer: operator_any.signer_id(),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(operator_any.sign(&remove_payload)),
            },
        )
        .await
        .unwrap();
    let removed: serde_json::Value = http
        .get(format!("{ingress}/api/approvals/{remove_id}"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(removed["state"], "completed");
    let released = http
        .get(&ingress)
        .header("host", "v1-admin-worker.workers.test")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(released.contains("RandallFlare 管理控制台"));

    // Request observability traverses the encrypted peer API, but its data
    // model intentionally cannot contain query strings, headers or bodies.
    let requests = client
        .worker_request_logs(
            &node.api,
            "admin-worker",
            Some("admin-worker.test"),
            Some(2),
            20,
        )
        .await
        .unwrap();
    assert!(!requests.entries.is_empty());
    assert!(requests
        .entries
        .iter()
        .all(|entry| entry.path == "/" && !entry.path.contains("access_token")));
    assert_eq!(requests.hours.len(), 24);
    let console_requests: serde_json::Value = http
        .get(format!(
            "{ingress}/api/workers/admin-worker/request-log?status=2xx&limit=20"
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(console_requests["nodes"].as_array().unwrap().len(), 1);
    assert!(!console_requests["entries"].as_array().unwrap().is_empty());
    let encoded = serde_json::to_string(&console_requests).unwrap();
    assert!(!encoded.contains("must-not-be-recorded"));
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

const SECRET: [u8; 32] = [42u8; 32];
// Each test launches real daemons after discovering ports with
// bind(0). Serialize test scenarios so another scenario cannot claim
// a released port before its child binds it; nodes within a scenario
// still run concurrently and exercise the real distributed behavior.
static E2E_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread")]
async fn durable_flow_webhook_loops_and_resource_nodes() {
    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([37u8; 32]);
    let operator_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();
    let mut node = start("flow", &operator, &[]);
    wait_ping(&node.api, Duration::from_secs(15)).await;

    let graph: rf::flow::FlowGraph = serde_json::from_value(serde_json::json!({
        "nodes": [
            {"id":"start","type":"flowNode","position":{"x":0,"y":0},"data":{"nodeType":"trigger","label":"开始"}},
            {"id":"enabled","type":"flowNode","position":{"x":180,"y":0},"data":{"nodeType":"branch","label":"是否启用","condition":"input.enabled == true"}},
            {"id":"items","type":"flowNode","position":{"x":360,"y":0},"data":{"nodeType":"loop","label":"逐项写入","items":"input.items","maxIterations":10}},
            {"id":"store","type":"flowNode","position":{"x":540,"y":100},"data":{"nodeType":"kv","label":"保存项目","namespace":"flow-e2e","action":"put","key":"{{ item.id }}","value":"{{ item }}"}},
            {"id":"finish","type":"flowNode","position":{"x":720,"y":0},"data":{"nodeType":"transform","label":"完成","expression":"input"}},
            {"id":"disabled","type":"flowNode","position":{"x":360,"y":180},"data":{"nodeType":"transform","label":"未启用","template":{"skipped":true}}}
        ],
        "edges": [
            {"id":"e1","source":"start","target":"enabled"},
            {"id":"e2","source":"enabled","target":"items","sourceHandle":"true"},
            {"id":"e3","source":"enabled","target":"disabled","sourceHandle":"false"},
            {"id":"e4","source":"items","target":"store","sourceHandle":"each"},
            {"id":"e5","source":"items","target":"finish","sourceHandle":"done"}
        ]
    }))
    .unwrap();
    let (token, plaintext) = rf::flow::mint_token("e2e-webhook").unwrap();
    let record = rf::flow::prepare_flow_after(
        "durable-map",
        rf::flow::FlowSpec {
            description: "Flow 端到端耐久循环".into(),
            graph,
            trigger: rf::flow::FlowTrigger::Webhook,
            cron: None,
            hostnames: vec!["flow.test".into()],
            tokens: vec![token],
            suspended: false,
            suspend_reason: String::new(),
            retention_days: 30,
            max_concurrent_runs: 8,
            alert_webhook_env: None,
        },
        false,
        None,
    )
    .unwrap();
    assert!(!record.spec_json.contains(&plaintext));
    client
        .post_resource(
            &node.api,
            &rf_core::envelope::Envelope::seal_any(&record, &operator_any),
        )
        .await
        .unwrap();

    let response: serde_json::Value = http
        .post(format!("http://127.0.0.1:{}/v1/run?wait=1", node.ingress))
        .header("host", "flow.test")
        .bearer_auth(&plaintext)
        .header("idempotency-key", "flow-e2e-run")
        .json(&serde_json::json!({
            "enabled": true,
            "items": [{"id":"alpha","value":1},{"id":"beta","value":2}]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let run_id = response["id"].as_str().unwrap().to_string();
    assert_eq!(response["status"], "complete");
    assert_eq!(response["output"][0]["key"], "alpha");
    assert_eq!(response["output"][1]["key"], "beta");
    let duplicate: serde_json::Value = http
        .post(format!("http://127.0.0.1:{}/v1/run", node.ingress))
        .header("host", "flow.test")
        .bearer_auth(&plaintext)
        .header("idempotency-key", "flow-e2e-run")
        .json(&serde_json::json!({"enabled":true,"items":[]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(duplicate["id"], run_id);

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let detail = client
            .flow_run(&node.api, "durable-map", &run_id)
            .await
            .unwrap();
        if detail["run"]["status"] == "complete" {
            assert_eq!(detail["run"]["output"][0]["key"], "alpha");
            assert_eq!(detail["run"]["output"][1]["key"], "beta");
            assert!(detail["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["node_id"] == "store" && step["iteration"] == 2));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Flow did not reach a durable terminal state: {detail}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let alpha = client
        .kv_get(&node.api, "flow-e2e", "alpha")
        .await
        .unwrap()
        .unwrap();
    let beta = client
        .kv_get(&node.api, "flow-e2e", "beta")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&alpha).unwrap()["value"],
        1
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&beta).unwrap()["value"],
        2
    );

    let denied = http
        .post(format!("http://127.0.0.1:{}/v1/run", node.ingress))
        .header("host", "flow.test")
        .bearer_auth("wrong")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);

    node.child.kill().unwrap();
    node.child.wait().unwrap();
}

struct TestNode {
    child: TestChild,
    api: String,
    ingress: u16,
    gossip: u16,
    _dir: PathBuf,
}

struct TestChild(Child);

impl std::ops::Deref for TestChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for TestChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        // Fault-injection assertions can abort a test before its
        // explicit cleanup. Always reap the node so later tests and CI
        // jobs do not inherit live listeners from a failed run.
        self.child.kill().ok();
        self.child.wait().ok();
        std::fs::remove_dir_all(&self._dir).ok();
    }
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
    let seeds_toml: Vec<String> = seeds.iter().map(|p| format!("\"127.0.0.1:{p}\"")).collect();
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
default_domain = "workers.test"
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

fn spawn_node(dir: &Path, config: &Path) -> TestChild {
    // tracing writes to stdout; workerd children inherit stderr —
    // both land in node.log.
    let log = std::fs::File::create(dir.join("node.log")).unwrap();
    let log2 = log.try_clone().unwrap();
    TestChild(
        Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("run")
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .expect("spawn rf"),
    )
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
        assert!(
            Instant::now() < deadline,
            "node at {api} never answered ping"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_full_membership(client: &PeerClient, nodes: &[&TestNode], budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let mut converged = true;
        for node in nodes {
            let status = client.status(&node.api).await.unwrap_or_default();
            if status["peers"].as_array().map(Vec::len).unwrap_or(0) + 1 < nodes.len() {
                converged = false;
                break;
            }
        }
        if converged {
            return;
        }
        if Instant::now() >= deadline {
            dump_node_logs(nodes);
            panic!("cluster membership did not converge on every node");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn dump_node_logs(nodes: &[&TestNode]) {
    for node in nodes {
        let path = node._dir.join("node.log");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| error.to_string());
        let mut tail: Vec<&str> = text.lines().rev().take(120).collect();
        tail.reverse();
        eprintln!("--- tail of {} ---", path.display());
        for line in tail {
            eprintln!("{line}");
        }
    }
}

fn start(label: &str, operator: &Keypair, seeds: &[u16]) -> TestNode {
    let dir = std::env::temp_dir().join(format!("rf-e2e-{label}-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (gossip, api, ingress) = (free_port(), free_port(), free_port());
    let config = write_config(&dir, operator, gossip, api, ingress, seeds, label);
    let child = spawn_node(&dir, &config);
    TestNode {
        child,
        api: format!("127.0.0.1:{api}"),
        ingress,
        gossip,
        _dir: dir,
    }
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
    let _scenario = E2E_LOCK.lock().await;
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

    let backend_dir =
        std::env::temp_dir().join(format!("rf-e2e-service-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&backend_dir).unwrap();
    std::fs::write(
        backend_dir.join("rf.json"),
        r#"{"name":"backend","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        backend_dir.join("index.js"),
        r#"export default { async fetch(request) {
  const url = new URL(request.url);
  return Response.json({
    path: url.pathname,
    query: url.search,
    sourceHeader: request.headers.get("x-rf-service-source"),
    targetHeader: request.headers.get("x-rf-service-target")
  });
} };"#,
    )
    .unwrap();
    let backend_bundle = rf::deploy::read_bundle(&backend_dir).unwrap();
    rf::deploy::deploy(&backend_bundle, &client, &n.api, &op_any)
        .await
        .unwrap();

    // Seed a KV value the worker will read through its binding.
    client
        .kv_put(&n.api, "ns1", "greet", b"kv-through-binding".to_vec())
        .await
        .unwrap();

    // A module worker that echoes env + fetches its KV binding URL.
    let dir = std::env::temp_dir().join(format!("rf-e2e-mod-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("rf.json"),
        r#"{"name":"api","main":"index.js","hostnames":["api.test"],
            "env":{"GREETING":"hi from env"},"kv":{"CACHE":"ns1"},
            "d1":{"DB":"worker-db"},"queues":{"EVENTS":"events"},
            "analytics":{"METRICS":"web-metrics"},
            "pipelines":{"ARCHIVE":"events-pipe"},
            "workflows":{"ORDER_WORKFLOW":"order-flow"},
            "services":{"BACKEND":"backend"},
            "crons":["0 0 * * *"],
            "compatibility_flags":["nodejs_compat"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("index.js"),
        r#"import { WorkflowEntrypoint } from "randallflare:workers";

export class OrderWorkflow extends WorkflowEntrypoint {
  async run(input, step) {
    const prepared = await step.do("prepare-order", async () => {
      const count = Number(await this.env.CACHE.get("workflow-prepare-count") || "0") + 1;
      await this.env.CACHE.put("workflow-prepare-count", String(count));
      return { orderId: input.orderId, prepared: true };
    });
    await step.sleep("payment-window", 100);
    const payment = await step.waitForSignal("paid");
    const confirmation = await step.do("confirm-order", { retries: { limit: 2, delay: 1 } }, async () => ({
      orderId: input.orderId,
      method: payment.method,
      confirmed: true,
    }));
    return { prepared, payment, confirmation };
  }
}

export default {
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
    if (url.pathname === "/kv-meta") {
      await env.CACHE.put("with-meta", "metadata-value", {
        expirationTtl: 3600,
        metadata: { source: "native-workerd", generation: 2 }
      });
      const fetched = await env.CACHE.getWithMetadata("with-meta");
      const listed = await env.CACHE.list({prefix: "with-meta"});
      return Response.json({fetched, listed: listed.keys[0]});
    }
    if (url.pathname === "/kv-bulk") {
      await env.CACHE.put("bulk-a", "one");
      await env.CACHE.put("bulk-b", JSON.stringify({number: 2}));
      const texts = await env.CACHE.get(["bulk-a", "missing"]);
      const json = await env.CACHE.get(["bulk-b"], "json");
      return Response.json({texts: Object.fromEntries(texts), json: Object.fromEntries(json)});
    }
    if (url.pathname === "/d1") {
      await env.DB.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT); DELETE FROM users;");
      const inserted = await env.DB.prepare("INSERT INTO users (id, name) VALUES (?, ?)").bind(1, "安杰").run();
      const batch = await env.DB.batch([
        env.DB.prepare("INSERT INTO users (id, name) VALUES (?, ?)").bind(2, "Randall"),
        env.DB.prepare("SELECT id, name FROM users ORDER BY id")
      ]);
      const first = await env.DB.prepare("SELECT name FROM users WHERE id = ?").bind(1).first("name");
      const all = await env.DB.prepare("SELECT id, name FROM users ORDER BY id").all();
      const raw = await env.DB.prepare("SELECT id, name FROM users ORDER BY id").raw({columnNames: true});
      return Response.json({inserted, batch, first, all, raw});
    }
    if (url.pathname === "/queue-send") {
      await env.EVENTS.send({ id: "ack", mode: "ack" });
      await env.EVENTS.send({ id: "retry", mode: "retry-once" });
      await env.EVENTS.send({ id: "dead", mode: "always-retry" });
      return new Response("queued");
    }
    if (url.pathname === "/analytics") {
      env.METRICS.writeDataPoint({
        blobs: ["pageview", "/analytics"],
        doubles: [42.5, 9],
        indexes: ["visitor-e2e"],
      });
      return new Response("recorded");
    }
    if (url.pathname === "/pipeline") {
      await env.ARCHIVE.send([
        { kind: "worker", sequence: 1 },
        { kind: "worker", sequence: 2 },
      ]);
      return new Response("accepted");
    }
    if (url.pathname === "/service") {
      return env.BACKEND.fetch(new Request("http://backend/from-frontend?source=service", {
        headers: { "x-rf-service-target": "attempted-override" }
      }));
    }
    if (url.pathname === "/secret") return new Response(env.API_TOKEN);
    if (url.pathname === "/workflow-trigger") {
      const instance = await env.ORDER_WORKFLOW.create({ id: "order-e2e", params: { orderId: "RF-1001" } });
      return Response.json({ id: instance.id, status: await instance.status() });
    }
    return new Response("module worker up");
  },
  async queue(batch, env, context) {
    for (const message of batch.messages) {
      if (message.body.mode === "retry-once" && message.attempts === 1) {
        message.retry({ delaySeconds: 0, error: "first attempt requested retry" });
        continue;
      }
      if (message.body.mode === "always-retry") {
        message.retry({ delaySeconds: 0, error: "permanent queue failure" });
        continue;
      }
      context.waitUntil(env.CACHE.put(
        `queue-${message.body.id}`,
        JSON.stringify({ attempts: message.attempts, queue: batch.queue }),
      ));
    }
  },
  async scheduled(event, env, context) {
    context.waitUntil(env.CACHE.put("cron-last", JSON.stringify({
      cron: event.cron,
      scheduledTime: event.scheduledTime,
    })));
  }
};"#,
    )
    .unwrap();
    let bundle = rf::deploy::read_bundle(&dir).unwrap();
    let queue_record = rf::resource::prepare_after(
        rf::queue::QUEUE_KIND,
        "events",
        serde_json::to_value(rf::queue::QueueSpec {
            consumer_worker: Some("api".into()),
            batch_size: 10,
            max_wait_ms: 100,
            max_retries: 1,
            visibility_timeout_ms: 2_000,
            ..Default::default()
        })
        .unwrap(),
        false,
        None,
    )
    .unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&queue_record, &op_any),
        )
        .await
        .unwrap();
    let bucket_record = rf::resource::prepare_after(
        rf::r2::BUCKET_KIND,
        "pipeline-output",
        serde_json::to_value(rf::r2::BucketSpec {
            description: "Pipeline 输出".into(),
            public_access: false,
            storage: rf::objectstore::StorageLocation::Local,
            max_bytes: None,
            max_objects: None,
            expire_objects_after_days: None,
            cors_origins: vec![],
            hostnames: vec![],
        })
        .unwrap(),
        false,
        None,
    )
    .unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&bucket_record, &op_any),
        )
        .await
        .unwrap();
    let (pipeline_token, pipeline_plaintext) = rf::pipeline::mint_token("e2e-ingest").unwrap();
    let pipeline_record = rf::pipeline::prepare_pipeline_after(
        "events-pipe",
        rf::pipeline::PipelineSpec {
            description: "真实 workerd Pipeline".into(),
            output_bucket: "pipeline-output".into(),
            output_key_template: "events-pipe/{batchId}.jsonl.gz".into(),
            batch_max_bytes: 1_024,
            batch_max_seconds: 1,
            schema: Some(serde_json::json!({
                "type": "object",
                "required": ["kind", "sequence"],
                "properties": {
                    "kind": {"type": "string"},
                    "sequence": {"type": "integer"}
                }
            })),
            suspended: false,
            suspend_reason: String::new(),
            hostnames: vec!["pipe.test".into()],
            tokens: vec![pipeline_token],
        },
        false,
        None,
    )
    .unwrap();
    assert!(!pipeline_record.spec_json.contains(&pipeline_plaintext));
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&pipeline_record, &op_any),
        )
        .await
        .unwrap();
    let analytics_record = rf::analytics::prepare_dataset_after(
        "web-metrics",
        rf::analytics::DatasetSpec {
            description: "真实 workerd 指标".into(),
            retention_days: Some(30),
        },
        false,
        None,
    )
    .unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&analytics_record, &op_any),
        )
        .await
        .unwrap();
    let workflow_record = rf::workflow::prepare_workflow_after(
        "order-flow",
        rf::workflow::WorkflowSpec {
            description: "真实 workerd 耐久订单流程".into(),
            worker: "api".into(),
            entrypoint: "OrderWorkflow".into(),
            suspended: false,
            suspend_reason: String::new(),
            retention_days: 30,
            instance_retries: 3,
            instance_timeout_seconds: 120,
        },
        false,
        None,
    )
    .unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&workflow_record, &op_any),
        )
        .await
        .unwrap();
    rf::deploy::deploy(&bundle, &client, &n.api, &op_any)
        .await
        .unwrap();
    let secret_plaintext = format!("runtime-secret-{}", rand::random::<u64>());
    let envelopes = client.worker_log(&n.api, "api").await.unwrap();
    let manifest = rf_core::manifest::verify_chain(&envelopes, &op_any.signer_id())
        .unwrap()
        .last()
        .unwrap()
        .clone();
    let secret_manifest = rf::worker_secret::put_manifest_secret(
        manifest,
        envelopes.last().unwrap().digest(),
        &SECRET,
        "API_TOKEN",
        &secret_plaintext,
    )
    .unwrap();
    assert!(!serde_json::to_string(&secret_manifest)
        .unwrap()
        .contains(&secret_plaintext));
    client
        .post_manifest(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&secret_manifest, &op_any),
        )
        .await
        .unwrap();

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
        if Instant::now() >= deadline {
            dump_node_logs(&[&n]);
            panic!("module worker never came up via ingress");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let service_response: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/service", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(service_response["path"], "/from-frontend");
    assert_eq!(service_response["query"], "?source=service");
    assert!(service_response["sourceHeader"].is_null());
    assert!(service_response["targetHeader"].is_null());
    let secret_response = http
        .get(format!("http://127.0.0.1:{}/secret", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(secret_response, secret_plaintext);
    assert!(
        !n._dir.join("data/workers/api/2/config.capnp").exists(),
        "含 Secret 的明文 workerd 配置应在启动成功后删除"
    );
    let cron = client
        .cron_fire(&n.api, "api", Some("0 0 * * *"))
        .await
        .unwrap();
    assert_eq!(cron.status, "success");
    assert_eq!(cron.status_code, Some(204));
    assert_eq!(cron.expression, "0 0 * * *");
    let cron_value: serde_json::Value = serde_json::from_slice(
        &client
            .kv_get(&n.api, "ns1", "cron-last")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cron_value["cron"], "0 0 * * *");
    assert!(cron_value["scheduledTime"].as_u64().unwrap() > 0);
    let cron_runs = client.cron_runs(&n.api, "api", false, 10).await.unwrap();
    assert!(cron_runs.iter().any(|run| run.id == cron.id));
    assert!(client
        .cron_replay(&n.api, "api", &cron.id)
        .await
        .unwrap()
        .is_none());
    let dlq_id = "AAAAAAAAAAAAAAAAAAAAAA";
    client
        .d1_exec(
            &n.api,
            &rf::cron_driver::database_name("api"),
            r#"INSERT INTO cron_runs
               (id, expression, scheduled_at_ms, started_at_ms, finished_at_ms,
                attempt, status, status_code, error_brief, dlq, replay_of,
                replayed_at_ms, node_id)
               VALUES (?1,?2,?3,?3,?3,3,'failed',500,'synthetic DLQ',1,NULL,NULL,?4)"#,
            serde_json::json!([dlq_id, "0 0 * * *", rf::node::now_ms(), "test-node"]),
        )
        .await
        .unwrap();
    let replay = client
        .cron_replay(&n.api, "api", dlq_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.status, "success");
    assert_eq!(replay.replay_of.as_deref(), Some(dlq_id));
    let dlq = client.cron_runs(&n.api, "api", true, 10).await.unwrap();
    assert!(dlq
        .iter()
        .any(|run| run.id == dlq_id && run.replayed_at_ms.is_some()));
    assert!(client.cron_delete_dlq(&n.api, "api", dlq_id).await.unwrap());
    assert!(!client.cron_delete_dlq(&n.api, "api", dlq_id).await.unwrap());
    let workflow_trigger: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/workflow-trigger", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let workflow_instance = workflow_trigger["id"].as_str().unwrap().to_string();
    assert_eq!(workflow_trigger["status"]["id"], workflow_instance);
    // The Worker binding's explicit id is an idempotency key, not mutable
    // state: retrying the trigger must return the same durable instance.
    let workflow_retry: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/workflow-trigger", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(workflow_retry["id"], workflow_instance);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let detail = client
            .workflow_instance(&n.api, "order-flow", &workflow_instance)
            .await
            .unwrap();
        if detail["instance"]["status"] == "waiting" && detail["instance"]["waiting_for"] == "paid"
        {
            assert_eq!(
                client
                    .kv_get(&n.api, "ns1", "workflow-prepare-count")
                    .await
                    .unwrap()
                    .as_deref(),
                Some(b"1".as_slice()),
                "the completed step body must not re-run after durable sleep replay"
            );
            assert!(detail["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["name"] == "prepare-order" && step["status"] == "ok"));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Workflow did not replay through sleep and park on signal"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let signal_id = client
        .workflow_signal(
            &n.api,
            "order-flow",
            &workflow_instance,
            "paid",
            serde_json::json!({ "method": "alipay" }),
        )
        .await
        .unwrap();
    assert!(signal_id.starts_with("sig_"));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let detail = client
            .workflow_instance(&n.api, "order-flow", &workflow_instance)
            .await
            .unwrap();
        if detail["instance"]["status"] == "complete" {
            assert_eq!(detail["instance"]["output"]["payment"]["method"], "alipay");
            assert_eq!(
                detail["instance"]["output"]["confirmation"]["confirmed"],
                true
            );
            assert_eq!(detail["steps"].as_array().unwrap().len(), 3);
            assert_eq!(
                detail["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|event| event["kind"] == "created")
                    .count(),
                1,
                "idempotent creates must not duplicate the audit trail"
            );
            assert!(detail["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "signal_delivered"));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Workflow did not resume and complete after its signal"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let pipeline_response = http
        .get(format!("http://127.0.0.1:{}/pipeline", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap();
    assert_eq!(pipeline_response.text().await.unwrap(), "accepted");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let objects = client
            .r2_list(&n.api, "pipeline-output", "events-pipe/", None, 10)
            .await
            .unwrap();
        if let Some(object) = objects.objects.first() {
            let (_, compressed) = client
                .r2_get(&n.api, "pipeline-output", &object.key)
                .await
                .unwrap()
                .unwrap();
            let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
            let mut jsonl = String::new();
            std::io::Read::read_to_string(&mut decoder, &mut jsonl).unwrap();
            let events: Vec<serde_json::Value> = jsonl
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["kind"], "worker");
            assert_eq!(events[1]["sequence"], 2);
            let status = client.pipeline_status(&n.api, "events-pipe").await.unwrap();
            assert_eq!(status.queued_events, 0);
            assert_eq!(status.completed_batches, 1);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Pipeline driver did not publish a gzip JSONL batch to R2"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let unauthorized = http
        .post(format!("http://127.0.0.1:{}/send", n.ingress))
        .header("host", "pipe.test")
        .header("content-type", "application/x-ndjson")
        .body("{\"kind\":\"public\",\"sequence\":3}\n")
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);
    let public_ingest: serde_json::Value = http
        .post(format!("http://127.0.0.1:{}/send", n.ingress))
        .header("host", "pipe.test")
        .bearer_auth(&pipeline_plaintext)
        .header("content-type", "application/x-ndjson")
        .body("{\"kind\":\"public\",\"sequence\":3}\n{\"kind\":\"public\",\"sequence\":4}\n")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(public_ingest["accepted"], 2);
    let invalid_schema = http
        .post(format!("http://127.0.0.1:{}/send", n.ingress))
        .header("host", "pipe.test")
        .bearer_auth(&pipeline_plaintext)
        .json(&serde_json::json!({"kind":"missing-sequence"}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_schema.status(), 422);
    let flushed = client.pipeline_flush(&n.api, "events-pipe").await.unwrap();
    if let Some(batch) = flushed {
        assert_eq!(batch.event_count, 2);
        assert_eq!(batch.state, "completed");
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
    let metadata: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/kv-meta", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["fetched"]["value"], "metadata-value");
    assert_eq!(metadata["fetched"]["metadata"]["source"], "native-workerd");
    assert_eq!(metadata["listed"]["metadata"]["generation"], 2);
    let bulk: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/kv-bulk", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bulk["texts"]["bulk-a"], "one");
    assert_eq!(bulk["texts"]["missing"], serde_json::Value::Null);
    assert_eq!(bulk["json"]["bulk-b"]["number"], 2);
    let d1: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/d1", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(d1["inserted"]["success"], true);
    assert_eq!(d1["inserted"]["meta"]["changes"], 1);
    assert_eq!(d1["first"], "安杰");
    assert_eq!(d1["all"]["results"][1]["name"], "Randall");
    assert_eq!(d1["batch"][1]["results"][0]["id"], 1);
    assert_eq!(d1["raw"][0], serde_json::json!(["id", "name"]));
    let analytics_response = http
        .get(format!("http://127.0.0.1:{}/analytics", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap();
    assert_eq!(analytics_response.text().await.unwrap(), "recorded");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let events = client
            .analytics_recent(&n.api, "web-metrics", None, 10)
            .await
            .unwrap_or_default();
        if let Some(event) = events.first() {
            assert_eq!(event.blobs, ["pageview", "/analytics"]);
            assert_eq!(event.doubles, [42.5, 9.0]);
            assert_eq!(event.indexes, ["visitor-e2e"]);
            let stats = client.analytics_stats(&n.api, "web-metrics").await.unwrap();
            assert_eq!(stats.last_hour, 1);
            assert_eq!(stats.last_24_hours, 1);
            assert_eq!(stats.total, 1);
            let groups = client
                .analytics_group(&n.api, "web-metrics", "blob", 0, Some(0), 0, 10)
                .await
                .unwrap();
            assert_eq!(groups[0].key, "pageview");
            assert_eq!(groups[0].count, 1);
            assert_eq!(groups[0].sum, Some(42.5));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Analytics Worker binding did not persist its waitUntil write"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let queued = http
        .get(format!("http://127.0.0.1:{}/queue-send", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap();
    assert_eq!(queued.text().await.unwrap(), "queued");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ack = client.kv_get(&n.api, "ns1", "queue-ack").await.unwrap();
        let retry = client.kv_get(&n.api, "ns1", "queue-retry").await.unwrap();
        let dead = client
            .queue_dead_letters(&n.api, "events", 10)
            .await
            .unwrap_or_default();
        if let (Some(ack), Some(retry), Some(dead_message)) = (
            ack,
            retry,
            dead.iter().find(|item| item.body["id"] == "dead"),
        ) {
            let ack: serde_json::Value = serde_json::from_slice(&ack).unwrap();
            let retry: serde_json::Value = serde_json::from_slice(&retry).unwrap();
            assert_eq!(ack["attempts"], 1);
            assert_eq!(ack["queue"], "events");
            assert_eq!(retry["attempts"], 2);
            assert_eq!(dead_message.attempts, 2);
            assert!(dead_message
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("permanent queue failure"));
            assert!(client
                .queue_redrive(&n.api, "events", &dead_message.id)
                .await
                .unwrap());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "queue binding/consumer did not settle"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // The worker's write is a real cluster KV write, visible via the
    // peer API too.
    assert_eq!(
        client
            .kv_get(&n.api, "ns1", "written-by-worker")
            .await
            .unwrap()
            .unwrap(),
        b"worker-wrote-this"
    );

    n.child.kill().unwrap();
    n.child.wait().unwrap();
}

/// Native workerd Durable Object API plus quorum snapshot persistence
/// across a complete rf/workerd restart.
#[tokio::test(flavor = "multi_thread")]
async fn durable_object_on_real_workerd() {
    let _scenario = E2E_LOCK.lock().await;
    let workerd_present = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("workerd").is_file()))
        .unwrap_or(false);
    if !workerd_present {
        eprintln!("SKIP: workerd not on PATH — Durable Object e2e not exercised");
        return;
    }

    let operator = Keypair::from_seed([18u8; 32]);
    let op_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();
    let dir = std::env::temp_dir().join(format!("rf-e2e-do-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (gossip, api, ingress) = (free_port(), free_port(), free_port());
    let config = write_config(&dir, &operator, gossip, api, ingress, &[], "do");
    let mut child = spawn_node(&dir, &config);
    let api_addr = format!("127.0.0.1:{api}");
    wait_ping(&api_addr, Duration::from_secs(15)).await;

    let bundle_dir = dir.join("bundle");
    std::fs::create_dir_all(&bundle_dir).unwrap();
    std::fs::write(
        bundle_dir.join("rf.json"),
        r#"{"name":"counter","main":"index.js","hostnames":["counter.test"],
            "durable_objects":{"COUNTER":{"class_name":"Counter","enable_sql":true}}}"#,
    )
    .unwrap();
    std::fs::write(
        bundle_dir.join("index.js"),
        r#"export class Counter {
  constructor(ctx) { this.ctx = ctx; }
  async fetch() {
    const old = (await this.ctx.storage.get("count")) || 0;
    const value = old + 1;
    await this.ctx.storage.put("count", value);
    return new Response(String(value));
  }
}

export default {
  fetch(req, env) {
    const id = env.COUNTER.idFromName("global");
    return env.COUNTER.get(id).fetch(req);
  }
};"#,
    )
    .unwrap();
    let bundle = rf::deploy::read_bundle(&bundle_dir).unwrap();
    rf::deploy::deploy(&bundle, &client, &api_addr, &op_any)
        .await
        .unwrap();

    let call = || {
        http.get(format!("http://127.0.0.1:{ingress}/"))
            .header("host", "counter.test")
            .send()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = call().await {
            if resp.status() == 200 && resp.text().await.unwrap() == "1" {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "Durable Object worker never came up"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(call().await.unwrap().text().await.unwrap(), "2");

    // Restart rf/workerd and prove local SQLite state survives.
    child.kill().unwrap();
    child.wait().unwrap();
    let mut child = spawn_node(&dir, &config);
    wait_ping(&api_addr, Duration::from_secs(15)).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = call().await {
            if resp.status() == 200 {
                assert_eq!(resp.text().await.unwrap(), "3");
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "Durable Object did not recover after restart"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Three independent disks, no shared filesystem: every ingress
/// follows the quorum-fenced DO owner. Killing that owner elects a new
/// one which restores the last majority-committed SQLite snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn durable_object_routes_and_survives_owner_loss() {
    let _scenario = E2E_LOCK.lock().await;
    let workerd_present = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("workerd").is_file()))
        .unwrap_or(false);
    if !workerd_present {
        eprintln!("SKIP: workerd not on PATH — distributed DO e2e not exercised");
        return;
    }

    let operator = Keypair::from_seed([28u8; 32]);
    let op_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();
    let a = start("doa", &operator, &[]);
    wait_ping(&a.api, Duration::from_secs(15)).await;
    let b = start("dob", &operator, &[a.gossip]);
    let c = start("doc", &operator, &[a.gossip]);
    wait_ping(&b.api, Duration::from_secs(15)).await;
    wait_ping(&c.api, Duration::from_secs(15)).await;
    wait_full_membership(&client, &[&a, &b, &c], Duration::from_secs(20)).await;

    let bundle_dir = std::env::temp_dir().join(format!(
        "rf-e2e-do-cluster-bundle-{}",
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&bundle_dir).unwrap();
    std::fs::write(
        bundle_dir.join("rf.json"),
        r#"{"name":"global-counter","main":"index.js","hostnames":["global-counter.test"],
            "durable_objects":{"COUNTER":{"class_name":"Counter"}}}"#,
    )
    .unwrap();
    std::fs::write(
        bundle_dir.join("index.js"),
        r#"export class Counter {
	  constructor(ctx) { this.ctx = ctx; }
	  async fetch(req) {
	    const path = new URL(req.url).pathname;
	    let value = (await this.ctx.storage.get("count")) || 0;
	    if (path === "/inc") {
	      value++;
	      await this.ctx.storage.put("count", value);
	    }
	    if (path === "/background") {
	      this.ctx.waitUntil((async () => {
	        await new Promise(resolve => setTimeout(resolve, 1000));
	        await this.ctx.storage.put("count", value + 10);
	      })());
	      return new Response("scheduled");
	    }
	    return new Response(String(value));
  }
}
export default {
  fetch(req, env) {
    return env.COUNTER.get(env.COUNTER.idFromName("global")).fetch(req);
  }
};"#,
    )
    .unwrap();
    let bundle = rf::deploy::read_bundle(&bundle_dir).unwrap();
    rf::deploy::deploy(&bundle, &client, &a.api, &op_any)
        .await
        .unwrap();

    let call = |ingress: u16, path: &str| {
        http.get(format!("http://127.0.0.1:{ingress}{path}"))
            .header("host", "global-counter.test")
            .send()
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(resp) = call(b.ingress, "/value").await {
            if resp.status() == 200 && resp.text().await.unwrap() == "0" {
                break;
            }
        }
        if Instant::now() >= deadline {
            dump_node_logs(&[&a, &b, &c]);
            panic!("distributed DO owner never became ready");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    for (expected, ingress) in [("1", a.ingress), ("2", b.ingress), ("3", c.ingress)] {
        let response = call(ingress, "/inc").await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), expected);
    }

    // The response is committed before this waitUntil mutation runs.
    // No later request reaches the object before the owner dies, so
    // recovery of 13 proves the periodic background checkpointer
    // replicated state changed by alarms/WebSockets/waitUntil work.
    let response = call(b.ingress, "/background").await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "scheduled");
    tokio::time::sleep(Duration::from_secs(4)).await;

    let mut nodes = [a, b, c];
    let mut owner_idx = None;
    for (idx, node) in nodes.iter().enumerate() {
        let status = client.status(&node.api).await.unwrap();
        let owned = status["workers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["name"] == "global-counter" && w["durable_owned_here"] == true);
        if owned {
            owner_idx = Some(idx);
            break;
        }
    }
    let owner_idx = owner_idx.expect("one node reports itself as DO owner");
    nodes[owner_idx].child.kill().unwrap();
    nodes[owner_idx].child.wait().unwrap();
    let survivor_idx = (owner_idx + 1) % 3;

    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        if let Ok(resp) = call(nodes[survivor_idx].ingress, "/value").await {
            if resp.status() == 200 {
                assert_eq!(resp.text().await.unwrap(), "13");
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "DO did not fail over with committed state"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let response = call(nodes[survivor_idx].ingress, "/inc").await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "14");

    for mut node in nodes {
        node.child.kill().ok();
        node.child.wait().ok();
    }
}

/// HTTPS ingress: drop a PEM pair into <data>/certs, boot, serve an
/// assets worker over TLS with correct SNI resolution.
#[tokio::test(flavor = "multi_thread")]
async fn tls_ingress_serves_with_sni_cert() {
    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([9u8; 32]);
    let op_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);

    let dir = std::env::temp_dir().join(format!("rf-e2e-tls-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (gossip, api, ingress) = (free_port(), free_port(), free_port());
    let https = free_port();
    let mut cfg = std::fs::read_to_string(write_config(
        &dir,
        &operator,
        gossip,
        api,
        ingress,
        &[],
        "tls",
    ))
    .unwrap();
    cfg.push_str(&format!("https = \"127.0.0.1:{https}\"\n"));
    std::fs::write(dir.join("rf.toml"), cfg).unwrap();

    // Pre-drop a self-signed cert for the site hostname.
    let certs_dir = dir.join("data").join("certs");
    std::fs::create_dir_all(&certs_dir).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["tls.test".to_string()]).unwrap();
    std::fs::write(certs_dir.join("tls.test.crt"), cert.cert.pem()).unwrap();
    std::fs::write(
        certs_dir.join("tls.test.key"),
        cert.signing_key.serialize_pem(),
    )
    .unwrap();

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
        match https_client
            .get(format!("https://tls.test:{https}/"))
            .send()
            .await
        {
            Ok(r) if r.status() == 200 => {
                assert!(r.text().await.unwrap().contains("hello from rf"));
                break;
            }
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "tls ingress never served the site"
        );
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
    let _scenario = E2E_LOCK.lock().await;
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
    let server_cert =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
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
    let mut pebble = TestChild(
        Command::new("pebble")
            .arg("-config")
            .arg(dir.join("pebble-config.json"))
            .env("PEBBLE_VA_ALWAYS_VALID", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(Stdio::from(
                std::fs::File::create(dir.join("pebble.log")).unwrap(),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(dir.join("pebble.err")).unwrap(),
            ))
            .spawn()
            .expect("spawn pebble"),
    );
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
        &dir,
        &operator,
        gossip,
        api,
        ingress,
        &[],
        "acme",
    ))
    .unwrap();
    cfg.push_str(&format!(
        r#"
[acme]
email = "test@example.com"
hostnames = ["acme.test"]
zone = "test.zone"
api_token_env = "RF_TEST_CF_TOKEN"
dns_propagation_seconds = 0
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
    assert!(
        txt.lock().unwrap().is_empty(),
        "TXT records not cleaned: {:?}",
        txt.lock().unwrap()
    );

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
    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([13u8; 32]);
    let client = PeerClient::new(SECRET);

    // Three-node cluster: b and c seed off a.
    let a = start("d1a", &operator, &[]);
    wait_ping(&a.api, Duration::from_secs(15)).await;
    let b = start("d1b", &operator, &[a.gossip]);
    let c = start("d1c", &operator, &[a.gossip]);
    wait_ping(&b.api, Duration::from_secs(15)).await;
    wait_ping(&c.api, Duration::from_secs(15)).await;
    // Let every node's address view settle before freezing the
    // database's replica group.
    wait_full_membership(&client, &[&a, &b, &c], Duration::from_secs(20)).await;

    client
        .post(&a.api, "/v1/d1/create", br#"{"name":"appdb"}"#.to_vec())
        .await
        .unwrap();

    // Schema + rows (leader election happens under the hood; the
    // client follows hints/retries).
    client
        .d1_exec(
            &a.api,
            "appdb",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    client
        .d1_exec(
            &a.api,
            "appdb",
            "INSERT INTO t (v) VALUES (?1)",
            serde_json::json!(["one"]),
        )
        .await
        .unwrap();
    client
        .d1_exec(
            &b.api,
            "appdb",
            "INSERT INTO t (v) VALUES (?1)",
            serde_json::json!(["two"]),
        )
        .await
        .unwrap();

    let count = client
        .d1_exec(
            &a.api,
            "appdb",
            "SELECT COUNT(*) AS n FROM t",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    assert_eq!(count["rows"][0]["n"], 2, "both writes visible: {count}");
    let cte = client
        .d1_exec(
            &b.api,
            "appdb",
            "WITH total(n) AS (SELECT COUNT(*) FROM t) SELECT n FROM total",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    assert_eq!(cte["rows"][0]["n"], 2, "CTE reads stay read-only: {cte}");
    client
        .d1_exec(
            &a.api,
            "appdb",
            "PRAGMA user_version = 7",
            serde_json::json!([]),
        )
        .await
        .unwrap();

    // Find the LEADER (the node that answers a direct SELECT without
    // a hint) and kill precisely it — the harshest failover case.
    let mut leader_idx = None;
    let probe = br#"{"sql":"SELECT 1 AS ok","params":[]}"#.to_vec();
    for (i, n) in [&a, &b, &c].iter().enumerate() {
        if let Ok(raw) = client
            .post(&n.api, "/v1/d1/appdb/exec", probe.clone())
            .await
        {
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
        .d1_exec(
            &survivor.api,
            "appdb",
            "INSERT INTO t (v) VALUES (?1)",
            serde_json::json!(["three"]),
        )
        .await
        .expect("write after leader loss");
    let count = client
        .d1_exec(
            &survivor.api,
            "appdb",
            "SELECT COUNT(*) AS n FROM t",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    assert_eq!(
        count["rows"][0]["n"], 3,
        "acked writes survive leader loss: {count}"
    );
    let pragma = client
        .d1_exec(
            &survivor.api,
            "appdb",
            "PRAGMA user_version",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    assert_eq!(
        pragma["rows"][0]["user_version"], 7,
        "mutating PRAGMA replicated before failover: {pragma}"
    );

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
    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([17u8; 32]);
    let client = PeerClient::new(SECRET);

    let mk = |label: &str, seeds: &[u16]| -> TestNode {
        let dir = std::env::temp_dir().join(format!("rf-e2e-{label}-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let (gossip, api, ingress) = (free_port(), free_port(), free_port());
        let mut cfg = std::fs::read_to_string(write_config(
            &dir, &operator, gossip, api, ingress, seeds, label,
        ))
        .unwrap();
        cfg.push_str("\n[d1]\ncompact_threshold = 12\nkeep_tail = 3\n");
        std::fs::write(dir.join("rf.toml"), cfg).unwrap();
        let child = spawn_node(&dir, &dir.join("rf.toml"));
        TestNode {
            child,
            api: format!("127.0.0.1:{api}"),
            ingress,
            gossip,
            _dir: dir,
        }
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

    client
        .post(&a.api, "/v1/d1/create", br#"{"name":"snapdb"}"#.to_vec())
        .await
        .unwrap();
    client
        .d1_exec(
            &a.api,
            "snapdb",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    // Make sure C's driver has joined (first write replicated) before
    // taking it down — we want it BEHIND, not UNKNOWN.
    client
        .d1_exec(
            &a.api,
            "snapdb",
            "INSERT INTO t (v) VALUES ('seed')",
            serde_json::json!([]),
        )
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
    if let Ok(raw) = client
        .post(&a.api, "/v1/d1/snapdb/exec", probe.clone())
        .await
    {
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        leader_is_a = v["rows"][0]["ok"] == 1;
    }
    let (dead, survivor) = if leader_is_a {
        (&mut a, &b)
    } else {
        (&mut b, &a)
    };
    dead.child.kill().unwrap();
    dead.child.wait().unwrap();

    // Quorum now requires C. Writes + reads must still work, with all
    // 31 acknowledged rows present.
    client
        .d1_exec(
            &survivor.api,
            "snapdb",
            "INSERT INTO t (v) VALUES ('post-recovery')",
            serde_json::json!([]),
        )
        .await
        .expect("write with recovered laggard in the majority");
    let count = client
        .d1_exec(
            &survivor.api,
            "snapdb",
            "SELECT COUNT(*) AS n FROM t",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    assert_eq!(
        count["rows"][0]["n"], 32,
        "all rows incl. snapshot-recovered: {count}"
    );

    for mut n in [a, b] {
        n.child.kill().ok();
        n.child.wait().ok();
    }
    c2.kill().ok();
    c2.wait().ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn two_node_deploy_kv_and_static_stability() {
    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([7u8; 32]);
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();

    // Boot A, then B seeded on A.
    let mut a = start("a", &operator, &[]);
    wait_ping(&a.api, Duration::from_secs(15)).await;
    let mut b = start("b", &operator, &[a.gossip]);
    wait_ping(&b.api, Duration::from_secs(15)).await;

    // A captured request is valid only for its intended node. The
    // original node also returns replay rejection through the same
    // encrypted response envelope expected by clients.
    let a_id = client.status(&a.api).await.unwrap()["node"]
        .as_str()
        .unwrap()
        .to_string();
    let replay_path = "/v1/kv/ns1/replay-proof";
    let replay_body = b"once";
    let replay_ts = rf::node::now_ms();
    let replay_mac = rf::auth::mac_hex(&SECRET, replay_ts, "POST", replay_path, replay_body);
    let (replay_nonce, replay_ciphertext) = rf::transport::seal(
        &SECRET,
        &rf::transport::request_aad(&replay_ts.to_string(), "POST", replay_path, &a_id),
        replay_body,
    )
    .unwrap();
    let send_capture = |api: &str| {
        http.post(format!("http://{api}{replay_path}"))
            .header(rf::auth::TS_HEADER, replay_ts.to_string())
            .header(rf::auth::MAC_HEADER, &replay_mac)
            .header(rf::transport::ENC_HEADER, rf::transport::VERSION)
            .header(rf::transport::NONCE_HEADER, &replay_nonce)
            .header(rf::transport::TARGET_HEADER, &a_id)
            .body(replay_ciphertext.clone())
            .send()
    };
    let first = send_capture(&a.api).await.unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(
        first
            .headers()
            .get(rf::transport::ENC_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some(rf::transport::VERSION)
    );
    let replay = send_capture(&a.api).await.unwrap();
    assert_eq!(replay.status(), 409);
    assert_eq!(
        replay
            .headers()
            .get(rf::transport::ENC_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some(rf::transport::VERSION)
    );
    assert_eq!(send_capture(&b.api).await.unwrap().status(), 421);

    // Deploy an assets-only worker (a pure static site) to A.
    let op_any = AnyKeypair::Ed(operator.clone());
    let bundle_dir = make_bundle("site.test");
    let bundle = rf::deploy::read_bundle(&bundle_dir).unwrap();
    let version = rf::deploy::deploy(&bundle, &client, &a.api, &op_any)
        .await
        .unwrap();
    assert_eq!(version, 1);

    // Second deploy: exercises the hash chain (prev link) and version
    // bump; then verify the transparency log end-to-end.
    std::fs::write(
        bundle_dir.join("public/index.html"),
        "<h1>hello from rf v2</h1>",
    )
    .unwrap();
    let bundle2 = rf::deploy::read_bundle(&bundle_dir).unwrap();
    let v2 = rf::deploy::deploy(&bundle2, &client, &a.api, &op_any)
        .await
        .unwrap();
    assert_eq!(v2, 2);
    let log = client.worker_log(&a.api, "site").await.unwrap();
    let chain = rf_core::manifest::verify_chain(&log, &op_any.signer_id()).expect("chain verifies");
    assert_eq!(
        chain.iter().map(|m| m.version).collect::<Vec<_>>(),
        vec![1, 2]
    );

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
        assert!(
            Instant::now() < deadline,
            "manifest/blobs never reached node B"
        );
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
    client
        .kv_put(&a.api, "ns1", "greet", b"hola".to_vec())
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(Some(v)) = client.kv_get(&b.api, "ns1", "greet").await {
            assert_eq!(v, b"hola");
            break;
        }
        assert!(Instant::now() < deadline, "kv write never reached node B");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Query-string authentication, percent-encoded namespace/key,
    // list, and tombstone paths all work through the encrypted API.
    client
        .kv_put(&a.api, "ns/special", "greet?one", b"encoded-key".to_vec())
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .kv_get(&b.api, "ns/special", "greet?one")
            .await
            .ok()
            .flatten()
            .as_deref()
            == Some(b"encoded-key")
        {
            break;
        }
        assert!(Instant::now() < deadline, "encoded kv key never converged");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        client
            .kv_list(&b.api, "ns/special", "greet?")
            .await
            .unwrap(),
        vec!["greet?one"]
    );
    client
        .kv_delete(&b.api, "ns/special", "greet?one")
        .await
        .unwrap();
    assert_eq!(
        client
            .kv_get(&b.api, "ns/special", "greet?one")
            .await
            .unwrap(),
        None
    );

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
        assert!(
            Instant::now() < deadline,
            "restarted B never served from disk"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    b2.kill().unwrap();
    b2.wait().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn tag_placement_forwards_public_ingress_to_an_eligible_peer() {
    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([47u8; 32]);
    let operator_any = AnyKeypair::Ed(operator.clone());
    let client = PeerClient::new(SECRET);
    let http = reqwest::Client::new();
    let a = start("placement-a", &operator, &[]);
    wait_ping(&a.api, Duration::from_secs(15)).await;
    let b = start("placement-b", &operator, &[a.gossip]);
    wait_ping(&b.api, Duration::from_secs(15)).await;
    wait_full_membership(&client, &[&a, &b], Duration::from_secs(20)).await;

    let b_id = client.status(&b.api).await.unwrap()["node"]
        .as_str()
        .unwrap()
        .to_string();
    let policy = rf::placement::prepare_after(
        rf::placement::NodePolicy {
            schema: rf::placement::NODE_POLICY_SCHEMA,
            node_id: b_id.clone(),
            region: "eu-west".into(),
            tags: vec!["gpu".into()],
            drain: false,
            suspended: false,
            reason: String::new(),
        },
        None,
    )
    .unwrap();
    client
        .post_resource(
            &a.api,
            &rf_core::envelope::Envelope::seal_any(&policy, &operator_any),
        )
        .await
        .unwrap();
    let policy_name = rf::placement::resource_name(&b_id).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if client
            .resource_head(&b.api, rf::placement::NODE_POLICY_KIND, &policy_name)
            .await
            .unwrap()
            .is_some()
        {
            break;
        }
        assert!(Instant::now() < deadline, "node policy did not replicate");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let bundle_dir =
        std::env::temp_dir().join(format!("rf-placement-bundle-{}", rand::random::<u32>()));
    std::fs::create_dir_all(bundle_dir.join("public")).unwrap();
    std::fs::write(
        bundle_dir.join("rf.json"),
        r#"{"name":"placed-site","assets":"public","hostnames":["placed.test"],"required_tags":["gpu","region-eu-west"]}"#,
    )
    .unwrap();
    std::fs::write(
        bundle_dir.join("public/index.html"),
        "<h1>served by the eligible node</h1>",
    )
    .unwrap();
    let bundle = rf::deploy::read_bundle(&bundle_dir).unwrap();
    rf::deploy::deploy(&bundle, &client, &a.api, &operator_any)
        .await
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let a_status = client.status(&a.api).await.unwrap_or_default();
        let b_status = client.status(&b.api).await.unwrap_or_default();
        let a_state = a_status["deployments"]["placed-site"]["state"].as_str();
        let b_state = b_status["deployments"]["placed-site"]["state"].as_str();
        let peer_state = a_status["peers"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|peer| peer["id"] == b_id)
            .and_then(|peer| peer["deployments"]["placed-site"]["state"].as_str());
        if a_state == Some("not_placed") && b_state == Some("ready") && peer_state == Some("ready")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "placement status did not converge: A={a_state:?}, B={b_state:?}, peer={peer_state:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // The request enters A, which is deliberately ineligible. A must not
    // serve its local blob copy; it forwards the request over the encrypted
    // peer API, where B verifies the exact revision and placement again.
    let response = http
        .get(format!("http://127.0.0.1:{}/", a.ingress))
        .header("host", "placed.test")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.text().await.unwrap(),
        "<h1>served by the eligible node</h1>"
    );
    std::fs::remove_dir_all(bundle_dir).ok();
}
