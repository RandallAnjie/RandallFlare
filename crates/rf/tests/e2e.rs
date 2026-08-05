//! Multi-process end-to-end tests with real `rf` binaries on loopback.
//!
//! Proves the three core properties:
//!  1. deploy-to-one is deploy-to-all (manifest gossip + blob sync)
//!  2. KV written on node A reads on node B (anti-entropy)
//!  3. static stability: node A dies, node B keeps serving

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rf::peers::PeerClient;
use rf_core::identity::{AnyKeypair, Keypair};
use sha2::Digest as _;

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
    verify_hostname(&client, &node.api, &operator_any, "admin-worker.test").await;
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
    verify_hostname(&client, &node.api, &operator_any, "flow.test").await;

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

async fn verify_hostname(client: &PeerClient, node: &str, operator: &AnyKeypair, hostname: &str) {
    let created_at_ms = rf::node::now_ms();
    let spec = rf::hostname::HostnameClaimSpec {
        hostname: hostname.to_string(),
        challenge: rf::hostname::generate_challenge(),
        created_at_ms,
        verified_at_ms: None,
    };
    let record =
        rf::hostname::prepare_claim_after(hostname, Some(spec), Some(created_at_ms), false, None)
            .unwrap();
    client
        .post_resource(
            node,
            &rf_core::envelope::Envelope::seal_any(&record, operator),
        )
        .await
        .unwrap();
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
    verify_hostname(&client, &n.api, &op_any, "api.test").await;
    verify_hostname(&client, &n.api, &op_any, "pipe.test").await;

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
            "r2":{"OUTPUTS":"pipeline-output"},
            "binaries":{"SHELL":"sandbox-shell"},
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
    if (input.holdMs) {
      return await step.do("hold-group-slot", async () => {
        await new Promise((resolve) => setTimeout(resolve, input.holdMs));
        return { held: true, label: input.label };
      });
    }
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
      await env.EVENTS.send("纯文本消息", { contentType: "text" });
      await env.EVENTS.send(new Uint8Array([0, 1, 2, 255]), { contentType: "bytes" });
      return new Response("queued");
    }
    if (url.pathname === "/queue-paused") {
      await env.EVENTS.send({ id: "paused", mode: "ack" });
      return new Response("queued while paused");
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
    if (url.pathname === "/binary") {
      const result = await env.SHELL.exec({
        args: ["-c", "read value; printf 'stdout:%s' \"$value\"; printf 'artifact:%s' \"$value\" > result.txt"],
        stdin: new TextEncoder().encode("signed-sandbox\n"),
        env: { TEST_MODE: "e2e" },
        outputFiles: [{ path: "result.txt", bucket: "OUTPUTS", key: "binary/result.txt", contentType: "text/plain" }]
      });
      return Response.json(result);
    }
    if (url.pathname === "/r2-stream") {
      const size = 2 * 1024 * 1024 + 257;
      const input = new Uint8Array(size);
      input.fill(90);
      input[0] = 17;
      input[input.length - 1] = 23;
      await env.OUTPUTS.put("native/stream.bin", input, {
        httpMetadata: { contentType: "application/octet-stream" },
        customMetadata: { source: "real-workerd" },
      });
      const head = await env.OUTPUTS.head("native/stream.bin");
      const ranged = await env.OUTPUTS.get("native/stream.bin", {
        range: { offset: 1024 * 1024 - 17, length: 4096 },
      });
      const rangeBytes = new Uint8Array(await ranged.arrayBuffer());
      const full = await env.OUTPUTS.get("native/stream.bin");
      const fullBytes = new Uint8Array(await full.arrayBuffer());
      return Response.json({
        headSize: head.size,
        headSource: head.customMetadata.source,
        contentType: head.httpMetadata.contentType,
        rangeSize: rangeBytes.length,
        rangeFirst: rangeBytes[0],
        fullSize: fullBytes.length,
        fullFirst: fullBytes[0],
        fullLast: fullBytes[fullBytes.length - 1],
      });
    }
    if (url.pathname === "/secret") return new Response(env.API_TOKEN);
    if (url.pathname === "/workflow-trigger") {
      const instance = await env.ORDER_WORKFLOW.create({
        id: "order-e2e",
        concurrencyGroup: "customer:RF-1001",
        params: { orderId: "RF-1001" }
      });
      return Response.json({ id: instance.id, status: await instance.status() });
    }
    return new Response("module worker up");
  },
  async queue(batch, env, context) {
    for (const message of batch.messages) {
      if (message.body instanceof Uint8Array) {
        context.waitUntil(env.CACHE.put(
          "queue-bytes",
          JSON.stringify(Array.from(message.body)),
        ));
        continue;
      }
      if (typeof message.body === "string") {
        context.waitUntil(env.CACHE.put("queue-text", message.body));
        continue;
      }
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
            storage_policy: None,
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
    let email_record = rf::email::prepare_email_domain_after(
        "mail-e2e",
        rf::email::EmailDomainSpec {
            description: "SMTPUTF8 与耐久 DSN 端到端验证".into(),
            domain: "mail.test".into(),
            verification_challenge: "email-e2e-verification".into(),
            mx_hostname: "mx.mail.test".into(),
            bucket: "pipeline-output".into(),
            object_prefix: "mail-e2e".into(),
            routes: vec![rf::email::EmailRoute {
                id: "catch-all".into(),
                priority: 100,
                enabled: true,
                matcher: rf::email::EmailMatcher::CatchAll,
                destination: rf::email::EmailDestination::Drop,
            }],
            max_message_bytes: 1024 * 1024,
            inbound_per_minute: 100,
            outbound_per_minute: 100,
            retention_days: 30,
            dkim_selector: "rf".into(),
            dkim_public_key: "v=DKIM1; k=rsa; p=e2e-public-key".into(),
            dkim_private_key_env: "RF_EMAIL_DKIM_E2E".into(),
            suspended: false,
            suspend_reason: String::new(),
        },
        false,
        None,
    )
    .unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&email_record, &op_any),
        )
        .await
        .unwrap();
    let posted_email = client
        .resource_head(&n.api, rf::email::EMAIL_DOMAIN_KIND, "mail-e2e")
        .await
        .unwrap()
        .expect("email resource must be visible immediately after signed ingest");
    rf::email::email_domain_spec(&posted_email.resource).unwrap();
    let shell_bytes = std::fs::read("/bin/sh").unwrap();
    let (shell_sha256, shell_size, shell_storage) = client
        .binary_put_blob(
            &n.api,
            &shell_bytes,
            &rf::objectstore::StorageLocation::Local,
        )
        .await
        .unwrap();
    let binary_record = rf::binary::prepare_after(
        "sandbox-shell",
        rf::binary::BinarySpec {
            schema: rf::binary::BINARY_SCHEMA,
            description: "真实 workerd Binary binding".into(),
            sha256: shell_sha256,
            size_bytes: shell_size,
            storage: shell_storage,
            os_arch: rf::binary::current_os_arch().into(),
            default_timeout_ms: 5_000,
            max_stdin_bytes: 1024,
            max_output_bytes: 4096,
            allow_network: false,
            allow_r2: true,
            required_tags: Vec::new(),
            suspended: false,
        },
        false,
        None,
    )
    .unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&binary_record, &op_any),
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
            transform_sql: Some(
                "INSERT INTO archive SELECT kind, sequence * 10 AS sequence FROM events WHERE sequence >= 2"
                    .into(),
            ),
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
    let (workflow_token, workflow_plaintext) =
        rf::workflow::mint_token("module worker e2e").unwrap();
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
            webhook_enabled: true,
            tokens: vec![workflow_token],
            ..Default::default()
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
    let binary_response: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/binary", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(binary_response["ok"], true);
    assert_eq!(binary_response["exitCode"], 0);
    assert_eq!(binary_response["stdout"], "stdout:signed-sandbox");
    assert_eq!(binary_response["uploads"][0]["key"], "binary/result.txt");
    assert!(binary_response["uploads"][0]["error"].is_null());
    let r2_stream_response: serde_json::Value = http
        .get(format!("http://127.0.0.1:{}/r2-stream", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r2_stream_response["headSize"], 2 * 1024 * 1024 + 257);
    assert_eq!(r2_stream_response["headSource"], "real-workerd");
    assert_eq!(
        r2_stream_response["contentType"],
        "application/octet-stream"
    );
    assert_eq!(r2_stream_response["rangeSize"], 4096);
    assert_eq!(r2_stream_response["rangeFirst"], 90);
    assert_eq!(r2_stream_response["fullSize"], 2 * 1024 * 1024 + 257);
    assert_eq!(r2_stream_response["fullFirst"], 17);
    assert_eq!(r2_stream_response["fullLast"], 23);
    let (_, binary_output) = client
        .r2_get(&n.api, "pipeline-output", "binary/result.txt")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(binary_output, b"artifact:signed-sandbox");
    let binary_head = client
        .resource_head(&n.api, rf::binary::BINARY_KIND, "sandbox-shell")
        .await
        .unwrap()
        .unwrap();
    let binary_tombstone = rf::binary::prepare_after(
        "sandbox-shell",
        rf::binary::binary_spec(&binary_head.resource).unwrap(),
        true,
        Some(&binary_head),
    )
    .unwrap();
    let delete_error = client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&binary_tombstone, &op_any),
        )
        .await
        .unwrap_err();
    assert!(format!("{delete_error:#}").contains("仍被 Worker 绑定"));
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
    assert_eq!(
        http.post(format!("http://127.0.0.1:{}/hook", n.ingress))
            .header("host", "workflow-order-flow.workers.test")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let webhook_trigger: serde_json::Value = http
        .post(format!("http://127.0.0.1:{}/hook", n.ingress))
        .header("host", "workflow-order-flow.workers.test")
        .bearer_auth(&workflow_plaintext)
        .header("idempotency-key", "order-e2e")
        .json(&serde_json::json!({ "orderId": "ignored-by-idempotency" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(webhook_trigger["id"], workflow_instance);
    let grouped_a = client
        .workflow_create(
            &n.api,
            "order-flow",
            Some("grouped-a"),
            Some("customer:serial"),
            serde_json::json!({ "holdMs": 1_500, "label": "a" }),
        )
        .await
        .unwrap();
    let grouped_b = client
        .workflow_create(
            &n.api,
            "order-flow",
            Some("grouped-b"),
            Some("customer:serial"),
            serde_json::json!({ "holdMs": 1_500, "label": "b" }),
        )
        .await
        .unwrap();
    assert_eq!(
        grouped_a.concurrency_group.as_deref(),
        Some("customer:serial")
    );
    assert_eq!(grouped_a.concurrency_group_limit, 1);
    let grouped_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let a = client
            .workflow_instance(&n.api, "order-flow", &grouped_a.id)
            .await
            .unwrap();
        let b = client
            .workflow_instance(&n.api, "order-flow", &grouped_b.id)
            .await
            .unwrap();
        let statuses = [
            a["instance"]["status"].as_str(),
            b["instance"]["status"].as_str(),
        ];
        if statuses.contains(&Some("running")) {
            assert!(
                statuses.contains(&Some("queued")),
                "same named group must keep the second instance queued: {statuses:?}"
            );
            break;
        }
        assert!(
            Instant::now() < grouped_deadline,
            "named concurrency group never entered a running/queued state: {statuses:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let detail = client
            .workflow_instance(&n.api, "order-flow", &workflow_instance)
            .await
            .unwrap();
        if detail["instance"]["status"] == "waiting" && detail["instance"]["waiting_for"] == "paid"
        {
            assert_eq!(detail["instance"]["definition_version"], 1);
            assert_eq!(detail["instance"]["entrypoint"], "OrderWorkflow");
            assert_eq!(detail["instance"]["instance_retries"], 3);
            assert_eq!(detail["instance"]["instance_timeout_seconds"], 120);
            assert_eq!(detail["instance"]["concurrency_group"], "customer:RF-1001");
            assert_eq!(detail["instance"]["concurrency_group_limit"], 1);
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
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["kind"], "worker");
            assert_eq!(events[0]["sequence"], 20);
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
    let pipeline_chunks = [
        Ok::<_, std::io::Error>("{\"kind\":\"public\","),
        Ok("\"sequence\":3}\n{\"kind\":"),
        Ok("\"public\",\"sequence\":4}\n"),
    ];
    let public_ingest: serde_json::Value = http
        .post(format!("http://127.0.0.1:{}/send", n.ingress))
        .header("host", "pipe.test")
        .bearer_auth(&pipeline_plaintext)
        .header("content-type", "application/x-ndjson")
        .body(reqwest::Body::wrap_stream(futures_util::stream::iter(
            pipeline_chunks,
        )))
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
    let d1_backup = client
        .d1_backup(&n.api, "worker-db", "pipeline-output", "d1-e2e")
        .await
        .unwrap();
    assert_eq!(d1_backup.database, "worker-db");
    assert_eq!(d1_backup.bucket, "pipeline-output");
    let (_, backup_bytes) = client
        .r2_get(&n.api, "pipeline-output", &d1_backup.object_key)
        .await
        .unwrap()
        .unwrap();
    assert!(backup_bytes.starts_with(b"SQLite format 3\0"));
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&backup_bytes)),
        d1_backup.sha256
    );
    let backup_path = n._dir.join("worker-db-backup.sqlite");
    std::fs::write(&backup_path, backup_bytes).unwrap();
    let backup_db = rusqlite::Connection::open(&backup_path).unwrap();
    let backed_up_name: String = backup_db
        .query_row("SELECT name FROM users WHERE id=1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(backed_up_name, "安杰");
    drop(backup_db);
    std::fs::remove_file(backup_path).unwrap();
    let audit = client
        .data_audit_cluster(&n.api, None, 1_000)
        .await
        .unwrap();
    assert!(audit
        .entries
        .iter()
        .any(|entry| entry.kind == "kv_put" && entry.resource == "ns1"));
    assert!(audit.entries.iter().any(|entry| {
        entry.kind == "d1_commit" && entry.resource == "worker-db" && entry.sequence.is_some()
    }));
    let audit_archive = client
        .data_audit_archive(&n.api, "pipeline-output", "audit-e2e", None)
        .await
        .unwrap();
    assert!(audit_archive.entries >= 2);
    let (_, compressed_audit) = client
        .r2_get(&n.api, "pipeline-output", &audit_archive.object_key)
        .await
        .unwrap()
        .unwrap();
    let mut archived_jsonl = String::new();
    flate2::read::GzDecoder::new(compressed_audit.as_slice())
        .read_to_string(&mut archived_jsonl)
        .unwrap();
    assert!(archived_jsonl
        .lines()
        .all(|line| { serde_json::from_str::<rf::data_audit::DataMutationAudit>(line).is_ok() }));
    assert!(!archived_jsonl.contains("written-by-worker"));
    assert!(!archived_jsonl.contains("INSERT INTO users"));
    assert!(client
        .email_verification(&n.api, "mail-e2e")
        .await
        .unwrap()
        .is_none());
    let email_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    client
        .d1_exec(
            &n.api,
            &rf::email::database_name("mail-e2e"),
            r#"INSERT INTO email_verification
               (singleton,domain,ownership_ok,mx_ok,dkim_ok,spf_present,verified,
                ownership_json,mx_json,dkim_json,spf_json,checked_at_ms,error)
               VALUES(1,'mail.test',1,1,1,1,1,'[]','[]','[]','[]',?1,NULL)"#,
            serde_json::json!([email_now]),
        )
        .await
        .unwrap();
    let outbound_raw = "From: 张三 <张三@mail.test>\r\nTo: 客户 <客户@example.net>\r\nSubject: SMTPUTF8 delivery\r\nMessage-ID: <smtp-utf8-e2e@mail.test>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n测试国际化信封地址。\r\n";
    let queued = client
        .email_send(
            &n.api,
            "mail-e2e",
            &rf::email::EmailSendMetadata {
                mail_from: "张三@MAIL.TEST".into(),
                recipients: vec!["客户@EXAMPLE.NET".into()],
            },
            outbound_raw.as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(queued.len(), 1);
    let outbound_id = queued[0].id.clone();
    client
        .d1_exec(
            &n.api,
            &rf::email::database_name("mail-e2e"),
            r#"UPDATE email_messages SET status='failed',attempts=5,
               last_error='550 5.1.1 用户不存在',dsn_status='pending',
               dsn_next_attempt_ms=0,updated_at_ms=?2 WHERE id=?1"#,
            serde_json::json!([outbound_id, email_now]),
        )
        .await
        .unwrap();
    assert!(client.email_process_dsn(&n.api, "mail-e2e").await.unwrap());
    let failed = client
        .email_message(&n.api, "mail-e2e", &outbound_id)
        .await
        .unwrap();
    assert_eq!(failed.dsn_status.as_deref(), Some("generated"));
    assert_eq!(failed.dsn_attempts, 1);
    let dsn_id = failed.dsn_message_id.unwrap();
    let dsn = client
        .email_message(&n.api, "mail-e2e", &dsn_id)
        .await
        .unwrap();
    assert_eq!(dsn.direction, "inbound");
    assert_eq!(dsn.mail_from, "");
    assert_eq!(dsn.rcpt_to, "张三@mail.test");
    let dsn_raw = client
        .email_message_raw(&n.api, "mail-e2e", &dsn_id)
        .await
        .unwrap();
    let dsn_text = String::from_utf8(dsn_raw).unwrap();
    assert!(dsn_text.contains("Auto-Submitted: auto-replied"));
    assert!(dsn_text.contains("Final-Recipient: utf-8; 客户@example.net"));
    assert!(dsn_text.contains("report-type=global-delivery-status"));
    assert!(dsn_text.contains("Status: 5.1.1"));
    assert!(dsn_text.contains("Diagnostic-Code: X-RandallFlare; 550 5.1.1 用户不存在"));
    assert!(!client.email_process_dsn(&n.api, "mail-e2e").await.unwrap());
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
            let query = client
                .analytics_query(
                    &n.api,
                    "web-metrics",
                    "SELECT blob1, COUNT(*) AS events, SUM(double1 * _sample_interval) AS total FROM events WHERE double1 > ?1 GROUP BY blob1",
                    vec![serde_json::json!(40)],
                    100,
                )
                .await
                .unwrap();
            assert_eq!(query.row_count, 1);
            assert_eq!(query.rows[0]["blob1"], "pageview");
            assert_eq!(query.rows[0]["events"], 1);
            assert_eq!(query.rows[0]["total"], 42.5);
            assert!(!query.truncated);
            let truncated = client
                .analytics_query(
                    &n.api,
                    "web-metrics",
                    "SELECT blob1 FROM events UNION ALL SELECT blob1 FROM events",
                    vec![],
                    1,
                )
                .await
                .unwrap();
            assert_eq!(truncated.row_count, 1);
            assert!(truncated.truncated);
            assert!(client
                .analytics_query(
                    &n.api,
                    "web-metrics",
                    "DELETE FROM analytics_events",
                    vec![],
                    100,
                )
                .await
                .is_err());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Analytics Worker binding did not persist its waitUntil write"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Suspending a queue pauses delivery but deliberately keeps producers
    // available, so upstream Workers do not fail while an operator drains a
    // consumer. Resume must deliver the durably staged message.
    let queue_head = client
        .resource_head(&n.api, rf::queue::QUEUE_KIND, "events")
        .await
        .unwrap()
        .unwrap();
    let mut queue_spec = rf::queue::queue_spec(&queue_head.resource).unwrap();
    queue_spec.suspended = true;
    let suspended =
        rf::queue::prepare_queue_after("events", queue_spec.clone(), false, Some(&queue_head))
            .unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&suspended, &op_any),
        )
        .await
        .unwrap();
    let paused = http
        .get(format!("http://127.0.0.1:{}/queue-paused", n.ingress))
        .header("host", "api.test")
        .send()
        .await
        .unwrap();
    assert_eq!(paused.text().await.unwrap(), "queued while paused");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if client.queue_stats(&n.api, "events").await.unwrap().ready >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "paused queue did not accept producer write"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(client
        .kv_get(&n.api, "ns1", "queue-paused")
        .await
        .unwrap()
        .is_none());
    queue_spec.suspended = false;
    let suspended_head = client
        .resource_head(&n.api, rf::queue::QUEUE_KIND, "events")
        .await
        .unwrap()
        .unwrap();
    let resumed =
        rf::queue::prepare_queue_after("events", queue_spec, false, Some(&suspended_head)).unwrap();
    client
        .post_resource(
            &n.api,
            &rf_core::envelope::Envelope::seal_any(&resumed, &op_any),
        )
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if client
            .kv_get(&n.api, "ns1", "queue-paused")
            .await
            .unwrap()
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "resumed queue did not deliver staged message"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
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
        let text = client.kv_get(&n.api, "ns1", "queue-text").await.unwrap();
        let bytes = client.kv_get(&n.api, "ns1", "queue-bytes").await.unwrap();
        let dead = client
            .queue_dead_letters(&n.api, "events", 10)
            .await
            .unwrap_or_default();
        if let (Some(ack), Some(retry), Some(text), Some(bytes), Some(dead_message)) = (
            ack,
            retry,
            text,
            bytes,
            dead.iter().find(|item| item.body["id"] == "dead"),
        ) {
            let ack: serde_json::Value = serde_json::from_slice(&ack).unwrap();
            let retry: serde_json::Value = serde_json::from_slice(&retry).unwrap();
            assert_eq!(ack["attempts"], 1);
            assert_eq!(ack["queue"], "events");
            assert_eq!(retry["attempts"], 2);
            assert_eq!(text, "纯文本消息".as_bytes());
            assert_eq!(bytes, b"[0,1,2,255]");
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
struct TestWebSocket {
    stream: std::net::TcpStream,
}

impl TestWebSocket {
    fn connect(address: std::net::SocketAddr, host: &str, path: &str) -> Self {
        let mut stream =
            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            response.push(byte[0]);
            assert!(response.len() <= 16 * 1024, "WebSocket response too large");
        }
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 101 "),
            "WebSocket handshake failed: {response}"
        );
        assert!(response.to_ascii_lowercase().contains("upgrade: websocket"));
        Self { stream }
    }

    fn send_text(&mut self, text: &str) {
        let bytes = text.as_bytes();
        assert!(bytes.len() < 126);
        let mask = [0x12, 0x34, 0x56, 0x78];
        let mut frame = vec![0x81, 0x80 | bytes.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend(
            bytes
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        self.stream.write_all(&frame).unwrap();
        self.stream.flush().unwrap();
    }

    fn read_text(&mut self) -> String {
        loop {
            let mut header = [0u8; 2];
            self.stream.read_exact(&mut header).unwrap();
            let opcode = header[0] & 0x0f;
            let masked = header[1] & 0x80 != 0;
            let mut length = u64::from(header[1] & 0x7f);
            if length == 126 {
                let mut extended = [0u8; 2];
                self.stream.read_exact(&mut extended).unwrap();
                length = u64::from(u16::from_be_bytes(extended));
            } else if length == 127 {
                let mut extended = [0u8; 8];
                self.stream.read_exact(&mut extended).unwrap();
                length = u64::from_be_bytes(extended);
            }
            assert!(length <= 1024 * 1024, "WebSocket test frame too large");
            let mut mask = [0u8; 4];
            if masked {
                self.stream.read_exact(&mut mask).unwrap();
            }
            let mut payload = vec![0u8; length as usize];
            self.stream.read_exact(&mut payload).unwrap();
            if masked {
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[index % mask.len()];
                }
            }
            match opcode {
                0x1 => return String::from_utf8(payload).unwrap(),
                0x9 => {
                    assert!(payload.len() < 126);
                    let mut pong = vec![0x8a, 0x80 | payload.len() as u8];
                    let pong_mask = [0x9a, 0xbc, 0xde, 0xf0];
                    pong.extend_from_slice(&pong_mask);
                    pong.extend(
                        payload
                            .iter()
                            .enumerate()
                            .map(|(index, byte)| byte ^ pong_mask[index % pong_mask.len()]),
                    );
                    self.stream.write_all(&pong).unwrap();
                    self.stream.flush().unwrap();
                }
                other => panic!("unexpected WebSocket opcode {other}"),
            }
        }
    }

    fn close(mut self) {
        self.stream
            .write_all(&[0x88, 0x82, 1, 2, 3, 4, 0x03 ^ 1, 0xe8 ^ 2])
            .ok();
        self.stream.flush().ok();
    }
}

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
    verify_hostname(&client, &api_addr, &op_any, "counter.test").await;

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
  async fetch(req) {
    const path = new URL(req.url).pathname;
    if (path === "/schedule") {
      await this.ctx.storage.setAlarm(Date.now() + 1500);
      return new Response("scheduled");
    }
    if (path === "/alarm") {
      const done = await this.ctx.storage.get("alarmDone");
      return new Response(done ? JSON.stringify(done) : "pending", { status: done ? 200 : 202 });
    }
    const old = (await this.ctx.storage.get("count")) || 0;
    const value = old + 1;
    await this.ctx.storage.put("count", value);
    return new Response(String(value));
  }
  async alarm(info) {
    if ((info?.retryCount || 0) < 2) throw new Error("exercise alarm retry");
    await this.ctx.storage.put("alarmDone", {
      retryCount: info.retryCount,
      isRetry: info.isRetry
    });
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

    let call = |path: &str| {
        http.get(format!("http://127.0.0.1:{ingress}{path}"))
            .header("host", "counter.test")
            .send()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = call("/").await {
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
    assert_eq!(call("/").await.unwrap().text().await.unwrap(), "2");
    assert_eq!(
        call("/schedule").await.unwrap().text().await.unwrap(),
        "scheduled"
    );

    // Restart before the alarm is due. The native workerd alarm row must be
    // part of the quorum snapshot and retain Cloudflare retry metadata.
    child.kill().unwrap();
    child.wait().unwrap();
    let mut child = spawn_node(&dir, &config);
    wait_ping(&api_addr, Duration::from_secs(15)).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let alarm_info = loop {
        if let Ok(resp) = call("/alarm").await {
            if resp.status() == 200 {
                break resp.json::<serde_json::Value>().await.unwrap();
            }
        }
        assert!(
            Instant::now() < deadline,
            "Durable Object alarm did not recover and exhaust its retries after restart"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    assert_eq!(alarm_info["retryCount"], 2);
    assert_eq!(alarm_info["isRetry"], true);
    assert_eq!(call("/").await.unwrap().text().await.unwrap(), "3");
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
    verify_hostname(&client, &a.api, &op_any, "global-counter.test").await;

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
	    if (path === "/ws") {
	      const pair = new WebSocketPair();
	      const [client, server] = Object.values(pair);
	      this.ctx.acceptWebSocket(server, ["counter"]);
	      server.serializeAttachment({ kind: "counter" });
	      return new Response(null, { status: 101, webSocket: client });
	    }
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
	  async webSocketMessage(ws, message) {
	    if (String(message) !== "inc") {
	      ws.send("unsupported");
	      return;
	    }
	    let value = (await this.ctx.storage.get("count")) || 0;
	    value++;
	    await this.ctx.storage.put("count", value);
	    ws.send(String(value));
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

    // Connect through a node that does not own this Worker. The public 101
    // and all later WebSocket frames must traverse the authenticated,
    // encrypted owner tunnel while workerd runs the native hibernation API.
    let nodes_before_failure = [&a, &b, &c];
    let mut owner_before_failure = None;
    for (index, node) in nodes_before_failure.iter().enumerate() {
        let status = client.status(&node.api).await.unwrap();
        if status["workers"].as_array().unwrap().iter().any(|worker| {
            worker["name"] == "global-counter" && worker["durable_owned_here"] == true
        }) {
            owner_before_failure = Some(index);
            break;
        }
    }
    let owner_before_failure = owner_before_failure.expect("one node reports itself as DO owner");
    let websocket_ingress = nodes_before_failure[(owner_before_failure + 1) % 3].ingress;
    let mut websocket = TestWebSocket::connect(
        format!("127.0.0.1:{websocket_ingress}").parse().unwrap(),
        "global-counter.test",
        "/ws",
    );
    websocket.send_text("inc");
    assert_eq!(websocket.read_text(), "4");
    websocket.close();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The response is committed before this waitUntil mutation runs.
    // No later request reaches the object before the owner dies, so
    // recovery of 14 proves the periodic background checkpointer
    // replicated state changed by alarms/WebSockets/waitUntil work.
    let response = call(b.ingress, "/background").await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "scheduled");
    // The background mutation waits one second and the checkpoint loop runs
    // once per second. Allow several additional ticks on loaded CI hosts
    // without issuing another Worker request that could mask this guarantee.
    tokio::time::sleep(Duration::from_secs(10)).await;

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
                assert_eq!(resp.text().await.unwrap(), "14");
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "DO did not fail over with committed state"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let mut websocket = TestWebSocket::connect(
        format!("127.0.0.1:{}", nodes[survivor_idx].ingress)
            .parse()
            .unwrap(),
        "global-counter.test",
        "/ws",
    );
    websocket.send_text("inc");
    assert_eq!(websocket.read_text(), "15");
    websocket.close();
    let response = call(nodes[survivor_idx].ingress, "/inc").await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "16");

    for mut node in nodes {
        node.child.kill().ok();
        node.child.wait().ok();
    }
}

fn smtp_response<S: Read>(reader: &mut BufReader<S>) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(
            !line.is_empty(),
            "SMTP connection closed before a complete response"
        );
        let terminal = line.as_bytes().get(3) == Some(&b' ');
        lines.push(line.trim_end().to_string());
        if terminal {
            return lines;
        }
    }
}

fn smtp_command<S: Read + Write>(reader: &mut BufReader<S>, command: &str) -> Vec<String> {
    reader.get_mut().write_all(command.as_bytes()).unwrap();
    reader.get_mut().flush().unwrap();
    smtp_response(reader)
}

fn smtp_capabilities(address: std::net::SocketAddr) -> Vec<String> {
    let stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    assert!(smtp_response(&mut reader)[0].starts_with("220 "));
    smtp_command(&mut reader, "EHLO client.test\r\n")
}

fn smtp_starttls(
    address: std::net::SocketAddr,
    hostname: &'static str,
    trusted: rustls_pki_types::CertificateDer<'static>,
) {
    let stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    smtp_response(&mut reader);
    let capabilities = smtp_command(&mut reader, "EHLO client.test\r\n");
    assert!(capabilities.iter().any(|line| line.contains("STARTTLS")));
    assert!(smtp_command(&mut reader, "STARTTLS\r\n")[0].starts_with("220 "));

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trusted).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls_pki_types::ServerName::try_from(hostname).unwrap();
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), name).unwrap();
    let mut reader = BufReader::new(rustls::StreamOwned::new(connection, reader.into_inner()));
    let response = smtp_command(&mut reader, "EHLO tls-client.test\r\n");
    assert!(response[0].starts_with("250-"));
    smtp_command(&mut reader, "QUIT\r\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_starttls_materializes_and_rotates_without_restart() {
    let _scenario = E2E_LOCK.lock().await;
    let operator = Keypair::from_seed([57u8; 32]);
    let dir =
        std::env::temp_dir().join(format!("rf-e2e-smtp-hot-reload-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (gossip, api, ingress, smtp) = (free_port(), free_port(), free_port(), free_port());
    let config = write_config(
        &dir,
        &operator,
        gossip,
        api,
        ingress,
        &[],
        "smtp-hot-reload",
    );
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "\n[email]\nenabled = true\nsmtp_listen = \"127.0.0.1:{smtp}\"\nmx_hostname = \"mx.test\"\noutbound = false\n"
    ));
    std::fs::write(&config, text).unwrap();
    let mut child = spawn_node(&dir, &config);
    wait_ping(&format!("127.0.0.1:{api}"), Duration::from_secs(15)).await;
    let smtp_address = format!("127.0.0.1:{smtp}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect_timeout(&smtp_address, Duration::from_millis(200)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "SMTP listener did not start");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let initial = smtp_capabilities(smtp_address);
    assert!(!initial.iter().any(|line| line.contains("STARTTLS")));

    let certs = dir.join("data").join("certs");
    std::fs::create_dir_all(&certs).unwrap();
    let first = rcgen::generate_simple_self_signed(vec!["mx.test".to_string()]).unwrap();
    std::fs::write(certs.join("mx.test.crt"), first.cert.pem()).unwrap();
    std::fs::write(certs.join("mx.test.key"), first.signing_key.serialize_pem()).unwrap();
    smtp_starttls(smtp_address, "mx.test", first.cert.der().clone());

    let second = rcgen::generate_simple_self_signed(vec!["mx.test".to_string()]).unwrap();
    std::fs::write(certs.join("mx.test.crt"), second.cert.pem()).unwrap();
    std::fs::write(
        certs.join("mx.test.key"),
        second.signing_key.serialize_pem(),
    )
    .unwrap();
    smtp_starttls(smtp_address, "mx.test", second.cert.der().clone());

    child.kill().unwrap();
    child.wait().unwrap();
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
    verify_hostname(&client, &format!("127.0.0.1:{api}"), &op_any, "tls.test").await;

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
    let failed_batch = client
        .d1_batch(
            &a.api,
            "appdb",
            &[
                rf::d1::Statement {
                    sql: "INSERT INTO t (id, v) VALUES (99, 'must-roll-back')".into(),
                    params: vec![],
                },
                rf::d1::Statement {
                    sql: "INSERT INTO t (id, v) VALUES (1, 'duplicate')".into(),
                    params: vec![],
                },
            ],
        )
        .await;
    assert!(
        failed_batch.is_err(),
        "constraint failure must reject the batch"
    );
    let rolled_back = client
        .d1_exec(
            &b.api,
            "appdb",
            "SELECT COUNT(*) AS n FROM t WHERE id = 99",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    assert_eq!(rolled_back["rows"][0]["n"], 0);

    let committed_batch = client
        .d1_batch(
            &c.api,
            "appdb",
            &[
                rf::d1::Statement {
                    sql: "INSERT INTO t (v) VALUES (?1)".into(),
                    params: vec![serde_json::json!("batch-three")],
                },
                rf::d1::Statement {
                    sql: "SELECT COUNT(*) AS n FROM t".into(),
                    params: vec![],
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(committed_batch["batch"][0]["rows_affected"], 1);
    assert_eq!(committed_batch["batch"][1]["rows"][0]["n"], 3);

    let snapshot = client.d1_export(&b.api, "appdb").await.unwrap();
    assert!(snapshot.starts_with(b"SQLite format 3\0"));
    let snapshot_path = std::env::temp_dir().join(format!(
        "rf-e2e-d1-export-{}-{}.sqlite",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&snapshot_path, snapshot).unwrap();
    let exported = rusqlite::Connection::open(&snapshot_path).unwrap();
    let exported_rows: i64 = exported
        .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(exported_rows, 3);
    let marker: i64 = exported
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = '_rf_applied'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, 0, "portable export must omit the Raft marker");
    drop(exported);
    std::fs::remove_file(snapshot_path).unwrap();
    let cte = client
        .d1_exec(
            &b.api,
            "appdb",
            "WITH total(n) AS (SELECT COUNT(*) FROM t) SELECT n FROM total",
            serde_json::json!([]),
        )
        .await
        .unwrap();
    assert_eq!(cte["rows"][0]["n"], 3, "CTE reads stay read-only: {cte}");
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
        count["rows"][0]["n"], 4,
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
    wait_full_membership(&client, &[&a, &b], Duration::from_secs(20)).await;

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
    verify_hostname(&client, &a.api, &op_any, "site.test").await;
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

    // A local R2 replica removed from A is repaired from B through the
    // sequence-bound encrypted object stream, then served without buffering
    // the multi-frame response in ingress.
    let bucket_record = rf::resource::prepare_after(
        rf::r2::BUCKET_KIND,
        "repair-stream",
        serde_json::to_value(rf::r2::BucketSpec {
            description: "跨节点流式修复".into(),
            public_access: true,
            storage: rf::objectstore::StorageLocation::Local,
            storage_policy: None,
            max_bytes: Some(8 * 1024 * 1024),
            max_objects: Some(10),
            expire_objects_after_days: None,
            cors_origins: Vec::new(),
            hostnames: Vec::new(),
        })
        .unwrap(),
        false,
        None,
    )
    .unwrap();
    client
        .post_resource(
            &a.api,
            &rf_core::envelope::Envelope::seal_any(&bucket_record, &op_any),
        )
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .resource_head(&b.api, rf::r2::BUCKET_KIND, "repair-stream")
            .await
            .ok()
            .flatten()
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "R2 bucket resource never converged to node B"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let repair_bytes = vec![0x39u8; 2 * 1024 * 1024 + 333];
    let repair_metadata = client
        .r2_put(
            &a.api,
            "repair-stream",
            "large.bin",
            &repair_bytes,
            &rf::r2::PutOptions::default(),
        )
        .await
        .unwrap();
    let local_replica = a
        ._dir
        .join("data/objects")
        .join(&repair_metadata.sha256[..2])
        .join(&repair_metadata.sha256);
    std::fs::remove_file(&local_replica).unwrap();
    let repaired = http
        .get(format!("http://127.0.0.1:{}/large.bin", a.ingress))
        .header("host", "r2-repair-stream.workers.test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(repaired.as_ref(), repair_bytes);
    assert!(
        local_replica.is_file(),
        "node A did not retain repaired replica"
    );

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
    let expires_at_ms = rf::node::now_ms() + 3_600_000;
    client
        .kv_put_with_metadata(
            &a.api,
            "ns/special",
            "greet?one",
            b"encoded-key".to_vec(),
            Some(expires_at_ms),
            Some(&serde_json::json!({"source": "e2e"})),
        )
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let rich = loop {
        if let Ok(Some(rich)) = client
            .kv_get_with_metadata(&b.api, "ns/special", "greet?one")
            .await
        {
            if rich.metadata == Some(serde_json::json!({"source": "e2e"}))
                && rich.expires_at_ms == Some(expires_at_ms)
            {
                break rich;
            }
        }
        assert!(
            Instant::now() < deadline,
            "encoded KV value and metadata never converged"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        client
            .kv_list(&b.api, "ns/special", "greet?")
            .await
            .unwrap(),
        vec!["greet?one"]
    );
    use base64::Engine as _;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(rich.value_base64)
            .unwrap(),
        b"encoded-key"
    );
    assert_eq!(rich.metadata, Some(serde_json::json!({"source": "e2e"})));
    assert_eq!(rich.expires_at_ms, Some(expires_at_ms));

    client
        .kv_put(&a.api, "ns/special", "greet?two", b"page-two".to_vec())
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let page = client
            .kv_list_page(&b.api, "ns/special", "greet?", None, 10)
            .await
            .unwrap();
        if page.entries.len() == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "paged KV listing never converged"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let first = client
        .kv_list_page(&b.api, "ns/special", "greet?", None, 1)
        .await
        .unwrap();
    assert!(!first.list_complete);
    let second = client
        .kv_list_page(&b.api, "ns/special", "greet?", first.cursor.as_deref(), 1)
        .await
        .unwrap();
    assert_eq!(second.entries[0].key, "greet?two");
    assert!(second.list_complete);
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
    verify_hostname(&client, &a.api, &operator_any, "placed.test").await;

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
