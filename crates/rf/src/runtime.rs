//! workerd runtime manager: turns live module-worker manifests into
//! supervised workerd child processes, one per worker, listening on
//! loopback ports that ingress proxies to.
//!
//! Per worker+version we materialize a directory:
//!   <data>/workers/<name>/<version>/
//!     config.capnp       generated workerd config
//!     src/<module paths> module files copied out of the blob store
//!
//! Version bump → new dir, new process, old one killed after the new
//! socket answers. workerd absent → workers are marked unavailable
//! (ingress still serves asset trees natively; the static-site
//! serving path never needs workerd).
//!
//! KV bindings are native workerd `kvNamespace` bindings: each one
//! points at an external service → the node's loopback kvbind server,
//! with the namespace id attached via injectRequestHeaders. Protocol
//! verified against workerd 2026-08-04 (see kvbind.rs).

use crate::node::{Node, NodeEvent};
use anyhow::{Context, Result};
use rf_core::manifest::{ModuleKind, WorkerManifest};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use zeroize::Zeroize;

pub struct Runtime {
    node: Arc<Node>,
    durable: crate::durable::Coordinator,
    workerd: Option<PathBuf>,
    port_base: u16,
    running: HashMap<String, RunningWorker>,
}

struct RunningWorker {
    version: u64,
    port: u16,
    child: Option<Child>,
}

/// Where ingress should send traffic for a module worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerPort(pub u16);

impl Runtime {
    pub fn new(node: Arc<Node>, durable: crate::durable::Coordinator) -> Self {
        let workerd = node.cfg.runtime.workerd.clone().or_else(find_workerd);
        if workerd.is_none() {
            tracing::warn!("未找到 workerd 可执行文件——模块 Worker 已停用，静态资源仍可提供服务");
        }
        let port_base = node.cfg.runtime.port_base;
        Self {
            node,
            durable,
            workerd,
            port_base,
            running: HashMap::new(),
        }
    }

    /// Long-running reconcile loop.
    pub async fn run(mut self) {
        let mut rx = self.node.subscribe();
        // Initial reconcile at boot.
        self.reconcile().await;
        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(NodeEvent::Manifests) => self.reconcile().await,
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return,
                },
                // Re-check periodically: blobs may have arrived, or a
                // child may have died.
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                    self.reap();
                    self.reconcile().await;
                }
            }
        }
    }

    fn reap(&mut self) {
        for (name, rw) in self.running.iter_mut() {
            if let Some(child) = &mut rw.child {
                if let Ok(Some(status)) = child.try_wait() {
                    tracing::warn!("Worker {name} 的 workerd 已退出：{status}");
                    self.node.set_runtime_status(
                        name,
                        rw.version,
                        "failed",
                        format!("workerd 已退出：{status}"),
                    );
                    self.node.append_runtime_log(
                        name,
                        rw.version,
                        "system",
                        &format!("workerd 已退出：{status}"),
                    );
                    rw.child = None;
                    self.node.remove_worker_event_token(name);
                }
            }
        }
    }

    /// Port registry published for ingress. name → port for every
    /// worker whose process is (believed) up.
    fn ports_snapshot(running: &HashMap<String, RunningWorker>) -> HashMap<String, u16> {
        running
            .iter()
            .filter(|(_, rw)| rw.child.is_some())
            .map(|(n, rw)| (n.clone(), rw.port))
            .collect()
    }

    async fn reconcile(&mut self) {
        let desired: Vec<WorkerManifest> = self
            .node
            .live_manifests()
            .into_iter()
            .filter(|m| !m.main.is_empty())
            .filter(|m| {
                let has_do = !crate::deploy::durable_objects(m).is_empty();
                !has_do
                    || self.node.cfg.runtime.allow_local_durable_objects
                    || self.durable.is_owner(&m.name)
            })
            .collect();

        // Stop workers that disappeared.
        let names: std::collections::HashSet<&str> =
            desired.iter().map(|m| m.name.as_str()).collect();
        let stale: Vec<String> = self
            .running
            .keys()
            .filter(|n| !names.contains(n.as_str()))
            .cloned()
            .collect();
        for name in stale {
            if let Some(mut rw) = self.running.remove(&name) {
                if let Some(child) = &mut rw.child {
                    let _ = child.start_kill();
                }
                tracing::info!("已停止 Worker {name}");
            }
            self.node.remove_worker_event_token(&name);
            if let Some(manifest) = self.node.manifest(&name) {
                self.node.set_runtime_status(
                    &name,
                    manifest.version,
                    "standby",
                    "此节点不是该 Durable Object 当前的活动所有者",
                );
            }
        }

        for m in desired {
            let current = self.running.get(&m.name);
            let up = current.map(|rw| rw.child.is_some()).unwrap_or(false);
            if current.map(|rw| rw.version) == Some(m.version) && up {
                continue; // already running this version
            }
            if self
                .node
                .missing_blobs()
                .iter()
                .any(|s| m.blob_refs().any(|r| r == *s))
            {
                tracing::debug!("Worker {} 正在等待内容块", m.name);
                self.node.set_runtime_status(
                    &m.name,
                    m.version,
                    "waiting_blobs",
                    "正在从对等节点获取不可变内容块",
                );
                continue;
            }
            match self.start_worker(&m).await {
                Ok(()) => {}
                Err(e) => {
                    self.node
                        .set_runtime_status(&m.name, m.version, "failed", format!("{e:#}"));
                    self.node.append_runtime_log(
                        &m.name,
                        m.version,
                        "system",
                        &format!("启动失败：{e:#}"),
                    );
                    tracing::warn!("启动 Worker {} 时出错：{e:#}", m.name)
                }
            }
        }
        // Publish the port table for ingress.
        let ports = Self::ports_snapshot(&self.running);
        self.node.set_worker_ports(ports);
    }

    fn alloc_port(&self, name: &str) -> u16 {
        // Stable slot by name hash, linear probe over ports that are
        // taken by us OR by anything else on the host (a previous
        // daemon's orphan, another service) — probed with a real bind.
        let mut slot = {
            let d = sha2::Sha256::digest(name.as_bytes());
            u16::from_le_bytes([d[0], d[1]]) % 1000
        };
        let used: std::collections::HashSet<u16> = self.running.values().map(|r| r.port).collect();
        for _ in 0..1000 {
            let port = self.port_base + slot;
            if !used.contains(&port) && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
            slot = (slot + 1) % 1000;
        }
        self.port_base // hopeless; spawn will fail loudly
    }

    async fn start_worker(&mut self, m: &WorkerManifest) -> Result<()> {
        let Some(workerd) = &self.workerd else {
            self.node.set_runtime_status(
                &m.name,
                m.version,
                "runtime_unavailable",
                "尚未安装 workerd 可执行文件",
            );
            return Ok(()); // no runtime on this node
        };
        self.node
            .set_runtime_status(&m.name, m.version, "starting", "正在准备 Worker 运行文件");
        let port = self
            .running
            .get(&m.name)
            .map(|r| r.port)
            .unwrap_or_else(|| self.alloc_port(&m.name));

        let dir = self
            .node
            .cfg
            .data_dir
            .join("workers")
            .join(&m.name)
            .join(m.version.to_string());
        let src = dir.join("src");
        std::fs::create_dir_all(&src)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        for module in &m.modules {
            let path = src.join(&module.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = self
                .node
                .blobs
                .get(&module.sha256)
                .context("读取模块内容块")?;
            std::fs::write(&path, bytes)?;
        }
        let d1_bindings = crate::deploy::d1_bindings(m);
        for database in d1_bindings.values() {
            crate::d1::ensure_database(&self.node, database)?;
        }
        let event_token = hex::encode(rand::random::<[u8; 32]>());
        std::fs::write(
            src.join("__rf_entry.js"),
            rf_entry_source(m, &d1_bindings, &event_token),
        )?;
        std::fs::write(src.join("__rf_workflow.js"), WORKFLOW_SHIM_SOURCE)?;
        let durable_dir = self.node.cfg.data_dir.join("durable").join(&m.name);
        std::fs::create_dir_all(&durable_dir)?;

        // Stop the old version before replacing a DO SQLite snapshot.
        // workerd may keep WAL handles open even between requests.
        if let Some(rw) = self.running.get_mut(&m.name) {
            if let Some(child) = &mut rw.child {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
            }
            rw.child = None;
        }
        if !crate::deploy::durable_objects(m).is_empty()
            && !self.node.cfg.runtime.allow_local_durable_objects
        {
            self.durable.restore(&m.name).await?;
        }
        let cluster_secret = self.node.cfg.cluster_secret_bytes()?;
        let mut secret_bindings = crate::worker_secret::decrypt_manifest(&cluster_secret, m)?;
        let mut config = generate_config(
            m,
            port,
            BindingPorts {
                kv: self.node.kvbind_port(),
                r2: self.node.r2bind_port(),
                d1: self.node.d1bind_port(),
                queue: self.node.qbind_port(),
                analytics: self.node.analyticsbind_port(),
                pipeline: self.node.pbind_port(),
                workflow: self.node.workflowbind_port(),
                email: self.node.emailbind_port(),
                service: self.node.servicebind_port(),
            },
            &durable_dir,
            &secret_bindings,
        );
        for value in secret_bindings.values_mut() {
            value.zeroize();
        }
        let config_path = dir.join("config.capnp");
        std::fs::write(&config_path, config.as_bytes())?;
        config.zeroize();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
        }
        let _secret_config_cleanup =
            SecretConfigCleanup((!secret_bindings.is_empty()).then_some(config_path.clone()));

        let mut cmd = Command::new(workerd);
        cmd.arg("serve");
        if !crate::deploy::durable_objects(m).is_empty() {
            cmd.arg("--experimental");
        }
        cmd.arg(dir.join("config.capnp"))
            .current_dir(&dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Die with the daemon: a SIGKILLed rf must not leave orphan
        // workerds squatting on worker ports with stale code.
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("为 Worker {} 启动 workerd", m.name))?;
        if let Some(stdout) = child.stdout.take() {
            spawn_log_reader(
                self.node.clone(),
                m.name.clone(),
                m.version,
                "stdout",
                stdout,
            );
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_log_reader(
                self.node.clone(),
                m.name.clone(),
                m.version,
                "stderr",
                stderr,
            );
        }

        // Wait until the socket actually answers (or the child dies) —
        // a bind failure otherwise looks like success for 10 seconds.
        let mut healthy = false;
        for _ in 0..50 {
            if let Ok(Some(status)) = child.try_wait() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let tail = self
                    .node
                    .runtime_logs(&m.name, 20)
                    .into_iter()
                    .map(|line| line.message)
                    .collect::<Vec<_>>()
                    .join(" | ");
                anyhow::bail!(
                    "Worker {} 的 workerd 在启动期间退出：{status}{}",
                    m.name,
                    if tail.is_empty() {
                        String::new()
                    } else {
                        format!("；日志：{tail}")
                    }
                );
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                healthy = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !healthy {
            let _ = child.start_kill();
            anyhow::bail!("Worker {} 的 workerd 未能监听 127.0.0.1:{port}", m.name);
        }

        tracing::info!(
            "Worker {} v{} 已在 127.0.0.1:{port} 运行",
            m.name,
            m.version
        );
        self.node.set_runtime_status(
            &m.name,
            m.version,
            "running",
            format!("workerd 正在 127.0.0.1:{port} 运行"),
        );
        self.node.append_runtime_log(
            &m.name,
            m.version,
            "system",
            &format!("Worker 已在 127.0.0.1:{port} 启动"),
        );
        self.node.set_worker_event_token(&m.name, event_token);
        self.running.insert(
            m.name.clone(),
            RunningWorker {
                version: m.version,
                port,
                child: Some(child),
            },
        );
        Ok(())
    }
}

struct SecretConfigCleanup(Option<std::path::PathBuf>);

impl Drop for SecretConfigCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn spawn_log_reader<R>(
    node: Arc<Node>,
    worker: String,
    version: u64,
    stream: &'static str,
    reader: R,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            node.append_runtime_log(&worker, version, stream, &line);
        }
    });
}

use sha2::Digest;

pub fn find_workerd() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("workerd");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn rf_entry_source(
    manifest: &WorkerManifest,
    bindings: &std::collections::BTreeMap<String, String>,
    event_token: &str,
) -> String {
    let import = format!("./{}", manifest.main);
    let import_literal = serde_json::to_string(&import).expect("module path is serializable");
    let binding_names = serde_json::to_string(&bindings.keys().collect::<Vec<_>>())
        .expect("binding names are serializable");
    let queue_names = serde_json::to_string(
        &crate::deploy::queue_bindings(manifest)
            .keys()
            .collect::<Vec<_>>(),
    )
    .expect("queue binding names are serializable");
    let analytics_names = serde_json::to_string(
        &crate::deploy::analytics_bindings(manifest)
            .keys()
            .collect::<Vec<_>>(),
    )
    .expect("Analytics binding names are serializable");
    let pipeline_names = serde_json::to_string(
        &crate::deploy::pipeline_bindings(manifest)
            .keys()
            .collect::<Vec<_>>(),
    )
    .expect("Pipeline binding names are serializable");
    let workflow_names = serde_json::to_string(
        &crate::deploy::workflow_bindings(manifest)
            .keys()
            .collect::<Vec<_>>(),
    )
    .expect("Workflow binding names are serializable");
    let email_names = serde_json::to_string(
        &crate::deploy::email_bindings(manifest)
            .keys()
            .collect::<Vec<_>>(),
    )
    .expect("Email binding names are serializable");
    let event_token = serde_json::to_string(event_token).expect("event token is serializable");
    let mut durable_wrappers = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for object in crate::deploy::durable_objects(manifest).into_values() {
        if seen.insert(object.class_name.clone()) {
            durable_wrappers.push_str(&format!(
                "export class {class} extends __rfUserModule.{class} {{\n  constructor(state, env) {{ super(state, __rfWrapEnv(env)); }}\n}}\n",
                class = object.class_name,
            ));
        }
    }
    RF_ENTRY_TEMPLATE
        .replace("__RF_USER_IMPORT__", &import_literal)
        .replace("__RF_D1_BINDING_NAMES__", &binding_names)
        .replace("__RF_QUEUE_BINDING_NAMES__", &queue_names)
        .replace("__RF_ANALYTICS_BINDING_NAMES__", &analytics_names)
        .replace("__RF_PIPELINE_BINDING_NAMES__", &pipeline_names)
        .replace("__RF_WORKFLOW_BINDING_NAMES__", &workflow_names)
        .replace("__RF_EMAIL_BINDING_NAMES__", &email_names)
        .replace("__RF_EVENT_TOKEN__", &event_token)
        .replace("__RF_DURABLE_WRAPPERS__", &durable_wrappers)
}

const RF_ENTRY_TEMPLATE: &str = r#"// generated by RandallFlare — platform binding facade
import __rfUserDefault, * as __rfUserModule from __RF_USER_IMPORT__;
export * from __RF_USER_IMPORT__;

class RandallFlareD1Database {
  constructor(service) { this._service = service; }
  prepare(sql) { return new RandallFlareD1Statement(this, String(sql), []); }
  async _send(payload) {
    const response = await this._service.fetch("http://d1-binding/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error("D1_ERROR: " + response.status + " " + await response.text());
    return await response.json();
  }
  async exec(sql) { return await this._send({ mode: "exec", sql: String(sql) }); }
  async batch(statements) {
    if (!Array.isArray(statements) || statements.some((item) => !(item instanceof RandallFlareD1Statement))) {
      throw new TypeError("D1 batch() expects an array of prepared statements");
    }
    return await this._send({
      mode: "batch",
      statements: statements.map((item) => ({ sql: item._sql, params: item._params })),
    });
  }
  withSession() { return new RandallFlareD1Session(this._service); }
}

class RandallFlareD1Session extends RandallFlareD1Database {
  getBookmark() { return null; }
}

class RandallFlareD1Statement {
  constructor(database, sql, params) { this._database = database; this._sql = sql; this._params = params; }
  bind(...values) { return new RandallFlareD1Statement(this._database, this._sql, values); }
  async all() { return await this._database._send({ mode: "query", sql: this._sql, params: this._params }); }
  async first(column) {
    const output = await this._database._send({ mode: "first", sql: this._sql, params: this._params });
    const row = output.results && output.results.length ? output.results[0] : null;
    return column === undefined ? row : (row === null ? null : row[column]);
  }
  async run() { return await this._database._send({ mode: "run", sql: this._sql, params: this._params }); }
  async raw(options = {}) {
    const output = await this.all();
    const rows = output.results || [];
    const columns = rows.length ? Object.keys(rows[0]) : [];
    const raw = rows.map((row) => columns.map((column) => row[column]));
    if (options.columnNames) raw.unshift(columns);
    return raw;
  }
}

class RandallFlareQueue {
  constructor(service) { this._service = service; }
  async _send(messages) {
    const response = await this._service.fetch("http://queue-binding/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages }),
    });
    if (!response.ok) throw new Error("QUEUE_ERROR: " + response.status + " " + await response.text());
  }
  async send(body, options = {}) {
    await this._send([{ body, delay_seconds: Number(options.delaySeconds || 0) }]);
  }
  async sendBatch(messages) {
    if (!Array.isArray(messages)) throw new TypeError("Queue sendBatch() expects an array");
    await this._send(messages.map((message) => ({
      body: message.body,
      delay_seconds: Number(message.delaySeconds || 0),
    })));
  }
}

class RandallFlareAnalyticsDataset {
  constructor(service, context) { this._service = service; this._context = context; }
  async _write(points) {
    const response = await this._service.fetch("http://analytics-binding/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ points }),
    });
    if (!response.ok) throw new Error("ANALYTICS_ERROR: " + response.status + " " + await response.text());
  }
  writeDataPoint(point = {}) {
    if (point === null || typeof point !== "object" || Array.isArray(point)) {
      throw new TypeError("Analytics writeDataPoint() expects an object");
    }
    const timestamp = point.ts_ms ?? point.ts ?? point.timestamp;
    const normalized = {
      blobs: Array.isArray(point.blobs) ? point.blobs.map(String) : [],
      doubles: Array.isArray(point.doubles) ? point.doubles.map(Number) : [],
      indexes: Array.isArray(point.indexes) ? point.indexes.map(String) : [],
    };
    if (timestamp !== undefined && timestamp !== null) {
      normalized.ts_ms = timestamp instanceof Date ? timestamp.getTime() : Number(timestamp);
    }
    const pending = this._write([normalized]);
    if (this._context && typeof this._context.waitUntil === "function") {
      this._context.waitUntil(pending);
      return;
    }
    return pending;
  }
}

class RandallFlarePipeline {
  constructor(service, context) { this._service = service; this._context = context; }
  send(events) {
    const normalized = Array.isArray(events) ? events : [events];
    if (normalized.length === 0) throw new TypeError("Pipeline send() expects at least one event");
    const pending = (async () => {
      const response = await this._service.fetch("http://pipeline-binding/", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ events: normalized }),
      });
      if (!response.ok) throw new Error("PIPELINE_ERROR: " + response.status + " " + await response.text());
      return await response.json();
    })();
    if (this._context && typeof this._context.waitUntil === "function") this._context.waitUntil(pending);
    return pending;
  }
}

class RandallFlareWorkflowInstance {
  constructor(service, id) { this._service = service; this.id = String(id); }
  async _call(op, extra = {}) {
    const response = await this._service.fetch("http://workflow-binding/binding", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ op, id: this.id, ...extra }),
    });
    if (!response.ok) throw new Error("WORKFLOW_ERROR: " + response.status + " " + await response.text());
    return await response.json();
  }
  status() { return this._call("status"); }
  pause() { return this._call("pause"); }
  resume() { return this._call("resume"); }
  terminate() { return this._call("terminate"); }
  restart() { return this._call("restart"); }
  sendEvent(event) {
    if (!event || typeof event.type !== "string" || !event.type) throw new TypeError("sendEvent() requires { type, payload }");
    return this._call("send_event", { event_type: event.type, payload: event.payload ?? null });
  }
}

class RandallFlareWorkflowBinding {
  constructor(service) { this._service = service; }
  async create(options = {}) {
    const response = await this._service.fetch("http://workflow-binding/binding", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ op: "create", id: options.id == null ? null : String(options.id), params: options.params ?? {} }),
    });
    if (!response.ok) throw new Error("WORKFLOW_ERROR: " + response.status + " " + await response.text());
    const out = await response.json();
    return new RandallFlareWorkflowInstance(this._service, out.id);
  }
  get(id) {
    if (id == null || String(id) === "") throw new TypeError("Workflow get(id): id is required");
    return new RandallFlareWorkflowInstance(this._service, id);
  }
}

class RandallFlareEmailBinding {
  constructor(service) { this._service = service; }
  async send(message) {
    if (!message || typeof message !== "object") throw new TypeError("Email send() expects a message object");
    const from = String(message.from || "");
    const to = String(message.to || "");
    if (!from || !to || /[\r\n]/.test(from + to)) throw new TypeError("Email send() requires valid from and to addresses");
    let source = message.raw;
    if (source == null) throw new TypeError("Email send() requires raw RFC 822 source");
    if (typeof source === "string") source = new TextEncoder().encode(source);
    const raw = await new Response(source).arrayBuffer();
    const response = await this._service.fetch("http://email-binding/send", {
      method: "POST",
      headers: {
        "content-type": "message/rfc822",
        "x-rf-email-from": from,
        "x-rf-email-to": to,
      },
      body: raw,
    });
    if (!response.ok) throw new Error("EMAIL_ERROR: " + response.status + " " + await response.text());
    return await response.json();
  }
}

const __rfD1Names = __RF_D1_BINDING_NAMES__;
const __rfQueueNames = __RF_QUEUE_BINDING_NAMES__;
const __rfAnalyticsNames = __RF_ANALYTICS_BINDING_NAMES__;
const __rfPipelineNames = __RF_PIPELINE_BINDING_NAMES__;
const __rfWorkflowNames = __RF_WORKFLOW_BINDING_NAMES__;
const __rfEmailNames = __RF_EMAIL_BINDING_NAMES__;
const __rfEventToken = __RF_EVENT_TOKEN__;
function __rfWrapEnv(env, context) {
  const wrapped = Object.create(env);
  for (const name of __rfD1Names) {
    Object.defineProperty(wrapped, name, {
      value: new RandallFlareD1Database(env[name]), enumerable: true, configurable: false,
    });
  }
  for (const name of __rfQueueNames) {
    Object.defineProperty(wrapped, name, {
      value: new RandallFlareQueue(env[name]), enumerable: true, configurable: false,
    });
  }
  for (const name of __rfAnalyticsNames) {
    Object.defineProperty(wrapped, name, {
      value: new RandallFlareAnalyticsDataset(env[name], context), enumerable: true, configurable: false,
    });
  }
  for (const name of __rfPipelineNames) {
    Object.defineProperty(wrapped, name, {
      value: new RandallFlarePipeline(env[name], context), enumerable: true, configurable: false,
    });
  }
  for (const name of __rfWorkflowNames) {
    Object.defineProperty(wrapped, name, {
      value: new RandallFlareWorkflowBinding(env[name]), enumerable: true, configurable: false,
    });
  }
  for (const name of __rfEmailNames) {
    Object.defineProperty(wrapped, name, {
      value: new RandallFlareEmailBinding(env[name]), enumerable: true, configurable: false,
    });
  }
  return wrapped;
}

function __rfWorkflowDuration(value, fallback = 0) {
  if (value == null) return fallback;
  if (typeof value === "number") return Math.max(0, Math.floor(value));
  const match = /^\s*(\d+(?:\.\d+)?)\s*([a-z]+)?\s*$/i.exec(String(value));
  if (!match) return fallback;
  const unit = (match[2] || "ms").toLowerCase();
  const units = {
    ms: 1, millisecond: 1, milliseconds: 1,
    s: 1000, sec: 1000, second: 1000, seconds: 1000,
    m: 60000, min: 60000, minute: 60000, minutes: 60000,
    h: 3600000, hour: 3600000, hours: 3600000,
    d: 86400000, day: 86400000, days: 86400000,
  };
  return Math.max(0, Math.floor(Number(match[1]) * (units[unit] || 0))) || fallback;
}

async function __rfWorkflowCall(service, payload) {
  const response = await service.fetch("http://workflow-binding/step", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error("WORKFLOW_STEP_ERROR: " + response.status + " " + await response.text());
  return await response.json();
}

function __rfWorkflowStep(env, advance) {
  const service = env.__RF_WORKFLOW_SERVICE;
  const base = {
    workflow: advance.workflow,
    instance_id: advance.instance_id,
    lease: advance.lease,
  };
  const park = (kind, name, extra = {}) => {
    const error = new Error("workflow-" + kind + ":" + name);
    error.__rf_workflow_parked__ = { kind, name, ...extra };
    throw error;
  };
  const sleep = async (name, duration) => {
    if (typeof name !== "string" || !name) throw new TypeError("step.sleep(name, duration): name is required");
    const out = await __rfWorkflowCall(service, { ...base, op: "sleep", name, duration_ms: __rfWorkflowDuration(duration, 0) });
    if (out.status === "wake") return;
    park("sleep", name, { wake_at_ms: out.wake_at_ms });
  };
  return {
    async do(name, configOrFn, maybeFn) {
      if (typeof name !== "string" || !name) throw new TypeError("step.do(name[, config], fn): name is required");
      const config = typeof configOrFn === "function" ? {} : (configOrFn || {});
      const fn = typeof configOrFn === "function" ? configOrFn : maybeFn;
      if (typeof fn !== "function") throw new TypeError("step.do(): fn must be a function");
      const cached = await __rfWorkflowCall(service, { ...base, op: "lookup", name });
      if (cached.cached) return cached.result;
      if (cached.already_failed) throw new Error("step \"" + name + "\" already failed: " + cached.error);
      const retry = config.retries || {};
      const limit = Number.isFinite(retry.limit) ? Math.max(0, Math.min(100, Math.floor(retry.limit))) : 5;
      const delay = __rfWorkflowDuration(retry.delay, 1000);
      const backoff = retry.backoff || "exponential";
      const timeout = __rfWorkflowDuration(config.timeout, 0);
      let result;
      let lastError;
      let attempts = 0;
      for (let attempt = 0; attempt <= limit; attempt++) {
        attempts = attempt + 1;
        try {
          const run = Promise.resolve().then(fn);
          if (timeout > 0) {
            result = await Promise.race([
              run,
              new Promise((_, reject) => setTimeout(() => reject(new Error("step \"" + name + "\" timed out")), timeout)),
            ]);
          } else result = await run;
          lastError = null;
          break;
        } catch (error) {
          lastError = error;
          if ((error && error.name === "NonRetryableError") || attempt >= limit) break;
          let wait = delay;
          if (backoff === "exponential") wait *= Math.pow(2, attempt);
          else if (backoff === "linear") wait *= attempt + 1;
          wait = Math.min(wait, 5 * 60 * 1000);
          if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
        }
      }
      if (lastError) {
        await __rfWorkflowCall(service, {
          ...base, op: "record", name, status: "failed", attempts,
          error: String(lastError && lastError.message || lastError),
        });
        throw lastError;
      }
      let safe;
      try { safe = JSON.parse(JSON.stringify(result === undefined ? null : result)); }
      catch { throw new TypeError("step.do() result must be JSON serializable"); }
      await __rfWorkflowCall(service, { ...base, op: "record", name, status: "ok", attempts, result: safe });
      return safe;
    },
    sleep,
    sleepUntil(name, timestamp) {
      const raw = timestamp instanceof Date ? timestamp.getTime() : Number(timestamp);
      if (!Number.isFinite(raw)) throw new TypeError("step.sleepUntil(): timestamp must be a Date or number");
      const target = raw < 1e12 ? raw * 1000 : raw;
      return sleep(name, Math.max(0, target - Date.now()));
    },
    async waitForSignal(name) {
      if (typeof name !== "string" || !name) throw new TypeError("step.waitForSignal(name): name is required");
      const out = await __rfWorkflowCall(service, { ...base, op: "signal", name });
      if (out.status === "delivered") return out.payload;
      park("signal", name);
    },
  };
}

async function __rfWorkflowEvent(request, env, context) {
  let advance;
  try { advance = await request.json(); }
  catch { return Response.json({ status: "failed", error: "Workflow 推进请求不是有效 JSON" }); }
  const Entry = __rfUserModule[advance.entrypoint];
  if (typeof Entry !== "function") {
    return Response.json({ status: "failed", error: "Worker 未导出 Workflow 入口类 " + advance.entrypoint });
  }
  const wrapped = __rfWrapEnv(env, context);
  const step = __rfWorkflowStep(wrapped, advance);
  try {
    const entry = new Entry({ instanceId: advance.instance_id }, wrapped);
    if (!entry || typeof entry.run !== "function") throw new TypeError("Workflow 入口类必须实现 run(input, step)");
    const output = await entry.run(advance.input, step);
    return Response.json({ status: "complete", output: output === undefined ? null : output });
  } catch (error) {
    if (error && error.__rf_workflow_parked__) return Response.json({ status: "parked" });
    return Response.json({
      status: "failed",
      error: String(error && error.stack || error).slice(0, 4000),
    });
  }
}

async function __rfQueueEvent(request, env, context) {
  if (!__rfUserDefault || typeof __rfUserDefault.queue !== "function") {
    return new Response("此 Worker 没有导出 queue() 处理程序", { status: 501 });
  }
  const payload = await request.json();
  const states = new Map();
  const messages = payload.messages.map((wire) => {
    const state = { action: "ack", delay_seconds: 0, error: null };
    states.set(wire.id, state);
    return {
      id: wire.id,
      timestamp: new Date(wire.produced_at_ms),
      body: wire.body,
      attempts: wire.attempts,
      ack() { state.action = "ack"; state.delay_seconds = 0; state.error = null; },
      retry(options = {}) {
        state.action = "retry";
        state.delay_seconds = Number(options.delaySeconds || 0);
        state.error = options.error == null ? null : String(options.error);
      },
    };
  });
  const batch = {
    queue: payload.queue,
    messages,
    ackAll() {
      for (const state of states.values()) {
        state.action = "ack"; state.delay_seconds = 0; state.error = null;
      }
    },
    retryAll(options = {}) {
      for (const state of states.values()) {
        state.action = "retry";
        state.delay_seconds = Number(options.delaySeconds || 0);
        state.error = options.error == null ? null : String(options.error);
      }
    },
  };
  const pending = [];
  const eventContext = {
    waitUntil(promise) { pending.push(Promise.resolve(promise)); },
    passThroughOnException() {
      if (context && typeof context.passThroughOnException === "function") context.passThroughOnException();
    },
  };
  try {
    await __rfUserDefault.queue(batch, __rfWrapEnv(env, eventContext), eventContext);
    await Promise.all(pending);
  } catch (error) {
    return new Response(String(error && error.stack || error), { status: 500 });
  }
  const actions = [];
  for (const [id, state] of states) {
    if (state.action === "retry") actions.push({ id, ...state });
  }
  return Response.json({ actions });
}

function __rfParseMailHeaders(raw) {
  let end = -1;
  for (let i = 0; i + 3 < raw.length; i++) {
    if (raw[i] === 13 && raw[i + 1] === 10 && raw[i + 2] === 13 && raw[i + 3] === 10) { end = i; break; }
  }
  if (end < 0) {
    for (let i = 0; i + 1 < raw.length; i++) {
      if (raw[i] === 10 && raw[i + 1] === 10) { end = i; break; }
    }
  }
  const headers = new Headers();
  const text = new TextDecoder("utf-8", { fatal: false }).decode(raw.slice(0, end < 0 ? raw.length : end));
  const unfolded = text.replace(/\r?\n[\t ]+/g, " ").split(/\r?\n/);
  for (const line of unfolded) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    try { headers.append(line.slice(0, colon).trim(), line.slice(colon + 1).trim()); } catch {}
  }
  return headers;
}

async function __rfEmailEvent(request, env, context) {
  if (!__rfUserDefault || typeof __rfUserDefault.email !== "function") {
    return new Response("此 Worker 没有导出 email() 处理程序", { status: 501 });
  }
  const raw = new Uint8Array(await request.arrayBuffer());
  const state = { reject: null, forwards: [] };
  const message = {
    from: request.headers.get("x-rf-email-from") || "",
    to: request.headers.get("x-rf-email-to") || "",
    authResults: request.headers.get("x-rf-email-authentication-results") || "",
    spf: request.headers.get("x-rf-email-spf") || "none",
    dkim: request.headers.get("x-rf-email-dkim") || "none",
    dmarc: request.headers.get("x-rf-email-dmarc") || "none",
    raw: new Blob([raw], { type: "message/rfc822" }).stream(),
    rawSize: raw.byteLength,
    headers: __rfParseMailHeaders(raw),
    setReject(reason) {
      const value = String(reason || "").trim();
      if (!value || value.length > 1000 || /[\r\n]/.test(value)) throw new TypeError("setReject() requires a safe reason");
      state.reject = value;
    },
    async forward(recipient, extraHeaders) {
      const value = String(recipient || "");
      if (!value || value.length > 320 || /[\r\n]/.test(value)) throw new TypeError("forward() requires a valid recipient");
      const headers = [];
      if (extraHeaders != null) {
        const input = extraHeaders instanceof Headers ? extraHeaders : new Headers(extraHeaders);
        for (const [name, headerValue] of input) {
          if (headers.length >= 128) throw new TypeError("forward() accepts at most 128 extra headers");
          headers.push([name, headerValue]);
        }
      }
      state.forwards.push({ recipient: value, headers });
    },
  };
  const pending = [];
  const eventContext = {
    waitUntil(promise) { pending.push(Promise.resolve(promise)); },
    passThroughOnException() {
      if (context && typeof context.passThroughOnException === "function") context.passThroughOnException();
    },
  };
  try {
    await __rfUserDefault.email(message, __rfWrapEnv(env, eventContext), eventContext);
    await Promise.all(pending);
  } catch (error) {
    return new Response(String(error && error.stack || error).slice(0, 4000), { status: 500 });
  }
  return Response.json(state);
}

const __rfOut = { ...__rfUserDefault };
__rfOut.fetch = (request, env, context) => {
  const url = new URL(request.url);
  if (url.pathname === "/.rf/internal/queue" && request.headers.get("x-rf-internal-event") === __rfEventToken) {
    return __rfQueueEvent(request, env, context);
  }
  if (url.pathname === "/.rf/internal/workflow" && request.headers.get("x-rf-internal-event") === __rfEventToken) {
    return __rfWorkflowEvent(request, env, context);
  }
  if (url.pathname === "/.rf/internal/email" && request.headers.get("x-rf-internal-event") === __rfEventToken) {
    return __rfEmailEvent(request, env, context);
  }
  if (__rfUserDefault && typeof __rfUserDefault.fetch === "function") {
    return __rfUserDefault.fetch(request, __rfWrapEnv(env, context), context);
  }
  return new Response("Not Found", { status: 404 });
};
if (__rfUserDefault && typeof __rfUserDefault.scheduled === "function") {
  __rfOut.scheduled = (event, env, context) => __rfUserDefault.scheduled(event, __rfWrapEnv(env, context), context);
}
if (__rfUserDefault && typeof __rfUserDefault.queue === "function") {
  __rfOut.queue = (batch, env, context) => __rfUserDefault.queue(batch, __rfWrapEnv(env, context), context);
}
if (__rfUserDefault && typeof __rfUserDefault.email === "function") {
  __rfOut.email = (message, env, context) => __rfUserDefault.email(message, __rfWrapEnv(env, context), context);
}
export default __rfOut;
__RF_DURABLE_WRAPPERS__
"#;

const WORKFLOW_SHIM_SOURCE: &str = r#"// generated by RandallFlare — durable Workflow API
export class WorkflowEntrypoint {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }
}

export class NonRetryableError extends Error {
  constructor(message) { super(message); this.name = "NonRetryableError"; }
}

// The generated RandallFlare entrypoint intercepts advance requests, so this
// compatibility helper intentionally returns null for ordinary user fetches.
export async function handleWorkflowRequest() { return null; }
"#;

/// Emit the workerd capnp config for one worker.
#[derive(Debug, Clone, Copy)]
pub struct BindingPorts {
    pub kv: u16,
    pub r2: u16,
    pub d1: u16,
    pub queue: u16,
    pub analytics: u16,
    pub pipeline: u16,
    pub workflow: u16,
    pub email: u16,
    pub service: u16,
}

pub fn generate_config(
    m: &WorkerManifest,
    port: u16,
    binding_ports: BindingPorts,
    durable_dir: &std::path::Path,
    secret_bindings: &std::collections::BTreeMap<String, String>,
) -> String {
    let BindingPorts {
        kv: kvbind_port,
        r2: r2bind_port,
        d1: d1bind_port,
        queue: qbind_port,
        analytics: analyticsbind_port,
        pipeline: pbind_port,
        workflow: workflowbind_port,
        email: emailbind_port,
        service: servicebind_port,
    } = binding_ports;
    let mut modules = String::new();
    modules
        .push_str("        (name = \"__rf_entry.js\", esModule = embed \"src/__rf_entry.js\"),\n");
    modules.push_str(
        "        (name = \"randallflare:workers\", esModule = embed \"src/__rf_workflow.js\"),\n",
    );
    for module in &m.modules {
        let kind = match module.kind {
            ModuleKind::EsModule => "esModule",
            ModuleKind::CommonJs => "commonJsModule",
            ModuleKind::Wasm => "wasm",
            ModuleKind::Text => "text",
            ModuleKind::Data => "data",
        };
        let source = format!("src/{}", module.path);
        modules.push_str(&format!(
            "        (name = {}, {kind} = embed {}),\n",
            capnp_string(&module.path),
            capnp_string(&source),
        ));
    }
    let mut bindings = String::new();
    for (k, v) in &m.env {
        if k == crate::deploy::DO_METADATA_ENV
            || k == crate::deploy::R2_METADATA_ENV
            || k == crate::deploy::D1_METADATA_ENV
            || k == crate::deploy::QUEUE_METADATA_ENV
            || k == crate::deploy::ANALYTICS_METADATA_ENV
            || k == crate::deploy::PIPELINE_METADATA_ENV
            || k == crate::deploy::WORKFLOW_METADATA_ENV
            || k == crate::deploy::EMAIL_METADATA_ENV
            || k == crate::deploy::SERVICE_METADATA_ENV
            || k == crate::deploy::SECRET_METADATA_ENV
        {
            continue;
        }
        bindings.push_str(&format!(
            "        (name = {}, text = {}),\n",
            capnp_string(k),
            capnp_string(v)
        ));
    }
    for (binding, value) in secret_bindings {
        bindings.push_str(&format!(
            "        (name = {}, text = {}),\n",
            capnp_string(binding),
            capnp_string(value),
        ));
    }
    // Native kvNamespace bindings: each one routes to the node's
    // loopback kvbind server, namespace carried in an injected header.
    let mut kv_services = String::new();
    for (binding, ns) in &m.kv_bindings {
        let service = format!("kv-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, kvNamespace = (name = {service})),\n",
            binding = capnp_string(binding),
            service = capnp_string(&service),
        ));
        kv_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{kvbind_port}\", \
             http = (injectRequestHeaders = [(name = \"{ns_header}\", value = {ns_val})]))),\n",
            service = capnp_string(&service),
            ns_header = crate::kvbind::NS_HEADER,
            ns_val = capnp_string(ns),
        ));
    }
    let mut r2_services = String::new();
    for (binding, bucket) in crate::deploy::r2_bindings(m) {
        let service = format!("r2-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, r2Bucket = (name = {service})),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        r2_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{r2bind_port}\", \
             http = (injectRequestHeaders = [(name = \"{bucket_header}\", value = {bucket})]))),\n",
            service = capnp_string(&service),
            bucket_header = crate::r2bind::BUCKET_HEADER,
            bucket = capnp_string(&bucket),
        ));
    }
    let mut d1_services = String::new();
    for (binding, database) in crate::deploy::d1_bindings(m) {
        let service = format!("d1-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, service = {service}),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        d1_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{d1bind_port}\", \
             http = (injectRequestHeaders = [(name = \"{database_header}\", value = {database})]))),\n",
            service = capnp_string(&service),
            database_header = crate::d1bind::DATABASE_HEADER,
            database = capnp_string(&database),
        ));
    }
    let mut queue_services = String::new();
    for (binding, queue) in crate::deploy::queue_bindings(m) {
        let service = format!("queue-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, service = {service}),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        queue_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{qbind_port}\", \
             http = (injectRequestHeaders = [(name = \"{queue_header}\", value = {queue})]))),\n",
            service = capnp_string(&service),
            queue_header = crate::qbind::QUEUE_HEADER,
            queue = capnp_string(&queue),
        ));
    }
    let mut analytics_services = String::new();
    for (binding, dataset) in crate::deploy::analytics_bindings(m) {
        let service = format!("analytics-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, service = {service}),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        analytics_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{analyticsbind_port}\", \
             http = (injectRequestHeaders = [(name = \"{dataset_header}\", value = {dataset})]))),\n",
            service = capnp_string(&service),
            dataset_header = crate::analyticsbind::DATASET_HEADER,
            dataset = capnp_string(&dataset),
        ));
    }
    let mut pipeline_services = String::new();
    for (binding, pipeline) in crate::deploy::pipeline_bindings(m) {
        let service = format!("pipeline-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, service = {service}),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        pipeline_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{pbind_port}\", \
             http = (injectRequestHeaders = [(name = \"{pipeline_header}\", value = {pipeline})]))),\n",
            service = capnp_string(&service),
            pipeline_header = crate::pbind::PIPELINE_HEADER,
            pipeline = capnp_string(&pipeline),
        ));
    }
    let mut workflow_services = String::new();
    for (binding, workflow) in crate::deploy::workflow_bindings(m) {
        let service = format!("workflow-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, service = {service}),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        workflow_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{workflowbind_port}\", \
             http = (injectRequestHeaders = [(name = \"{workflow_header}\", value = {workflow})]))),\n",
            service = capnp_string(&service),
            workflow_header = crate::workflowbind::WORKFLOW_HEADER,
            workflow = capnp_string(&workflow),
        ));
    }
    // Every Worker gets a private replay-log service, fenced on its signed
    // Worker name. The generated entrypoint is the only normal consumer.
    bindings
        .push_str("        (name = \"__RF_WORKFLOW_SERVICE\", service = \"workflow-internal\"),\n");
    workflow_services.push_str(&format!(
        "    (name = \"workflow-internal\", external = (address = \"127.0.0.1:{workflowbind_port}\", \
         http = (injectRequestHeaders = [(name = \"{worker_header}\", value = {worker})]))),\n",
        worker_header = crate::workflowbind::WORKER_HEADER,
        worker = capnp_string(&m.name),
    ));
    let mut email_services = String::new();
    for (binding, domain) in crate::deploy::email_bindings(m) {
        let service = format!("email-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, service = {service}),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        email_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{emailbind_port}\", \
             http = (injectRequestHeaders = [\
               (name = \"{domain_header}\", value = {domain}),\
               (name = \"{worker_header}\", value = {worker})\
             ]))),\n",
            service = capnp_string(&service),
            domain_header = crate::emailbind::EMAIL_DOMAIN_HEADER,
            domain = capnp_string(&domain),
            worker_header = crate::emailbind::WORKER_HEADER,
            worker = capnp_string(&m.name),
        ));
    }
    let mut worker_services = String::new();
    for (binding, target) in crate::deploy::service_bindings(m) {
        let service = format!("worker-service-{binding}");
        bindings.push_str(&format!(
            "        (name = {binding}, service = {service}),\n",
            binding = capnp_string(&binding),
            service = capnp_string(&service),
        ));
        worker_services.push_str(&format!(
            "    (name = {service}, external = (address = \"127.0.0.1:{servicebind_port}\", \
             http = (injectRequestHeaders = [\
               (name = \"{source_header}\", value = {source}),\
               (name = \"{target_header}\", value = {target})\
             ]))),\n",
            service = capnp_string(&service),
            source_header = crate::servicebind::SOURCE_HEADER,
            source = capnp_string(&m.name),
            target_header = crate::servicebind::TARGET_HEADER,
            target = capnp_string(&target),
        ));
    }
    let durable_objects = crate::deploy::durable_objects(m);
    let mut durable_namespaces = String::new();
    let mut seen_durable = std::collections::BTreeSet::new();
    for (binding, object) in &durable_objects {
        bindings.push_str(&format!(
            "        (name = {binding}, durableObjectNamespace = (className = {class})),\n",
            binding = capnp_string(binding),
            class = capnp_string(&object.class_name),
        ));
        if seen_durable.insert((&object.class_name, &object.unique_key)) {
            durable_namespaces.push_str(&format!(
                "        (className = {class}, uniqueKey = {key}, enableSql = {sql}),\n",
                class = capnp_string(&object.class_name),
                key = capnp_string(&object.unique_key),
                sql = object.enable_sql,
            ));
        }
    }
    let durable_worker = if durable_objects.is_empty() {
        String::new()
    } else {
        format!(
            "      durableObjectNamespaces = [\n{durable_namespaces}      ],\n      durableObjectStorage = (localDisk = \"do-storage\"),\n"
        )
    };
    let durable_service = if durable_objects.is_empty() {
        String::new()
    } else {
        format!(
            "    (name = \"do-storage\", disk = (path = {}, writable = true)),\n",
            capnp_string(&durable_dir.to_string_lossy())
        )
    };
    format!(
        r#"# generated by rf — do not edit
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = (
      modules = [
{modules}      ],
      compatibilityDate = {compat},
      bindings = [
{bindings}      ],
{durable_worker}    )),
{kv_services}{r2_services}{d1_services}{queue_services}{analytics_services}{pipeline_services}{workflow_services}{email_services}{worker_services}{durable_service}  ],
  sockets = [
    (name = "http", address = "127.0.0.1:{port}", http = (), service = "main"),
  ],
);
"#,
        compat = capnp_string(&m.compatibility_date),
    )
}

fn capnp_string(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_core::manifest::Module;
    use std::collections::BTreeMap;

    #[test]
    fn config_contains_modules_env_and_socket() {
        let m = WorkerManifest {
            name: "w".into(),
            version: 3,
            prev: Some([1; 32]),
            deleted: false,
            main: "index.js".into(),
            modules: vec![Module {
                path: "index.js".into(),
                sha256: [0; 32],
                kind: ModuleKind::EsModule,
                size: 1,
            }],
            assets: vec![],
            hostnames: vec![],
            env: BTreeMap::from([("GREETING".into(), "hi \"there\"".into())]),
            kv_bindings: BTreeMap::from([("CACHE".into(), "ns1".into())]),
            crons: vec![],
            compatibility_date: "2026-07-31".into(),
        };
        let mut m = m;
        m.env.insert(
            crate::deploy::DO_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "COUNTER".to_string(),
                crate::deploy::DurableObjectBinding {
                    class_name: "Counter".into(),
                    unique_key: "rf--w--Counter".into(),
                    enable_sql: true,
                },
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::R2_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "OBJECTS".to_string(),
                "assets".to_string(),
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::D1_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "DATABASE".to_string(),
                "primary".to_string(),
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::QUEUE_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "EVENTS".to_string(),
                "events".to_string(),
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::ANALYTICS_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "METRICS".to_string(),
                "web-metrics".to_string(),
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::PIPELINE_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "EVENT_PIPE".to_string(),
                "event-archive".to_string(),
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::WORKFLOW_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "ORDER_FLOW".to_string(),
                "order-flow".to_string(),
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::EMAIL_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "MAILER".to_string(),
                "primary-mail".to_string(),
            )]))
            .unwrap(),
        );
        m.env.insert(
            crate::deploy::SERVICE_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "BACKEND".to_string(),
                "backend".to_string(),
            )]))
            .unwrap(),
        );
        let cfg = generate_config(
            &m,
            30111,
            BindingPorts {
                kv: 7382,
                r2: 7383,
                d1: 7384,
                queue: 7385,
                analytics: 7386,
                pipeline: 7387,
                workflow: 7388,
                email: 7389,
                service: 7390,
            },
            std::path::Path::new("/tmp/rf-do"),
            &BTreeMap::from([("API_TOKEN".into(), "private-value".into())]),
        );
        assert!(cfg.contains("esModule = embed \"src/index.js\""));
        assert!(cfg.contains("127.0.0.1:30111"));
        assert!(cfg.contains("GREETING"));
        assert!(cfg.contains("hi \\\"there\\\""));
        assert!(cfg.contains("API_TOKEN"));
        assert!(cfg.contains("private-value"));
        assert!(cfg.contains("(name = \"CACHE\", kvNamespace = (name = \"kv-CACHE\"))"));
        assert!(cfg.contains("external = (address = \"127.0.0.1:7382\""));
        assert!(cfg.contains("injectRequestHeaders = [(name = \"x-rf-kv-ns\", value = \"ns1\")]"));
        assert!(cfg.contains("(name = \"OBJECTS\", r2Bucket = (name = \"r2-OBJECTS\"))"));
        assert!(cfg.contains("address = \"127.0.0.1:7383\""));
        assert!(cfg.contains("x-rf-r2-bucket\", value = \"assets\""));
        assert!(cfg.contains("(name = \"DATABASE\", service = \"d1-DATABASE\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7384\""));
        assert!(cfg.contains("x-rf-d1-database\", value = \"primary\""));
        assert!(cfg.contains("src/__rf_entry.js"));
        assert!(cfg.contains("(name = \"EVENTS\", service = \"queue-EVENTS\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7385\""));
        assert!(cfg.contains("x-rf-queue\", value = \"events\""));
        assert!(cfg.contains("(name = \"METRICS\", service = \"analytics-METRICS\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7386\""));
        assert!(cfg.contains("x-rf-analytics-dataset\", value = \"web-metrics\""));
        assert!(cfg.contains("(name = \"EVENT_PIPE\", service = \"pipeline-EVENT_PIPE\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7387\""));
        assert!(cfg.contains("x-rf-pipeline\", value = \"event-archive\""));
        assert!(cfg.contains("(name = \"ORDER_FLOW\", service = \"workflow-ORDER_FLOW\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7388\""));
        assert!(cfg.contains("x-rf-workflow\", value = \"order-flow\""));
        assert!(cfg.contains("(name = \"MAILER\", service = \"email-MAILER\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7389\""));
        assert!(cfg.contains("x-rf-email-domain\", value = \"primary-mail\""));
        assert!(cfg.contains("x-rf-worker\", value = \"w\""));
        assert!(cfg.contains("(name = \"BACKEND\", service = \"worker-service-BACKEND\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7390\""));
        assert!(cfg.contains("x-rf-service-source\", value = \"w\""));
        assert!(cfg.contains("x-rf-service-target\", value = \"backend\""));
        assert!(cfg.contains("name = \"randallflare:workers\""));
        assert!(cfg.contains("compatibilityDate = \"2026-07-31\""));
        assert!(cfg.contains("durableObjectNamespace = (className = \"Counter\")"));
        assert!(cfg.contains("uniqueKey = \"rf--w--Counter\", enableSql = true"));
        assert!(cfg.contains("durableObjectStorage = (localDisk = \"do-storage\")"));
        assert!(cfg.contains("disk = (path = \"/tmp/rf-do\", writable = true)"));
    }

    #[test]
    fn config_escapes_binding_names_and_control_characters() {
        assert_eq!(capnp_string("a\"b\n"), "\"a\\\"b\\n\"");
    }

    #[test]
    fn platform_entry_wraps_bindings_and_internal_queue_events() {
        let mut manifest = tests_manifest();
        manifest.env.insert(
            crate::deploy::D1_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([("DB".to_string(), "main".to_string())]))
                .unwrap(),
        );
        manifest.env.insert(
            crate::deploy::DO_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "COUNTER".to_string(),
                crate::deploy::DurableObjectBinding {
                    class_name: "Counter".into(),
                    unique_key: "counter".into(),
                    enable_sql: true,
                },
            )]))
            .unwrap(),
        );
        manifest.env.insert(
            crate::deploy::QUEUE_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([("JOBS".to_string(), "jobs".to_string())]))
                .unwrap(),
        );
        manifest.env.insert(
            crate::deploy::ANALYTICS_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "METRICS".to_string(),
                "web-metrics".to_string(),
            )]))
            .unwrap(),
        );
        manifest.env.insert(
            crate::deploy::PIPELINE_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "PIPE".to_string(),
                "archive".to_string(),
            )]))
            .unwrap(),
        );
        manifest.env.insert(
            crate::deploy::WORKFLOW_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "FLOW".to_string(),
                "order-flow".to_string(),
            )]))
            .unwrap(),
        );
        manifest.env.insert(
            crate::deploy::EMAIL_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([(
                "MAILER".to_string(),
                "primary-mail".to_string(),
            )]))
            .unwrap(),
        );
        let source = rf_entry_source(
            &manifest,
            &crate::deploy::d1_bindings(&manifest),
            "test-token",
        );
        assert!(source.contains("new RandallFlareD1Database(env[name])"));
        assert!(source.contains("new RandallFlareQueue(env[name])"));
        assert!(source.contains("new RandallFlareAnalyticsDataset(env[name], context)"));
        assert!(source.contains("new RandallFlarePipeline(env[name], context)"));
        assert!(source.contains("new RandallFlareWorkflowBinding(env[name])"));
        assert!(source.contains("new RandallFlareEmailBinding(env[name])"));
        assert!(source.contains("/.rf/internal/workflow"));
        assert!(source.contains("waitForSignal"));
        assert!(source.contains("test-token"));
        assert!(source.contains("/.rf/internal/queue"));
        assert!(source.contains("/.rf/internal/email"));
        assert!(source.contains("setReject(reason)"));
        assert!(source.contains("authResults: request.headers.get"));
        assert!(source.contains("x-rf-email-dmarc"));
        assert!(source.contains("export class Counter extends __rfUserModule.Counter"));
        assert!(
            source.contains("__rfUserDefault.fetch(request, __rfWrapEnv(env, context), context)")
        );
    }

    fn tests_manifest() -> WorkerManifest {
        WorkerManifest {
            name: "test".into(),
            version: 1,
            prev: None,
            deleted: false,
            main: "index.js".into(),
            modules: vec![],
            assets: vec![],
            hostnames: vec![],
            env: BTreeMap::new(),
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-08-04".into(),
        }
    }
}
