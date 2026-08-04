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
        if !d1_bindings.is_empty() {
            for database in d1_bindings.values() {
                crate::d1::ensure_database(&self.node, database)?;
            }
            std::fs::write(
                src.join("__rf_d1_entry.js"),
                d1_entry_source(m, &d1_bindings),
            )?;
        }
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
        let config = generate_config(
            m,
            port,
            self.node.kvbind_port(),
            self.node.r2bind_port(),
            self.node.d1bind_port(),
            &durable_dir,
        );
        std::fs::write(dir.join("config.capnp"), config)?;

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
                anyhow::bail!("Worker {} 的 workerd 在启动期间退出：{status}", m.name);
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

fn d1_entry_source(
    manifest: &WorkerManifest,
    bindings: &std::collections::BTreeMap<String, String>,
) -> String {
    let import = format!("./{}", manifest.main);
    let import_literal = serde_json::to_string(&import).expect("module path is serializable");
    let binding_names = serde_json::to_string(&bindings.keys().collect::<Vec<_>>())
        .expect("binding names are serializable");
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
    D1_ENTRY_TEMPLATE
        .replace("__RF_USER_IMPORT__", &import_literal)
        .replace("__RF_D1_BINDING_NAMES__", &binding_names)
        .replace("__RF_DURABLE_WRAPPERS__", &durable_wrappers)
}

const D1_ENTRY_TEMPLATE: &str = r#"// generated by RandallFlare — native D1 facade
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

const __rfD1Names = __RF_D1_BINDING_NAMES__;
function __rfWrapEnv(env) {
  const wrapped = Object.create(env);
  for (const name of __rfD1Names) {
    Object.defineProperty(wrapped, name, {
      value: new RandallFlareD1Database(env[name]), enumerable: true, configurable: false,
    });
  }
  return wrapped;
}

const __rfOut = { ...__rfUserDefault };
if (__rfUserDefault && typeof __rfUserDefault.fetch === "function") {
  __rfOut.fetch = (request, env, context) => __rfUserDefault.fetch(request, __rfWrapEnv(env), context);
}
if (__rfUserDefault && typeof __rfUserDefault.scheduled === "function") {
  __rfOut.scheduled = (event, env, context) => __rfUserDefault.scheduled(event, __rfWrapEnv(env), context);
}
if (__rfUserDefault && typeof __rfUserDefault.queue === "function") {
  __rfOut.queue = (batch, env, context) => __rfUserDefault.queue(batch, __rfWrapEnv(env), context);
}
if (__rfUserDefault && typeof __rfUserDefault.email === "function") {
  __rfOut.email = (message, env, context) => __rfUserDefault.email(message, __rfWrapEnv(env), context);
}
export default __rfOut;
__RF_DURABLE_WRAPPERS__
"#;

/// Emit the workerd capnp config for one worker.
pub fn generate_config(
    m: &WorkerManifest,
    port: u16,
    kvbind_port: u16,
    r2bind_port: u16,
    d1bind_port: u16,
    durable_dir: &std::path::Path,
) -> String {
    let mut modules = String::new();
    if !crate::deploy::d1_bindings(m).is_empty() {
        modules.push_str(
            "        (name = \"__rf_d1_entry.js\", esModule = embed \"src/__rf_d1_entry.js\"),\n",
        );
    }
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
        {
            continue;
        }
        bindings.push_str(&format!(
            "        (name = {}, text = {}),\n",
            capnp_string(k),
            capnp_string(v)
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
{kv_services}{r2_services}{d1_services}{durable_service}  ],
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
        let cfg = generate_config(
            &m,
            30111,
            7382,
            7383,
            7384,
            std::path::Path::new("/tmp/rf-do"),
        );
        assert!(cfg.contains("esModule = embed \"src/index.js\""));
        assert!(cfg.contains("127.0.0.1:30111"));
        assert!(cfg.contains("GREETING"));
        assert!(cfg.contains("hi \\\"there\\\""));
        assert!(cfg.contains("(name = \"CACHE\", kvNamespace = (name = \"kv-CACHE\"))"));
        assert!(cfg.contains("external = (address = \"127.0.0.1:7382\""));
        assert!(cfg.contains("injectRequestHeaders = [(name = \"x-rf-kv-ns\", value = \"ns1\")]"));
        assert!(cfg.contains("(name = \"OBJECTS\", r2Bucket = (name = \"r2-OBJECTS\"))"));
        assert!(cfg.contains("address = \"127.0.0.1:7383\""));
        assert!(cfg.contains("x-rf-r2-bucket\", value = \"assets\""));
        assert!(cfg.contains("(name = \"DATABASE\", service = \"d1-DATABASE\")"));
        assert!(cfg.contains("address = \"127.0.0.1:7384\""));
        assert!(cfg.contains("x-rf-d1-database\", value = \"primary\""));
        assert!(cfg.contains("src/__rf_d1_entry.js"));
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
    fn d1_entry_wraps_fetch_and_durable_object_environments() {
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
        let source = d1_entry_source(&manifest, &crate::deploy::d1_bindings(&manifest));
        assert!(source.contains("new RandallFlareD1Database(env[name])"));
        assert!(source.contains("export class Counter extends __rfUserModule.Counter"));
        assert!(source.contains("__rfUserDefault.fetch(request, __rfWrapEnv(env), context)"));
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
