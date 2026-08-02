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
//! verified against workerd 2026-07-31 (see kvbind.rs).

use crate::node::{Node, NodeEvent};
use anyhow::{Context, Result};
use rf_core::manifest::{ModuleKind, WorkerManifest};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::{Child, Command};

pub struct Runtime {
    node: Arc<Node>,
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
    pub fn new(node: Arc<Node>) -> Self {
        let workerd = node
            .cfg
            .runtime
            .workerd
            .clone()
            .or_else(|| which_workerd());
        if workerd.is_none() {
            tracing::warn!(
                "workerd binary not found — module workers disabled, assets still serve"
            );
        }
        let port_base = node.cfg.runtime.port_base;
        Self { node, workerd, port_base, running: HashMap::new() }
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
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
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
                    tracing::warn!("workerd for {name} exited: {status}");
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
                if !crate::deploy::durable_objects(m).is_empty()
                    && !self.node.cfg.runtime.allow_local_durable_objects
                {
                    tracing::warn!(
                        "worker {} declares Durable Objects but has no quorum-fenced owner; refusing to start",
                        m.name
                    );
                    false
                } else {
                    true
                }
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
                tracing::info!("stopped worker {name}");
            }
        }

        for m in desired {
            let current = self.running.get(&m.name);
            let up = current.map(|rw| rw.child.is_some()).unwrap_or(false);
            if current.map(|rw| rw.version) == Some(m.version) && up {
                continue; // already running this version
            }
            if self.node.missing_blobs().iter().any(|s| m.blob_refs().any(|r| r == *s)) {
                tracing::debug!("worker {} waiting for blobs", m.name);
                continue;
            }
            match self.start_worker(&m).await {
                Ok(()) => {}
                Err(e) => tracing::warn!("starting worker {}: {e:#}", m.name),
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
        let used: std::collections::HashSet<u16> =
            self.running.values().map(|r| r.port).collect();
        for _ in 0..1000 {
            let port = self.port_base + slot;
            if !used.contains(&port)
                && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
            {
                return port;
            }
            slot = (slot + 1) % 1000;
        }
        self.port_base // hopeless; spawn will fail loudly
    }

    async fn start_worker(&mut self, m: &WorkerManifest) -> Result<()> {
        let Some(workerd) = &self.workerd else {
            return Ok(()); // no runtime on this node
        };
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
            let bytes = self.node.blobs.get(&module.sha256).context("module blob")?;
            std::fs::write(&path, bytes)?;
        }
        let durable_dir = self.node.cfg.data_dir.join("durable").join(&m.name);
        std::fs::create_dir_all(&durable_dir)?;
        let config = generate_config(m, port, self.node.kvbind_port(), &durable_dir);
        std::fs::write(dir.join("config.capnp"), config)?;

        // Kill the old version and WAIT for it to exit — spawning the
        // new one while the old still holds the port is a bind race.
        if let Some(rw) = self.running.get_mut(&m.name) {
            if let Some(child) = &mut rw.child {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    child.wait(),
                )
                .await;
            }
            rw.child = None;
        }

        let mut cmd = Command::new(workerd);
        cmd.arg("serve");
        if !crate::deploy::durable_objects(m).is_empty() {
            cmd.arg("--experimental");
        }
        cmd.arg(dir.join("config.capnp"))
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
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
        let mut child =
            cmd.spawn().with_context(|| format!("spawning workerd for {}", m.name))?;

        // Wait until the socket actually answers (or the child dies) —
        // a bind failure otherwise looks like success for 10 seconds.
        let mut healthy = false;
        for _ in 0..50 {
            if let Ok(Some(status)) = child.try_wait() {
                anyhow::bail!("workerd for {} exited during startup: {status}", m.name);
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                healthy = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !healthy {
            let _ = child.start_kill();
            anyhow::bail!("workerd for {} never bound 127.0.0.1:{port}", m.name);
        }

        tracing::info!("worker {} v{} on 127.0.0.1:{port}", m.name, m.version);
        self.running
            .insert(m.name.clone(), RunningWorker { version: m.version, port, child: Some(child) });
        Ok(())
    }
}

use sha2::Digest;

fn which_workerd() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("workerd");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Emit the workerd capnp config for one worker.
pub fn generate_config(
    m: &WorkerManifest,
    port: u16,
    kvbind_port: u16,
    durable_dir: &std::path::Path,
) -> String {
    let mut modules = String::new();
    for module in &m.modules {
        let kind = match module.kind {
            ModuleKind::EsModule => "esModule",
            ModuleKind::CommonJs => "commonJsModule",
            ModuleKind::Wasm => "wasm",
            ModuleKind::Text => "text",
            ModuleKind::Data => "data",
        };
        modules.push_str(&format!(
            "        (name = \"{}\", {kind} = embed \"src/{}\"),\n",
            module.path, module.path
        ));
    }
    let mut bindings = String::new();
    for (k, v) in &m.env {
        if k == crate::deploy::DO_METADATA_ENV {
            continue;
        }
        bindings.push_str(&format!(
            "        (name = \"{}\", text = {}),\n",
            k,
            capnp_string(v)
        ));
    }
    // Native kvNamespace bindings: each one routes to the node's
    // loopback kvbind server, namespace carried in an injected header.
    let mut kv_services = String::new();
    for (binding, ns) in &m.kv_bindings {
        bindings.push_str(&format!(
            "        (name = \"{binding}\", kvNamespace = (name = \"kv-{binding}\")),\n"
        ));
        kv_services.push_str(&format!(
            "    (name = \"kv-{binding}\", external = (address = \"127.0.0.1:{kvbind_port}\", \
             http = (injectRequestHeaders = [(name = \"{ns_header}\", value = {ns_val})]))),\n",
            ns_header = crate::kvbind::NS_HEADER,
            ns_val = capnp_string(ns),
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
      compatibilityDate = "{compat}",
      bindings = [
{bindings}      ],
{durable_worker}    )),
{kv_services}{durable_service}  ],
  sockets = [
    (name = "http", address = "127.0.0.1:{port}", http = (), service = "main"),
  ],
);
"#,
        compat = m.compatibility_date,
    )
}

fn capnp_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
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
        let cfg = generate_config(&m, 30111, 7382, std::path::Path::new("/tmp/rf-do"));
        assert!(cfg.contains("esModule = embed \"src/index.js\""));
        assert!(cfg.contains("127.0.0.1:30111"));
        assert!(cfg.contains("GREETING"));
        assert!(cfg.contains("hi \\\"there\\\""));
        assert!(cfg.contains("(name = \"CACHE\", kvNamespace = (name = \"kv-CACHE\"))"));
        assert!(cfg.contains("external = (address = \"127.0.0.1:7382\""));
        assert!(cfg.contains("injectRequestHeaders = [(name = \"x-rf-kv-ns\", value = \"ns1\")]"));
        assert!(cfg.contains("compatibilityDate = \"2026-07-31\""));
        assert!(cfg.contains("durableObjectNamespace = (className = \"Counter\")"));
        assert!(cfg.contains("uniqueKey = \"rf--w--Counter\", enableSql = true"));
        assert!(cfg.contains("durableObjectStorage = (localDisk = \"do-storage\")"));
        assert!(cfg.contains("disk = (path = \"/tmp/rf-do\", writable = true)"));
    }
}
