//! Operator-side deploy: read a worker directory, upload blobs to any
//! node, sign a manifest with the operator key, submit. The node
//! gossips it from there — deploying to one node deploys to all.
//!
//! Bundle layout:
//!   rf.json          spec (see DeploySpec)
//!   <modules>        every non-asset file = a module (main required
//!                    unless the worker is assets-only)
//!   <assets dir>/    optional static asset tree

use crate::node::Node;
use crate::peers::PeerClient;
use anyhow::{bail, Context, Result};
use rf_core::envelope::Envelope;
use rf_core::identity::AnyKeypair;
use rf_core::manifest::{AssetFile, Module, ModuleKind, WorkerManifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DO_METADATA_ENV: &str = "__RF_DURABLE_OBJECTS_V1";
pub const R2_METADATA_ENV: &str = "__RF_R2_BINDINGS_V1";
pub const D1_METADATA_ENV: &str = "__RF_D1_BINDINGS_V1";
pub const QUEUE_METADATA_ENV: &str = "__RF_QUEUE_BINDINGS_V1";
pub const ANALYTICS_METADATA_ENV: &str = "__RF_ANALYTICS_BINDINGS_V1";
pub const PIPELINE_METADATA_ENV: &str = "__RF_PIPELINE_BINDINGS_V1";
pub const WORKFLOW_METADATA_ENV: &str = "__RF_WORKFLOW_BINDINGS_V1";
pub const EMAIL_METADATA_ENV: &str = "__RF_EMAIL_BINDINGS_V1";
pub const SERVICE_METADATA_ENV: &str = "__RF_SERVICE_BINDINGS_V1";
pub const SECRET_METADATA_ENV: &str = "__RF_SECRET_BINDINGS_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableObjectBinding {
    pub class_name: String,
    #[serde(default)]
    pub unique_key: String,
    #[serde(default)]
    pub enable_sql: bool,
}

pub fn durable_objects(m: &WorkerManifest) -> BTreeMap<String, DurableObjectBinding> {
    m.env
        .get(DO_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn r2_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(R2_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn d1_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(D1_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn queue_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(QUEUE_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn analytics_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(ANALYTICS_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn pipeline_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(PIPELINE_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn workflow_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(WORKFLOW_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn email_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(EMAIL_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn service_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(SERVICE_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploySpec {
    pub name: String,
    #[serde(default)]
    pub main: Option<String>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// binding name → kv namespace id.
    #[serde(default)]
    pub kv: BTreeMap<String, String>,
    /// binding name → Durable Object class configuration.
    #[serde(default)]
    pub durable_objects: BTreeMap<String, DurableObjectBinding>,
    /// binding name → signed R2 bucket name.
    #[serde(default)]
    pub r2: BTreeMap<String, String>,
    /// binding name → D1 database name.
    #[serde(default)]
    pub d1: BTreeMap<String, String>,
    /// binding name → signed Queue resource name.
    #[serde(default)]
    pub queues: BTreeMap<String, String>,
    /// binding name → signed Analytics Engine dataset name.
    #[serde(default)]
    pub analytics: BTreeMap<String, String>,
    /// binding name → signed Pipeline resource name.
    #[serde(default)]
    pub pipelines: BTreeMap<String, String>,
    /// binding name → signed Workflow resource name.
    #[serde(default)]
    pub workflows: BTreeMap<String, String>,
    /// binding name → signed Email Domain resource name.
    #[serde(default)]
    pub email: BTreeMap<String, String>,
    /// binding name → target Worker name.
    #[serde(default)]
    pub services: BTreeMap<String, String>,
    #[serde(default)]
    pub crons: Vec<String>,
    /// Relative dir of static assets.
    #[serde(default)]
    pub assets: Option<String>,
    #[serde(default = "default_compat")]
    pub compatibility_date: String,
}

fn default_compat() -> String {
    "2026-07-01".into()
}

fn module_kind(path: &Path) -> ModuleKind {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "js" | "mjs" => ModuleKind::EsModule,
        "cjs" => ModuleKind::CommonJs,
        "wasm" => ModuleKind::Wasm,
        "txt" | "html" | "css" => ModuleKind::Text,
        _ => ModuleKind::Data,
    }
}

fn validate_spec(spec: &DeploySpec) -> Result<()> {
    if spec.env.keys().any(|key| key.starts_with("__RF_")) {
        bail!("env keys beginning with __RF_ are reserved by rf");
    }
    let mut binding_names = std::collections::BTreeSet::new();
    for name in spec
        .env
        .keys()
        .chain(spec.kv.keys())
        .chain(spec.durable_objects.keys())
        .chain(spec.r2.keys())
        .chain(spec.d1.keys())
        .chain(spec.queues.keys())
        .chain(spec.analytics.keys())
        .chain(spec.pipelines.keys())
        .chain(spec.workflows.keys())
        .chain(spec.email.keys())
        .chain(spec.services.keys())
    {
        if !binding_names.insert(name) {
            bail!("binding name {name:?} is used more than once");
        }
    }
    for target in spec.services.values() {
        if !rf_core::manifest::valid_name(target) || target == &spec.name {
            bail!("invalid Worker Service binding target {target:?}");
        }
    }
    if let Some(assets) = &spec.assets {
        let path = Path::new(assets);
        if assets.is_empty()
            || assets.contains('\\')
            || path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            bail!("assets must be a safe relative directory");
        }
    }
    Ok(())
}

fn validate_bundle(bundle: &Bundle) -> Result<()> {
    if bundle
        .modules
        .iter()
        .any(|(path, _, _)| path == "__rf_entry.js" || path == "__rf_d1_entry.js")
    {
        bail!("module paths beginning with __rf_ are reserved by rf");
    }
    if let Some(main) = &bundle.spec.main {
        if !bundle.modules.iter().any(|(path, _, _)| path == main) {
            bail!("main module {main:?} not found in bundle");
        }
    } else if bundle.assets.is_empty() {
        bail!("worker has neither a main module nor assets");
    }
    Ok(())
}

fn safe_upload_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.as_bytes().iter().any(|byte| byte.is_ascii_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("bundle contains symlink: {}", path.display());
            }
            if kind.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

pub struct Bundle {
    pub spec: DeploySpec,
    /// (relative path, bytes, kind) for modules.
    pub modules: Vec<(String, Vec<u8>, ModuleKind)>,
    /// (relative path, bytes) for assets.
    pub assets: Vec<(String, Vec<u8>)>,
}

pub fn read_bundle(dir: &Path) -> Result<Bundle> {
    let spec_path = dir.join("rf.json");
    let raw = std::fs::read_to_string(&spec_path)
        .with_context(|| format!("reading {}", spec_path.display()))?;
    let spec: DeploySpec = serde_json::from_str(&raw).context("parsing rf.json")?;
    validate_spec(&spec)?;

    let assets_dir = spec.assets.as_ref().map(|a| dir.join(a));
    let mut modules = Vec::new();
    let mut assets = Vec::new();

    for path in walk(dir)? {
        let rel = path.strip_prefix(dir).unwrap();
        if rel == Path::new("rf.json") {
            continue;
        }
        if let Some(ad) = &assets_dir {
            if let Ok(arel) = path.strip_prefix(ad) {
                let bytes = std::fs::read(&path)?;
                assets.push((arel.to_string_lossy().replace('\\', "/"), bytes));
                continue;
            }
        }
        let bytes = std::fs::read(&path)?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let kind = module_kind(&path);
        modules.push((rel_str, bytes, kind));
    }

    let bundle = Bundle {
        spec,
        modules,
        assets,
    };
    validate_bundle(&bundle)?;
    Ok(bundle)
}

/// Build a bundle from browser-uploaded relative paths. The browser sends
/// bytes only; filesystem paths are never interpreted on the node.
pub fn read_bundle_files(files: Vec<(String, Vec<u8>)>) -> Result<Bundle> {
    let mut files_by_path = BTreeMap::new();
    for (path, bytes) in files {
        if !safe_upload_path(&path) {
            bail!("unsafe uploaded bundle path: {path:?}");
        }
        if files_by_path.insert(path.clone(), bytes).is_some() {
            bail!("duplicate uploaded bundle path: {path:?}");
        }
    }
    let spec_bytes = files_by_path
        .remove("rf.json")
        .ok_or_else(|| anyhow::anyhow!("uploaded bundle is missing rf.json"))?;
    let spec_raw = std::str::from_utf8(&spec_bytes).context("rf.json is not UTF-8")?;
    let spec: DeploySpec = serde_json::from_str(spec_raw).context("parsing rf.json")?;
    validate_spec(&spec)?;

    let asset_prefix = spec.assets.as_ref().map(|assets| format!("{assets}/"));
    let mut modules = Vec::new();
    let mut assets = Vec::new();
    for (path, bytes) in files_by_path {
        if let Some(prefix) = &asset_prefix {
            if let Some(asset_path) = path.strip_prefix(prefix) {
                if asset_path.is_empty() {
                    bail!("uploaded asset path is empty");
                }
                assets.push((asset_path.to_string(), bytes));
                continue;
            }
        }
        let kind = module_kind(Path::new(&path));
        modules.push((path, bytes, kind));
    }
    let bundle = Bundle {
        spec,
        modules,
        assets,
    };
    validate_bundle(&bundle)?;
    Ok(bundle)
}

/// Upload all blobs + submit the signed manifest. Returns the new
/// version number.
pub async fn deploy(
    bundle: &Bundle,
    client: &PeerClient,
    node_addr: &str,
    operator: &AnyKeypair,
) -> Result<u64> {
    let manifest = prepare_manifest(bundle, client, node_addr).await?;
    let version = manifest.version;
    let env = Envelope::seal_any(&manifest, operator);
    client.post_manifest(node_addr, &env).await?;
    Ok(version)
}

/// Upload bundle blobs and build the exact canonical manifest that the
/// operator must sign. No cluster state changes until the signed envelope is
/// submitted.
pub async fn prepare_manifest(
    bundle: &Bundle,
    client: &PeerClient,
    node_addr: &str,
) -> Result<WorkerManifest> {
    let head = client.worker_head(node_addr, &bundle.spec.name).await?;
    let version = head.map(|(v, _)| v).unwrap_or(0) + 1;
    let prev = head.map(|(_, digest)| digest);

    let mut modules = Vec::new();
    for (path, bytes, kind) in &bundle.modules {
        let sha_hex = client.put_blob(node_addr, bytes.clone()).await?;
        let sha = decode_sha(&sha_hex)?;
        modules.push(Module {
            path: path.clone(),
            sha256: sha,
            kind: *kind,
            size: bytes.len() as u64,
        });
    }
    let mut assets = Vec::new();
    for (path, bytes) in &bundle.assets {
        let sha_hex = client.put_blob(node_addr, bytes.clone()).await?;
        assets.push(AssetFile {
            path: path.clone(),
            sha256: decode_sha(&sha_hex)?,
            size: bytes.len() as u64,
        });
    }

    manifest_from_bundle(bundle, version, prev, modules, assets)
}

/// Node-local counterpart of [`prepare_manifest`], used by Git builds. Blobs
/// enter the same content-addressed store and are then available to peers
/// through the normal blob fetch API.
pub fn prepare_manifest_local(bundle: &Bundle, node: &Node) -> Result<WorkerManifest> {
    let head = node.manifest_head(&bundle.spec.name);
    let version = head.map(|(value, _)| value).unwrap_or(0) + 1;
    let prev = head.map(|(_, digest)| digest);
    let mut modules = Vec::new();
    for (path, bytes, kind) in &bundle.modules {
        modules.push(Module {
            path: path.clone(),
            sha256: node.blobs.put(bytes)?,
            kind: *kind,
            size: bytes.len() as u64,
        });
    }
    let mut assets = Vec::new();
    for (path, bytes) in &bundle.assets {
        assets.push(AssetFile {
            path: path.clone(),
            sha256: node.blobs.put(bytes)?,
            size: bytes.len() as u64,
        });
    }
    manifest_from_bundle(bundle, version, prev, modules, assets)
}

fn manifest_from_bundle(
    bundle: &Bundle,
    version: u64,
    prev: Option<[u8; 32]>,
    modules: Vec<Module>,
    assets: Vec<AssetFile>,
) -> Result<WorkerManifest> {
    let mut durable_objects = bundle.spec.durable_objects.clone();
    for binding in durable_objects.values_mut() {
        if binding.unique_key.is_empty() {
            binding.unique_key = format!("rf--{}--{}", bundle.spec.name, binding.class_name);
        }
    }
    let mut env = bundle.spec.env.clone();
    if !durable_objects.is_empty() {
        let identifier = |s: &str| {
            let mut chars = s.chars();
            chars
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
                .unwrap_or(false)
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        };
        let mut classes = BTreeMap::new();
        for (binding, object) in &durable_objects {
            if !identifier(binding)
                || !identifier(&object.class_name)
                || object.unique_key.contains('/')
                || object.unique_key.contains('\\')
                || object.unique_key == "."
                || object.unique_key == ".."
            {
                bail!("invalid Durable Object binding {binding:?}");
            }
            if let Some(prior) = classes.insert(&object.class_name, &object.unique_key) {
                if prior != &object.unique_key {
                    bail!(
                        "Durable Object class {:?} has conflicting unique keys",
                        object.class_name
                    );
                }
            }
        }
        env.insert(
            DO_METADATA_ENV.into(),
            serde_json::to_string(&durable_objects)?,
        );
    }
    if !bundle.spec.r2.is_empty() {
        let identifier = |s: &str| {
            let mut chars = s.chars();
            chars
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
                .unwrap_or(false)
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        };
        for (binding, bucket) in &bundle.spec.r2 {
            if !identifier(binding) || !rf_core::manifest::valid_name(bucket) {
                bail!("invalid R2 binding {binding:?}");
            }
        }
        env.insert(
            R2_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.r2)?,
        );
    }
    if !bundle.spec.d1.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters
                .next()
                .map(|character| {
                    character.is_ascii_alphabetic() || character == '_' || character == '$'
                })
                .unwrap_or(false)
                && characters.all(|character| {
                    character.is_ascii_alphanumeric() || character == '_' || character == '$'
                })
        };
        for (binding, database) in &bundle.spec.d1 {
            if !identifier(binding)
                || !rf_core::manifest::valid_name(database)
                || database.starts_with("r2-")
                || database.starts_with("rfdo-")
            {
                bail!("invalid D1 binding {binding:?}");
            }
        }
        env.insert(
            D1_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.d1)?,
        );
    }
    if !bundle.spec.queues.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            }) && characters.all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        };
        for (binding, queue) in &bundle.spec.queues {
            if !identifier(binding) || !rf_core::manifest::valid_name(queue) {
                bail!("invalid Queue binding {binding:?}");
            }
        }
        env.insert(
            QUEUE_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.queues)?,
        );
    }
    if !bundle.spec.analytics.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            }) && characters.all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        };
        for (binding, dataset) in &bundle.spec.analytics {
            if !identifier(binding) || !rf_core::manifest::valid_name(dataset) {
                bail!("invalid Analytics binding {binding:?}");
            }
        }
        env.insert(
            ANALYTICS_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.analytics)?,
        );
    }
    if !bundle.spec.pipelines.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            }) && characters.all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        };
        for (binding, pipeline) in &bundle.spec.pipelines {
            if !identifier(binding) || !rf_core::manifest::valid_name(pipeline) {
                bail!("invalid Pipeline binding {binding:?}");
            }
        }
        env.insert(
            PIPELINE_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.pipelines)?,
        );
    }
    if !bundle.spec.workflows.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            }) && characters.all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        };
        for (binding, workflow) in &bundle.spec.workflows {
            if !identifier(binding) || !rf_core::manifest::valid_name(workflow) {
                bail!("invalid Workflow binding {binding:?}");
            }
        }
        env.insert(
            WORKFLOW_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.workflows)?,
        );
    }
    if !bundle.spec.email.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            }) && characters.all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        };
        for (binding, domain) in &bundle.spec.email {
            if !identifier(binding) || !rf_core::manifest::valid_name(domain) {
                bail!("invalid Email binding {binding:?}");
            }
        }
        env.insert(
            EMAIL_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.email)?,
        );
    }
    if !bundle.spec.services.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            }) && characters.all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        };
        for (binding, target) in &bundle.spec.services {
            if !identifier(binding)
                || !rf_core::manifest::valid_name(target)
                || target == &bundle.spec.name
            {
                bail!("invalid Worker Service binding {binding:?}");
            }
        }
        env.insert(
            SERVICE_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.services)?,
        );
    }
    let manifest = WorkerManifest {
        name: bundle.spec.name.clone(),
        version,
        prev,
        deleted: false,
        main: bundle.spec.main.clone().unwrap_or_default(),
        modules,
        assets,
        hostnames: bundle
            .spec
            .hostnames
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
        env,
        kv_bindings: bundle.spec.kv.clone(),
        crons: bundle.spec.crons.clone(),
        compatibility_date: bundle.spec.compatibility_date.clone(),
    };
    manifest
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid manifest: {e}"))?;
    Ok(manifest)
}

/// Tombstone a worker.
pub async fn delete_worker(
    name: &str,
    client: &PeerClient,
    node_addr: &str,
    operator: &AnyKeypair,
) -> Result<u64> {
    let manifest = prepare_delete(name, client, node_addr).await?;
    let version = manifest.version;
    let env = Envelope::seal_any(&manifest, operator);
    client.post_manifest(node_addr, &env).await?;
    Ok(version)
}

pub async fn prepare_delete(
    name: &str,
    client: &PeerClient,
    node_addr: &str,
) -> Result<WorkerManifest> {
    let head = client.worker_head(node_addr, name).await?;
    let Some((prior, prev_digest)) = head else {
        bail!("no such worker: {name}")
    };
    let manifest = WorkerManifest {
        name: name.to_string(),
        version: prior + 1,
        prev: Some(prev_digest),
        deleted: true,
        main: String::new(),
        modules: vec![],
        assets: vec![],
        hostnames: vec![],
        env: BTreeMap::new(),
        kv_bindings: BTreeMap::new(),
        crons: vec![],
        compatibility_date: String::new(),
    };
    Ok(manifest)
}

fn decode_sha(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("node returned bad sha")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("node returned bad sha length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_bundle(dir: &Path, spec: &str, files: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("rf.json"), spec).unwrap();
        for (path, content) in files {
            let p = dir.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
    }

    #[test]
    fn reads_hybrid_bundle() {
        let dir = std::env::temp_dir().join(format!("rf-bundle-{}", rand::random::<u32>()));
        write_bundle(
            &dir,
            r#"{"name":"w","main":"index.js","assets":"public","hostnames":["a.example.com"],"services":{"BACKEND":"backend"}}"#,
            &[
                ("index.js", "export default {}"),
                ("lib/util.js", "export const x = 1"),
                ("public/index.html", "<h1>hi</h1>"),
                ("public/css/site.css", "body{}"),
            ],
        );
        let b = read_bundle(&dir).unwrap();
        assert_eq!(b.spec.name, "w");
        assert_eq!(b.spec.services["BACKEND"], "backend");
        let mpaths: Vec<&str> = b.modules.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(mpaths, vec!["index.js", "lib/util.js"]);
        let apaths: Vec<&str> = b.assets.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(apaths, vec!["css/site.css", "index.html"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn worker_service_binding_cannot_target_itself() {
        let dir = std::env::temp_dir().join(format!("rf-bundle-{}", rand::random::<u32>()));
        write_bundle(
            &dir,
            r#"{"name":"frontend","main":"index.js","services":{"SELF":"frontend"}}"#,
            &[("index.js", "export default {}")],
        );
        assert!(read_bundle(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn assets_only_bundle_ok_and_empty_bundle_rejected() {
        let dir = std::env::temp_dir().join(format!("rf-bundle-{}", rand::random::<u32>()));
        write_bundle(
            &dir,
            r#"{"name":"site","assets":"public"}"#,
            &[("public/index.html", "<h1>hi</h1>")],
        );
        assert!(read_bundle(&dir).is_ok());
        std::fs::remove_dir_all(&dir).ok();

        let dir2 = std::env::temp_dir().join(format!("rf-bundle-{}", rand::random::<u32>()));
        write_bundle(&dir2, r#"{"name":"empty"}"#, &[]);
        assert!(read_bundle(&dir2).is_err());
        std::fs::remove_dir_all(&dir2).ok();
    }

    #[test]
    fn browser_uploaded_bundle_uses_only_safe_relative_paths() {
        let bundle = read_bundle_files(vec![
            (
                "rf.json".into(),
                br#"{"name":"browser-site","assets":"public"}"#.to_vec(),
            ),
            ("public/index.html".into(), b"<h1>browser</h1>".to_vec()),
        ])
        .unwrap();
        assert_eq!(bundle.spec.name, "browser-site");
        assert_eq!(bundle.assets[0].0, "index.html");
        assert!(read_bundle_files(vec![
            (
                "rf.json".into(),
                br#"{"name":"bad","main":"index.js"}"#.to_vec(),
            ),
            ("../index.js".into(), b"export default {}".to_vec()),
        ])
        .is_err());
        assert!(read_bundle_files(vec![
            (
                "rf.json".into(),
                br#"{"name":"duplicate","main":"index.js"}"#.to_vec(),
            ),
            ("index.js".into(), b"one".to_vec()),
            ("index.js".into(), b"two".to_vec()),
        ])
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bundle_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("rf-bundle-{}", rand::random::<u32>()));
        write_bundle(
            &dir,
            r#"{"name":"w","main":"index.js"}"#,
            &[("index.js", "export default {}")],
        );
        symlink("/etc/passwd", dir.join("secret.txt")).unwrap();
        assert!(read_bundle(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
