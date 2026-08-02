//! Operator-side deploy: read a worker directory, upload blobs to any
//! node, sign a manifest with the operator key, submit. The node
//! gossips it from there — deploying to one node deploys to all.
//!
//! Bundle layout:
//!   rf.json          spec (see DeploySpec)
//!   <modules>        every non-asset file = a module (main required
//!                    unless the worker is assets-only)
//!   <assets dir>/    optional static asset tree

use crate::peers::PeerClient;
use anyhow::{bail, Context, Result};
use rf_core::envelope::Envelope;
use rf_core::identity::AnyKeypair;
use rf_core::manifest::{AssetFile, Module, ModuleKind, WorkerManifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DO_METADATA_ENV: &str = "__RF_DURABLE_OBJECTS_V1";

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

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
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
    if spec.env.contains_key(DO_METADATA_ENV) {
        bail!("env key {DO_METADATA_ENV} is reserved by rf");
    }

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

    if let Some(main) = &spec.main {
        if !modules.iter().any(|(p, _, _)| p == main) {
            bail!("main module {main:?} not found in bundle");
        }
    } else if assets.is_empty() {
        bail!("worker has neither a main module nor assets");
    }
    Ok(Bundle { spec, modules, assets })
}

/// Upload all blobs + submit the signed manifest. Returns the new
/// version number.
pub async fn deploy(
    bundle: &Bundle,
    client: &PeerClient,
    node_addr: &str,
    operator: &AnyKeypair,
) -> Result<u64> {
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
                    bail!("Durable Object class {:?} has conflicting unique keys", object.class_name);
                }
            }
        }
        env.insert(DO_METADATA_ENV.into(), serde_json::to_string(&durable_objects)?);
    }
    let manifest = WorkerManifest {
        name: bundle.spec.name.clone(),
        version,
        prev,
        deleted: false,
        main: bundle.spec.main.clone().unwrap_or_default(),
        modules,
        assets,
        hostnames: bundle.spec.hostnames.iter().map(|h| h.to_ascii_lowercase()).collect(),
        env,
        kv_bindings: bundle.spec.kv.clone(),
        crons: bundle.spec.crons.clone(),
        compatibility_date: bundle.spec.compatibility_date.clone(),
    };
    manifest.validate().map_err(|e| anyhow::anyhow!("invalid manifest: {e}"))?;
    let env = Envelope::seal_any(&manifest, operator);
    client.post_manifest(node_addr, &env).await?;
    Ok(version)
}

/// Tombstone a worker.
pub async fn delete_worker(
    name: &str,
    client: &PeerClient,
    node_addr: &str,
    operator: &AnyKeypair,
) -> Result<u64> {
    let head = client.worker_head(node_addr, name).await?;
    let Some((prior, prev_digest)) = head else { bail!("no such worker: {name}") };
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
    let env = Envelope::seal_any(&manifest, operator);
    client.post_manifest(node_addr, &env).await?;
    Ok(prior + 1)
}

fn decode_sha(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("node returned bad sha")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("node returned bad sha length"))
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
            r#"{"name":"w","main":"index.js","assets":"public","hostnames":["a.example.com"]}"#,
            &[
                ("index.js", "export default {}"),
                ("lib/util.js", "export const x = 1"),
                ("public/index.html", "<h1>hi</h1>"),
                ("public/css/site.css", "body{}"),
            ],
        );
        let b = read_bundle(&dir).unwrap();
        assert_eq!(b.spec.name, "w");
        let mpaths: Vec<&str> = b.modules.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(mpaths, vec!["index.js", "lib/util.js"]);
        let apaths: Vec<&str> = b.assets.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(apaths, vec!["css/site.css", "index.html"]);
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
}
