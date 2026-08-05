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
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ARCHIVE_FILES: usize = 2_048;

pub const DO_METADATA_ENV: &str = "__RF_DURABLE_OBJECTS_V1";
pub const R2_METADATA_ENV: &str = "__RF_R2_BINDINGS_V1";
pub const D1_METADATA_ENV: &str = "__RF_D1_BINDINGS_V1";
pub const QUEUE_METADATA_ENV: &str = "__RF_QUEUE_BINDINGS_V1";
pub const ANALYTICS_METADATA_ENV: &str = "__RF_ANALYTICS_BINDINGS_V1";
pub const PIPELINE_METADATA_ENV: &str = "__RF_PIPELINE_BINDINGS_V1";
pub const WORKFLOW_METADATA_ENV: &str = "__RF_WORKFLOW_BINDINGS_V1";
pub const EMAIL_METADATA_ENV: &str = "__RF_EMAIL_BINDINGS_V1";
pub const SERVICE_METADATA_ENV: &str = "__RF_SERVICE_BINDINGS_V1";
pub const BINARY_METADATA_ENV: &str = "__RF_BINARY_BINDINGS_V1";
pub const SECRET_METADATA_ENV: &str = "__RF_SECRET_BINDINGS_V1";
pub const COMPATIBILITY_FLAGS_METADATA_ENV: &str = "__RF_COMPATIBILITY_FLAGS_V1";
pub const REQUIRED_TAGS_METADATA_ENV: &str = crate::placement::REQUIRED_TAGS_METADATA_ENV;

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

/// Return deterministic Worker Service cycles. Missing targets are allowed so
/// services may be deployed in either order; as soon as the target exists its
/// outgoing edges participate in cycle detection.
pub fn service_binding_cycles(manifests: &[WorkerManifest]) -> Vec<Vec<String>> {
    let graph = manifests
        .iter()
        .filter(|manifest| !manifest.deleted)
        .map(|manifest| {
            (
                manifest.name.clone(),
                service_bindings(manifest).into_values().collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    cycles_in_service_graph(&graph)
}

pub fn validate_service_binding_graph(node: &Node, replacement: &WorkerManifest) -> Result<()> {
    if replacement.deleted {
        return Ok(());
    }
    let mut manifests = node
        .live_manifests()
        .into_iter()
        .filter(|manifest| manifest.name != replacement.name)
        .collect::<Vec<_>>();
    manifests.push(replacement.clone());
    if let Some(cycle) = service_binding_cycles(&manifests).first() {
        bail!("Worker Service 绑定存在循环：{}", cycle.join(" → "));
    }
    Ok(())
}

fn cycles_in_service_graph(graph: &BTreeMap<String, Vec<String>>) -> Vec<Vec<String>> {
    fn visit(
        worker: &str,
        graph: &BTreeMap<String, Vec<String>>,
        states: &mut BTreeMap<String, u8>,
        stack: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        match states.get(worker).copied().unwrap_or(0) {
            2 => return,
            1 => {
                if let Some(start) = stack.iter().position(|item| item == worker) {
                    let mut cycle = stack[start..].to_vec();
                    cycle.push(worker.to_string());
                    cycles.push(cycle);
                }
                return;
            }
            _ => {}
        }
        states.insert(worker.to_string(), 1);
        stack.push(worker.to_string());
        if let Some(targets) = graph.get(worker) {
            for target in targets {
                visit(target, graph, states, stack, cycles);
            }
        }
        stack.pop();
        states.insert(worker.to_string(), 2);
    }

    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    let mut cycles = Vec::new();
    for worker in graph.keys() {
        visit(worker, graph, &mut states, &mut stack, &mut cycles);
    }
    cycles
}

pub fn binary_bindings(m: &WorkerManifest) -> BTreeMap<String, String> {
    m.env
        .get(BINARY_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn compatibility_flags(m: &WorkerManifest) -> Vec<String> {
    m.env
        .get(COMPATIBILITY_FLAGS_METADATA_ENV)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

pub fn required_tags(m: &WorkerManifest) -> Vec<String> {
    crate::placement::required_tags(m)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// binding name → signed Binary Deliver resource name.
    #[serde(default)]
    pub binaries: BTreeMap<String, String>,
    #[serde(default)]
    pub crons: Vec<String>,
    /// Relative dir of static assets.
    #[serde(default)]
    pub assets: Option<String>,
    #[serde(default = "default_compat")]
    pub compatibility_date: String,
    #[serde(default)]
    pub compatibility_flags: Vec<String>,
    /// Node capability tags that must all be present before this Worker runs.
    #[serde(default)]
    pub required_tags: Vec<String>,
}

fn default_compat() -> String {
    "2026-07-01".into()
}

pub(crate) fn module_kind(path: &Path) -> ModuleKind {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "js" | "mjs" => ModuleKind::EsModule,
        "cjs" => ModuleKind::CommonJs,
        "wasm" => ModuleKind::Wasm,
        "txt" | "html" | "css" => ModuleKind::Text,
        _ => ModuleKind::Data,
    }
}

pub(crate) fn reserved_module_path(path: &str) -> bool {
    matches!(
        path,
        "__rf_entry.js" | "__rf_d1_entry.js" | "__rf_workflow.js"
    )
}

fn validate_spec(spec: &DeploySpec) -> Result<()> {
    if spec.env.keys().any(|key| key.starts_with("__RF_")) {
        bail!("env keys beginning with __RF_ are reserved by rf");
    }
    crate::placement::normalize_tags(spec.required_tags.clone())?;
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
        .chain(spec.binaries.keys())
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
    for binary in spec.binaries.values() {
        if !rf_core::manifest::valid_name(binary) {
            bail!("invalid Binary Deliver binding target {binary:?}");
        }
    }
    validate_compatibility_flags(&spec.compatibility_flags)?;
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

pub fn validate_compatibility_flags(flags: &[String]) -> Result<()> {
    if flags.len() > 128 {
        bail!("a Worker may have at most 128 compatibility flags");
    }
    let mut seen = std::collections::BTreeSet::new();
    for flag in flags {
        if flag.is_empty()
            || flag.len() > 100
            || !flag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !seen.insert(flag)
        {
            bail!("invalid or duplicate compatibility flag {flag:?}");
        }
    }
    Ok(())
}

fn validate_bundle(bundle: &Bundle) -> Result<()> {
    if bundle
        .modules
        .iter()
        .any(|(path, _, _)| reserved_module_path(path))
    {
        bail!("generated __rf_ module path is reserved by rf");
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

/// Decode ZIP, TAR or gzip-compressed TAR without ever materializing paths on
/// the node filesystem. Entry count, expanded bytes, path depth and special
/// file types are bounded before the ordinary bundle validator runs.
pub fn read_bundle_archive(bytes: &[u8], filename: &str) -> Result<Bundle> {
    if bytes.is_empty() || bytes.len() > MAX_ARCHIVE_BYTES {
        bail!("Worker 压缩包必须在 1 字节至 64 MiB 之间");
    }
    let lower = filename.to_ascii_lowercase();
    let files = if bytes.starts_with(b"PK\x03\x04") || lower.ends_with(".zip") {
        read_zip_files(bytes)?
    } else if bytes.starts_with(&[0x1f, 0x8b])
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
    {
        let decoder = flate2::read::GzDecoder::new(bytes);
        read_tar_files(decoder)?
    } else if lower.ends_with(".tar") || bytes.len() >= 512 {
        read_tar_files(Cursor::new(bytes))?
    } else {
        bail!("只支持 .zip、.tar、.tar.gz 或 .tgz Worker 包");
    };
    read_bundle_files(strip_single_archive_root(files)?)
}

fn read_zip_files(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("解析 ZIP Worker 包")?;
    if archive.len() > MAX_ARCHIVE_FILES.saturating_mul(2) {
        bail!("ZIP 条目过多");
    }
    let mut files = Vec::new();
    let mut total = 0usize;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("读取 ZIP 条目")?;
        if entry.is_dir() {
            continue;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 != 0 && mode & 0o170000 != 0o100000)
        {
            bail!("ZIP Worker 包不能包含符号链接或特殊文件");
        }
        let path = entry.name().to_string();
        validate_archive_path(&path)?;
        let remaining = MAX_ARCHIVE_BYTES.saturating_sub(total);
        let mut content = Vec::with_capacity((entry.size() as usize).min(remaining));
        entry
            .by_ref()
            .take(remaining.saturating_add(1) as u64)
            .read_to_end(&mut content)
            .context("展开 ZIP 条目")?;
        total = total.saturating_add(content.len());
        if total > MAX_ARCHIVE_BYTES {
            bail!("ZIP 展开后超过 64 MiB");
        }
        files.push((path, content));
        if files.len() > MAX_ARCHIVE_FILES {
            bail!("ZIP 文件数超过 2,048");
        }
    }
    Ok(files)
}

fn read_tar_files(reader: impl Read) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = tar::Archive::new(reader);
    let mut files = Vec::new();
    let mut total = 0usize;
    for entry in archive.entries().context("解析 TAR Worker 包")? {
        let mut entry = entry.context("读取 TAR 条目")?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            bail!("TAR Worker 包不能包含链接、设备或其他特殊文件");
        }
        let path = entry
            .path()
            .context("读取 TAR 路径")?
            .to_string_lossy()
            .replace('\\', "/");
        validate_archive_path(&path)?;
        let remaining = MAX_ARCHIVE_BYTES.saturating_sub(total);
        let mut content = Vec::with_capacity((entry.size() as usize).min(remaining));
        entry
            .by_ref()
            .take(remaining.saturating_add(1) as u64)
            .read_to_end(&mut content)
            .context("展开 TAR 条目")?;
        total = total.saturating_add(content.len());
        if total > MAX_ARCHIVE_BYTES {
            bail!("TAR 展开后超过 64 MiB");
        }
        files.push((path, content));
        if files.len() > MAX_ARCHIVE_FILES {
            bail!("TAR 文件数超过 2,048");
        }
    }
    Ok(files)
}

fn validate_archive_path(path: &str) -> Result<()> {
    if !safe_upload_path(path) || path.split('/').count() > 64 {
        bail!("压缩包含有不安全或过深的路径：{path:?}");
    }
    Ok(())
}

fn strip_single_archive_root(mut files: Vec<(String, Vec<u8>)>) -> Result<Vec<(String, Vec<u8>)>> {
    if files.iter().any(|(path, _)| path == "rf.json") {
        return Ok(files);
    }
    let root = files
        .first()
        .and_then(|(path, _)| path.split('/').next())
        .filter(|root| !root.is_empty())
        .ok_or_else(|| anyhow::anyhow!("压缩包中没有文件"))?
        .to_string();
    let prefix = format!("{root}/");
    if !files.iter().all(|(path, _)| path.starts_with(&prefix)) {
        bail!("压缩包根目录中缺少 rf.json");
    }
    for (path, _) in &mut files {
        *path = path
            .strip_prefix(&prefix)
            .ok_or_else(|| anyhow::anyhow!("压缩包目录结构不一致"))?
            .to_string();
        validate_archive_path(path)?;
    }
    if !files.iter().any(|(path, _)| path == "rf.json") {
        bail!("压缩包中缺少 rf.json");
    }
    Ok(files)
}

/// Reconstruct a deployable, secret-redacted bundle from a signed manifest.
/// Blob bytes must be fetched and hash-verified by the caller. Secrets are
/// intentionally absent: an export must never turn write-only values back
/// into readable material.
pub fn export_bundle_files(
    manifest: &WorkerManifest,
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let module_paths = manifest
        .modules
        .iter()
        .map(|module| module.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut assets_dir = "public".to_string();
    let mut suffix = 0u16;
    while module_paths
        .iter()
        .any(|path| **path == assets_dir || path.starts_with(&format!("{assets_dir}/")))
    {
        suffix = suffix.saturating_add(1);
        assets_dir = format!("public-{suffix}");
    }
    let mut env = manifest.env.clone();
    for key in [
        DO_METADATA_ENV,
        R2_METADATA_ENV,
        D1_METADATA_ENV,
        QUEUE_METADATA_ENV,
        ANALYTICS_METADATA_ENV,
        PIPELINE_METADATA_ENV,
        WORKFLOW_METADATA_ENV,
        EMAIL_METADATA_ENV,
        SERVICE_METADATA_ENV,
        BINARY_METADATA_ENV,
        SECRET_METADATA_ENV,
        COMPATIBILITY_FLAGS_METADATA_ENV,
        REQUIRED_TAGS_METADATA_ENV,
    ] {
        env.remove(key);
    }
    let spec = DeploySpec {
        name: manifest.name.clone(),
        main: (!manifest.main.is_empty()).then(|| manifest.main.clone()),
        hostnames: manifest.hostnames.clone(),
        env,
        kv: manifest.kv_bindings.clone(),
        durable_objects: durable_objects(manifest),
        r2: r2_bindings(manifest),
        d1: d1_bindings(manifest),
        queues: queue_bindings(manifest),
        analytics: analytics_bindings(manifest),
        pipelines: pipeline_bindings(manifest),
        workflows: workflow_bindings(manifest),
        email: email_bindings(manifest),
        services: service_bindings(manifest),
        binaries: binary_bindings(manifest),
        crons: manifest.crons.clone(),
        assets: (!manifest.assets.is_empty()).then_some(assets_dir.clone()),
        compatibility_date: manifest.compatibility_date.clone(),
        compatibility_flags: compatibility_flags(manifest),
        required_tags: required_tags(manifest),
    };
    validate_spec(&spec)?;
    let mut files = vec![(
        "rf.json".into(),
        serde_json::to_vec_pretty(&spec).context("序列化 rf.json")?,
    )];
    for module in &manifest.modules {
        files.push((
            module.path.clone(),
            export_blob(&blobs, module.sha256, module.size)?,
        ));
    }
    for asset in &manifest.assets {
        files.push((
            format!("{assets_dir}/{}", asset.path),
            export_blob(&blobs, asset.sha256, asset.size)?,
        ));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let total = files.iter().try_fold(0usize, |total, (_, bytes)| {
        total
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("导出包大小溢出"))
    })?;
    if files.len() > MAX_ARCHIVE_FILES || total > MAX_ARCHIVE_BYTES {
        bail!("Worker 导出内容超过 2,048 个文件或 64 MiB");
    }
    Ok(files)
}

fn export_blob(
    blobs: &BTreeMap<[u8; 32], Vec<u8>>,
    sha256: [u8; 32],
    size: u64,
) -> Result<Vec<u8>> {
    let bytes = blobs
        .get(&sha256)
        .ok_or_else(|| anyhow::anyhow!("导出所需内容块缺失：{}", hex::encode(sha256)))?;
    if bytes.len() as u64 != size || crate::blob::sha256_hex(bytes) != hex::encode(sha256) {
        bail!("导出内容块的大小或 SHA-256 不匹配");
    }
    Ok(bytes.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Zip,
    Tar,
    TarGz,
}

pub fn write_bundle_archive(files: &[(String, Vec<u8>)], format: ExportFormat) -> Result<Vec<u8>> {
    match format {
        ExportFormat::Zip => write_zip(files),
        ExportFormat::Tar => write_tar(files, false),
        ExportFormat::TarGz => write_tar(files, true),
    }
}

fn write_zip(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);
    for (path, bytes) in files {
        validate_archive_path(path)?;
        writer.start_file(path, options).context("创建 ZIP 条目")?;
        writer.write_all(bytes).context("写入 ZIP 条目")?;
    }
    Ok(writer.finish().context("完成 ZIP 导出")?.into_inner())
}

fn write_tar(files: &[(String, Vec<u8>)], gzip: bool) -> Result<Vec<u8>> {
    if gzip {
        let encoder = flate2::GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        append_tar_files(&mut archive, files)?;
        let encoder = archive.into_inner().context("完成 TAR 写入")?;
        encoder.finish().context("完成 gzip 导出")
    } else {
        let mut archive = tar::Builder::new(Vec::new());
        append_tar_files(&mut archive, files)?;
        archive.into_inner().context("完成 TAR 导出")
    }
}

fn append_tar_files<W: Write>(
    archive: &mut tar::Builder<W>,
    files: &[(String, Vec<u8>)],
) -> Result<()> {
    for (path, bytes) in files {
        validate_archive_path(path)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, path, Cursor::new(bytes))
            .context("写入 TAR 条目")?;
    }
    archive.finish().context("完成 TAR 归档")
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
    if !bundle.spec.binaries.is_empty() {
        let identifier = |value: &str| {
            let mut characters = value.chars();
            characters.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            }) && characters.all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        };
        for (binding, binary) in &bundle.spec.binaries {
            if !identifier(binding) || !rf_core::manifest::valid_name(binary) {
                bail!("invalid Binary Deliver binding {binding:?}");
            }
        }
        env.insert(
            BINARY_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.binaries)?,
        );
    }
    if !bundle.spec.compatibility_flags.is_empty() {
        validate_compatibility_flags(&bundle.spec.compatibility_flags)?;
        env.insert(
            COMPATIBILITY_FLAGS_METADATA_ENV.into(),
            serde_json::to_string(&bundle.spec.compatibility_flags)?,
        );
    }
    if !bundle.spec.required_tags.is_empty() {
        let tags = crate::placement::normalize_tags(bundle.spec.required_tags.clone())?;
        env.insert(
            REQUIRED_TAGS_METADATA_ENV.into(),
            serde_json::to_string(&tags)?,
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

    fn digest(bytes: &[u8]) -> [u8; 32] {
        hex::decode(crate::blob::sha256_hex(bytes))
            .unwrap()
            .try_into()
            .unwrap()
    }

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
            r#"{"name":"w","main":"index.js","assets":"public","hostnames":["a.example.com"],"services":{"BACKEND":"backend"},"compatibility_flags":["nodejs_compat"]}"#,
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
        assert_eq!(b.spec.compatibility_flags, ["nodejs_compat"]);
        let mpaths: Vec<&str> = b.modules.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(mpaths, vec!["index.js", "lib/util.js"]);
        let apaths: Vec<&str> = b.assets.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(apaths, vec!["css/site.css", "index.html"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn zip_tar_and_targz_round_trip_deterministically() {
        let files = vec![
            (
                "rf.json".into(),
                br#"{"name":"archive-test","main":"index.js","assets":"public"}"#.to_vec(),
            ),
            ("index.js".into(), b"export default {}".to_vec()),
            ("public/index.html".into(), b"<h1>ok</h1>".to_vec()),
        ];
        for (format, filename) in [
            (ExportFormat::Zip, "worker.zip"),
            (ExportFormat::Tar, "worker.tar"),
            (ExportFormat::TarGz, "worker.tar.gz"),
        ] {
            let first = write_bundle_archive(&files, format).unwrap();
            let second = write_bundle_archive(&files, format).unwrap();
            assert_eq!(first, second, "archive output must be reproducible");
            let bundle = read_bundle_archive(&first, filename).unwrap();
            assert_eq!(bundle.spec.name, "archive-test");
            assert_eq!(bundle.modules[0].0, "index.js");
            assert_eq!(bundle.assets[0].0, "index.html");
        }

        let nested = files
            .iter()
            .map(|(path, bytes)| (format!("release-root/{path}"), bytes.clone()))
            .collect::<Vec<_>>();
        let zip = write_bundle_archive(&nested, ExportFormat::Zip).unwrap();
        assert_eq!(
            read_bundle_archive(&zip, "nested.zip").unwrap().spec.name,
            "archive-test"
        );
    }

    #[test]
    fn archives_reject_traversal_links_and_expanded_overflow() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("../rf.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(br#"{"name":"bad"}"#).unwrap();
        let zip = writer.finish().unwrap().into_inner();
        assert!(read_bundle_archive(&zip, "bad.zip").is_err());

        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../secret").unwrap();
        header.set_cksum();
        tar.append_data(&mut header, "link", std::io::empty())
            .unwrap();
        let tar = tar.into_inner().unwrap();
        assert!(read_bundle_archive(&tar, "bad.tar").is_err());

        let oversized = vec![0u8; MAX_ARCHIVE_BYTES + 1];
        assert!(read_bundle_archive(&oversized, "huge.tar").is_err());
    }

    #[test]
    fn export_preserves_bindings_and_content_but_never_secrets() {
        let module_bytes = b"export default {}".to_vec();
        let asset_bytes = b"same-content".to_vec();
        let module_sha = digest(&module_bytes);
        let asset_sha = digest(&asset_bytes);
        let mut env = BTreeMap::new();
        env.insert(R2_METADATA_ENV.into(), r#"{"FILES":"assets"}"#.into());
        env.insert(
            SECRET_METADATA_ENV.into(),
            r#"{"TOKEN":{"ciphertext":"must-not-export"}}"#.into(),
        );
        env.insert("PUBLIC_VALUE".into(), "visible".into());
        let manifest = WorkerManifest {
            name: "export-test".into(),
            version: 7,
            prev: Some([9; 32]),
            deleted: false,
            main: "index.js".into(),
            modules: vec![Module {
                path: "index.js".into(),
                sha256: module_sha,
                kind: ModuleKind::EsModule,
                size: module_bytes.len() as u64,
            }],
            assets: vec![AssetFile {
                path: "index.html".into(),
                sha256: asset_sha,
                size: asset_bytes.len() as u64,
            }],
            hostnames: vec!["export.example.com".into()],
            env,
            kv_bindings: BTreeMap::from([("CACHE".into(), "cache".into())]),
            crons: vec!["0 * * * *".into()],
            compatibility_date: "2026-07-01".into(),
        };
        let files = export_bundle_files(
            &manifest,
            BTreeMap::from([(module_sha, module_bytes), (asset_sha, asset_bytes)]),
        )
        .unwrap();
        let spec = files.iter().find(|(path, _)| path == "rf.json").unwrap();
        let text = std::str::from_utf8(&spec.1).unwrap();
        assert!(!text.contains("must-not-export"));
        assert!(!text.contains(SECRET_METADATA_ENV));
        let bundle = read_bundle_files(files).unwrap();
        assert_eq!(bundle.spec.r2["FILES"], "assets");
        assert_eq!(bundle.spec.kv["CACHE"], "cache");
        assert_eq!(bundle.spec.env["PUBLIC_VALUE"], "visible");
        assert_eq!(bundle.modules[0].1, b"export default {}");
        assert_eq!(bundle.assets[0].1, b"same-content");
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
    fn worker_service_graph_reports_complete_cycle_path() {
        let graph = BTreeMap::from([
            ("api".into(), vec!["billing".into(), "missing".into()]),
            ("billing".into(), vec!["mailer".into()]),
            ("mailer".into(), vec!["api".into()]),
            ("independent".into(), vec!["missing".into()]),
        ]);
        assert_eq!(
            cycles_in_service_graph(&graph),
            vec![vec![
                "api".to_string(),
                "billing".to_string(),
                "mailer".to_string(),
                "api".to_string(),
            ]]
        );
    }

    #[test]
    fn compatibility_flags_reject_duplicates_and_unsafe_names() {
        assert!(validate_compatibility_flags(
            &["nodejs_compat".into(), "global-navigator".into(),]
        )
        .is_ok());
        assert!(
            validate_compatibility_flags(&["nodejs_compat".into(), "nodejs_compat".into(),])
                .is_err()
        );
        assert!(validate_compatibility_flags(&["contains space".into()]).is_err());
        assert!(validate_compatibility_flags(&["非ASCII".into()]).is_err());
    }

    #[test]
    fn generated_runtime_modules_are_reserved() {
        for path in ["__rf_entry.js", "__rf_d1_entry.js", "__rf_workflow.js"] {
            assert!(reserved_module_path(path));
        }
        assert!(!reserved_module_path("src/__rf_helper.js"));
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
