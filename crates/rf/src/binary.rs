//! Operator-signed Binary Deliver definitions and content-addressed bytes.
//!
//! Binary metadata is part of the replicated signed resource log. Bytes use
//! the same local/rclone object substrate as R2. Local bytes are repaired on
//! demand from authenticated peers and are cached by SHA-256 before exec.

use crate::node::Node;
use crate::objectstore::StorageLocation;
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const BINARY_KIND: &str = "binary";
pub const BINARY_SCHEMA: u8 = 1;
pub const MAX_BINARY_BYTES: usize = 200 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinarySpec {
    pub schema: u8,
    #[serde(default)]
    pub description: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub storage: StorageLocation,
    pub os_arch: String,
    pub default_timeout_ms: u64,
    pub max_stdin_bytes: u64,
    pub max_output_bytes: u64,
    #[serde(default)]
    pub allow_network: bool,
    #[serde(default)]
    pub allow_r2: bool,
    #[serde(default)]
    pub required_tags: Vec<String>,
    #[serde(default)]
    pub suspended: bool,
}

impl BinarySpec {
    pub fn validate(&self) -> Result<()> {
        if self.schema != BINARY_SCHEMA {
            bail!("不支持此版本的 Binary Deliver 定义");
        }
        if self.description.len() > 2_000 || self.description.chars().any(char::is_control) {
            bail!("Binary 描述无效或超过 2000 字符");
        }
        let digest = decode_digest(&self.sha256)?;
        if hex::encode(digest) != self.sha256 {
            bail!("Binary SHA-256 必须使用小写十六进制");
        }
        if self.size_bytes == 0 || self.size_bytes > MAX_BINARY_BYTES as u64 {
            bail!("Binary 大小必须介于 1 字节和 200 MiB 之间");
        }
        self.storage.validate()?;
        if matches!(self.storage, StorageLocation::RcloneShard { .. }) {
            bail!("Binary Deliver 只能使用本地存储或固定 rclone remote");
        }
        if !matches!(self.os_arch.as_str(), "linux/amd64" | "linux/arm64") {
            bail!("Binary 目标当前仅支持 linux/amd64 或 linux/arm64");
        }
        if !(100..=600_000).contains(&self.default_timeout_ms) {
            bail!("Binary 默认超时必须介于 100ms 和 10 分钟之间");
        }
        if self.max_stdin_bytes > MAX_BINARY_BYTES as u64
            || self.max_output_bytes > MAX_BINARY_BYTES as u64
        {
            bail!("Binary 输入或输出上限不得超过 200 MiB");
        }
        if crate::placement::normalize_tags(self.required_tags.clone())? != self.required_tags {
            bail!("Binary 必需节点标签必须排序且不能重复");
        }
        Ok(())
    }
}

pub fn prepare_after(
    name: &str,
    mut spec: BinarySpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.description = spec.description.trim().to_string();
    spec.required_tags = crate::placement::normalize_tags(spec.required_tags)?;
    spec.validate()?;
    resource::prepare_after(
        BINARY_KIND,
        name,
        serde_json::to_value(spec)?,
        deleted,
        head,
    )
}

pub fn binary_spec(record: &ResourceRecord) -> Result<BinarySpec> {
    if record.kind != BINARY_KIND || record.deleted {
        bail!("平台资源不是可用的 Binary Deliver 定义");
    }
    let spec: BinarySpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn record(node: &Node, name: &str) -> Option<(ResourceView, BinarySpec)> {
    let view = resource::head(node, BINARY_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = binary_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn records(node: &Node) -> Vec<(ResourceView, BinarySpec)> {
    resource::heads(node, Some(BINARY_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| binary_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn bound_workers(node: &Node, name: &str) -> Vec<String> {
    let mut workers = node
        .live_manifests()
        .into_iter()
        .filter(|manifest| {
            crate::deploy::binary_bindings(manifest)
                .values()
                .any(|binary| binary == name)
        })
        .map(|manifest| manifest.name)
        .collect::<Vec<_>>();
    workers.sort();
    workers
}

/// Validate Binary-specific admission rules before a signed resource is
/// appended. In particular, a definition cannot disappear while a live
/// Worker still names it; this keeps every node's binding behavior coherent.
pub fn validate_admission(node: &Node, record: &ResourceRecord) -> Result<()> {
    if record.kind != BINARY_KIND {
        return Ok(());
    }
    if record.deleted {
        let workers = bound_workers(node, &record.name);
        if !workers.is_empty() {
            bail!(
                "Binary {} 仍被 Worker 绑定：{}；请先移除绑定",
                record.name,
                workers.join("、")
            );
        }
        return Ok(());
    }
    binary_spec(record).map(|_| ())
}

pub async fn store_bytes(
    node: &Node,
    storage: &StorageLocation,
    bytes: &[u8],
) -> Result<(String, u64)> {
    if bytes.is_empty() || bytes.len() > MAX_BINARY_BYTES {
        bail!("Binary 文件必须介于 1 字节和 200 MiB 之间");
    }
    if !node.objects.supports(storage) {
        bail!("当前节点不具备所选 Binary 存储后端");
    }
    let digest = node.objects.put(storage, bytes).await?;
    Ok((hex::encode(digest), bytes.len() as u64))
}

pub async fn materialize(node: &Node, name: &str, spec: &BinarySpec) -> Result<PathBuf> {
    let digest = decode_digest(&spec.sha256)?;
    let path = cache_path(node, &digest);
    if let Ok(metadata) = std::fs::metadata(&path) {
        if metadata.len() == spec.size_bytes && verify_file(&path, &digest)? {
            return Ok(path);
        }
        let _ = std::fs::remove_file(&path);
    }

    let bytes = match node.objects.get(&spec.storage, &digest).await {
        Ok(bytes) => bytes,
        Err(local_error) if spec.storage == StorageLocation::Local => repair_local(node, &digest)
            .await
            .with_context(|| format!("Binary {name} 本地副本缺失；{local_error:#}"))?,
        Err(error) => return Err(error),
    };
    if bytes.len() as u64 != spec.size_bytes {
        bail!("Binary {name} 的内容大小与签名定义不一致");
    }
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != digest {
        bail!("Binary {name} 的内容摘要校验失败");
    }
    write_cache(&path, &bytes)?;
    Ok(path)
}

async fn repair_local(node: &Node, digest: &[u8; 32]) -> Result<Vec<u8>> {
    let peers = node.peers();
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let mut errors = Vec::new();
    for (id, peer) in peers {
        let Some(address) = peer.api_addr else {
            continue;
        };
        match client.r2_fetch_blob(&address.to_string(), digest).await {
            Ok(Some(bytes)) => {
                node.objects
                    .put_verified(&StorageLocation::Local, digest, &bytes)
                    .await?;
                return Ok(bytes);
            }
            Ok(None) => errors.push(format!("{id}: 无副本")),
            Err(error) => errors.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "集群中找不到 Binary 副本{}",
        if errors.is_empty() {
            String::new()
        } else {
            format!("；{}", errors.join("；"))
        }
    )
}

fn cache_path(node: &Node, digest: &[u8; 32]) -> PathBuf {
    let sha = hex::encode(digest);
    node.cfg
        .data_dir
        .join("binary-cache")
        .join(&sha[..2])
        .join(sha)
}

fn write_cache(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("Binary 缓存路径无父目录")?;
    std::fs::create_dir_all(parent)?;
    let stage = parent.join(format!(
        ".stage-{}",
        hex::encode(rand::random::<[u8; 12]>())
    ));
    std::fs::write(&stage, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o500))?;
    }
    match std::fs::rename(&stage, path) {
        Ok(()) => Ok(()),
        Err(_error) if path.is_file() => {
            let _ = std::fs::remove_file(stage);
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_file(stage);
            Err(error.into())
        }
    }
}

fn verify_file(path: &Path, expected: &[u8; 32]) -> Result<bool> {
    let bytes = std::fs::read(path)?;
    Ok(<[u8; 32]>::from(Sha256::digest(bytes)) == *expected)
}

pub fn current_os_arch() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return "linux/amd64";
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return "linux/arm64";
    #[allow(unreachable_code)]
    "unsupported"
}

fn decode_digest(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .context("Binary SHA-256 必须是 64 位十六进制")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_policy_is_bounded_and_canonical() {
        let mut spec = BinarySpec {
            schema: BINARY_SCHEMA,
            description: "ffmpeg".into(),
            sha256: "ab".repeat(32),
            size_bytes: 42,
            storage: StorageLocation::Local,
            os_arch: "linux/amd64".into(),
            default_timeout_ms: 30_000,
            max_stdin_bytes: 10 * 1024 * 1024,
            max_output_bytes: 10 * 1024 * 1024,
            allow_network: false,
            allow_r2: false,
            required_tags: vec!["gpu".into()],
            suspended: false,
        };
        spec.validate().unwrap();
        spec.sha256.make_ascii_uppercase();
        assert!(spec.validate().is_err());
    }
}
