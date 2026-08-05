//! Content-addressed object bytes for R2, pipelines, mail and binaries.
//!
//! Metadata lives in a per-resource micro-quorum. Bytes live either on the
//! node's local object root or on a named rclone remote. The rclone config and
//! its credentials are node-local; replicated bucket specs contain only the
//! remote name and an optional key prefix.

use crate::blob::sha256_hex;
use crate::config::StorageConfig;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageLocation {
    Local,
    Rclone {
        remote: String,
        #[serde(default)]
        prefix: String,
    },
    /// A concrete shard selected from a signed storage policy. Unlike legacy
    /// per-bucket rclone storage, shard drives are deliberately flat: every
    /// remote contains `<prefix>/<sha256>` and no fan-out directories.
    RcloneShard {
        remote: String,
        #[serde(default)]
        prefix: String,
    },
}

impl StorageLocation {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Local => {}
            Self::Rclone { remote, prefix } | Self::RcloneShard { remote, prefix } => {
                if !valid_remote(remote) {
                    bail!("rclone remote 名称须由字母、数字、点、下划线或连字符组成");
                }
                validate_prefix(prefix)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ObjectStore {
    local_root: PathBuf,
    rclone: Option<RcloneRuntime>,
}

#[derive(Clone)]
struct RcloneRuntime {
    binary: PathBuf,
    config: PathBuf,
    timeout: Duration,
}

impl ObjectStore {
    pub fn open(data_dir: &Path, cfg: &StorageConfig) -> Result<Self> {
        let local_root = cfg
            .local_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("objects"));
        std::fs::create_dir_all(&local_root)?;
        let rclone = match (&cfg.rclone_binary, &cfg.rclone_config) {
            (Some(binary), Some(config)) => Some(RcloneRuntime {
                binary: binary.clone(),
                config: config.clone(),
                timeout: Duration::from_secs(cfg.rclone_timeout_seconds),
            }),
            (None, None) => None,
            _ => bail!("storage.rclone_binary 与 storage.rclone_config 必须同时配置"),
        };
        Ok(Self { local_root, rclone })
    }

    pub fn supports(&self, location: &StorageLocation) -> bool {
        matches!(location, StorageLocation::Local)
            || matches!(
                location,
                StorageLocation::Rclone { .. } | StorageLocation::RcloneShard { .. }
            ) && self.rclone.is_some()
    }

    pub fn local_root(&self) -> &Path {
        &self.local_root
    }

    pub async fn put(&self, location: &StorageLocation, bytes: &[u8]) -> Result<[u8; 32]> {
        location.validate()?;
        let sha: [u8; 32] = Sha256::digest(bytes).into();
        self.put_verified(location, &sha, bytes).await?;
        Ok(sha)
    }

    pub async fn put_verified(
        &self,
        location: &StorageLocation,
        expected: &[u8; 32],
        bytes: &[u8],
    ) -> Result<()> {
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if actual != *expected {
            bail!(
                "object hash mismatch: expected {} got {}",
                hex::encode(expected),
                hex::encode(actual)
            );
        }
        match location {
            StorageLocation::Local => self.put_local(expected, bytes),
            StorageLocation::Rclone { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_target(remote, prefix, expected);
                let mut child = runtime
                    .command("rcat")
                    .arg(&target)
                    .arg("--size")
                    .arg(bytes.len().to_string())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .context("启动 rclone rcat")?;
                let mut stdin = child.stdin.take().context("打开 rclone 标准输入")?;
                let transfer = async move {
                    stdin.write_all(bytes).await?;
                    drop(stdin);
                    child.wait_with_output().await.map_err(anyhow::Error::from)
                };
                let output = tokio::time::timeout(runtime.timeout, transfer)
                    .await
                    .context("rclone 写入超时")??;
                command_ok("rclone rcat", output)
            }
            StorageLocation::RcloneShard { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_shard_target(remote, prefix, expected);
                let mut child = runtime
                    .command("rcat")
                    .arg(&target)
                    .arg("--size")
                    .arg(bytes.len().to_string())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .context("启动 rclone 分片写入")?;
                let mut stdin = child.stdin.take().context("打开 rclone 标准输入")?;
                let transfer = async move {
                    stdin.write_all(bytes).await?;
                    drop(stdin);
                    child.wait_with_output().await.map_err(anyhow::Error::from)
                };
                let output = tokio::time::timeout(runtime.timeout, transfer)
                    .await
                    .context("rclone 分片写入超时")??;
                command_ok("rclone rcat", output)
            }
        }
    }

    pub async fn get(&self, location: &StorageLocation, sha: &[u8; 32]) -> Result<Vec<u8>> {
        location.validate()?;
        let bytes = match location {
            StorageLocation::Local => std::fs::read(self.local_path(sha))
                .with_context(|| format!("object {} not on local disk", hex::encode(sha)))?,
            StorageLocation::Rclone { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_target(remote, prefix, sha);
                let output = tokio::time::timeout(
                    runtime.timeout,
                    runtime.command("cat").arg(&target).output(),
                )
                .await
                .context("rclone 读取超时")??;
                if !output.status.success() {
                    return Err(command_error("rclone cat", &output.stderr));
                }
                output.stdout
            }
            StorageLocation::RcloneShard { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_shard_target(remote, prefix, sha);
                let output = tokio::time::timeout(
                    runtime.timeout,
                    runtime.command("cat").arg(&target).output(),
                )
                .await
                .context("rclone 分片读取超时")??;
                if !output.status.success() {
                    return Err(command_error("rclone cat", &output.stderr));
                }
                output.stdout
            }
        };
        let actual = sha256_hex(&bytes);
        if actual != hex::encode(sha) {
            bail!(
                "对象内容摘要校验失败：期望 {}，实际 {actual}",
                hex::encode(sha)
            );
        }
        Ok(bytes)
    }

    pub async fn exists(&self, location: &StorageLocation, sha: &[u8; 32]) -> Result<bool> {
        location.validate()?;
        match location {
            StorageLocation::Local => Ok(self.local_path(sha).is_file()),
            StorageLocation::Rclone { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_target(remote, prefix, sha);
                let output = tokio::time::timeout(
                    runtime.timeout,
                    runtime
                        .command("lsjson")
                        .arg("--stat")
                        .arg(&target)
                        .output(),
                )
                .await
                .context("rclone 检查对象超时")??;
                if output.status.success() {
                    return Ok(true);
                }
                if output.status.code() == Some(3) {
                    // rclone's documented "directory not found" exit code;
                    // some backends intentionally emit no stderr for it.
                    return Ok(false);
                }
                let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                if stderr.contains("not found")
                    || stderr.contains("doesn't exist")
                    || stderr.contains("directory not found")
                {
                    return Ok(false);
                }
                Err(command_error("rclone lsjson", &output.stderr))
            }
            StorageLocation::RcloneShard { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_shard_target(remote, prefix, sha);
                let output = tokio::time::timeout(
                    runtime.timeout,
                    runtime
                        .command("lsjson")
                        .arg("--stat")
                        .arg(&target)
                        .output(),
                )
                .await
                .context("rclone 分片对象检查超时")??;
                object_exists_result("rclone lsjson", output)
            }
        }
    }

    pub async fn delete(&self, location: &StorageLocation, sha: &[u8; 32]) -> Result<()> {
        location.validate()?;
        match location {
            StorageLocation::Local => {
                let path = self.local_path(sha);
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
                Ok(())
            }
            StorageLocation::Rclone { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_target(remote, prefix, sha);
                let output = tokio::time::timeout(
                    runtime.timeout,
                    runtime.command("deletefile").arg(&target).output(),
                )
                .await
                .context("rclone 删除对象超时")??;
                if output.status.success() {
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                    if output.status.code() == Some(3)
                        || stderr.contains("not found")
                        || stderr.contains("doesn't exist")
                    {
                        Ok(())
                    } else {
                        Err(command_error("rclone deletefile", &output.stderr))
                    }
                }
            }
            StorageLocation::RcloneShard { remote, prefix } => {
                let runtime = self.rclone()?;
                let target = rclone_shard_target(remote, prefix, sha);
                let output = tokio::time::timeout(
                    runtime.timeout,
                    runtime.command("deletefile").arg(&target).output(),
                )
                .await
                .context("rclone 分片对象删除超时")??;
                delete_result("rclone deletefile", output)
            }
        }
    }

    pub async fn probe(&self, remote: &str, prefix: &str) -> Result<()> {
        if !valid_remote(remote) {
            bail!("rclone remote 名称无效");
        }
        validate_prefix(prefix)?;
        let runtime = self.rclone()?;
        // Probe the remote root rather than the bucket prefix: a brand-new
        // prefix legitimately does not exist until the first object upload.
        let target = format!("{remote}:");
        let output = tokio::time::timeout(
            runtime.timeout,
            runtime
                .command("lsf")
                .arg("--max-depth")
                .arg("1")
                .arg(&target)
                .output(),
        )
        .await
        .context("rclone 连通性检查超时")??;
        command_ok("rclone lsf", output)
    }

    fn put_local(&self, sha: &[u8; 32], bytes: &[u8]) -> Result<()> {
        let path = self.local_path(sha);
        if path.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(path.parent().context("对象路径没有父目录")?)?;
        let temporary = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&temporary, bytes)?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    }

    fn local_path(&self, sha: &[u8; 32]) -> PathBuf {
        let encoded = hex::encode(sha);
        self.local_root.join(&encoded[..2]).join(encoded)
    }

    fn rclone(&self) -> Result<&RcloneRuntime> {
        self.rclone
            .as_ref()
            .context("当前节点未配置 rclone，不能访问该存储后端")
    }
}

impl RcloneRuntime {
    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .arg(operation)
            .arg("--config")
            .arg(&self.config)
            .arg("--log-level")
            .arg("ERROR")
            .kill_on_drop(true);
        command
    }
}

pub(crate) fn valid_remote(remote: &str) -> bool {
    !remote.is_empty()
        && remote.len() <= 128
        && !remote.starts_with('-')
        && remote
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.len() > 512
        || prefix.starts_with('/')
        || prefix.contains('\0')
        || prefix
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        bail!("rclone 对象前缀无效");
    }
    Ok(())
}

fn rclone_target(remote: &str, prefix: &str, sha: &[u8; 32]) -> String {
    let encoded = hex::encode(sha);
    let key = format!("blobs/{}/{}", &encoded[..2], encoded);
    if prefix.is_empty() {
        format!("{remote}:{key}")
    } else {
        format!("{remote}:{}/{key}", prefix.trim_matches('/'))
    }
}

fn rclone_shard_target(remote: &str, prefix: &str, sha: &[u8; 32]) -> String {
    let encoded = hex::encode(sha);
    if prefix.is_empty() {
        format!("{remote}:{encoded}")
    } else {
        format!("{remote}:{}/{encoded}", prefix.trim_matches('/'))
    }
}

fn object_exists_result(label: &str, output: std::process::Output) -> Result<bool> {
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(3) {
        return Ok(false);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("not found")
        || stderr.contains("doesn't exist")
        || stderr.contains("directory not found")
    {
        return Ok(false);
    }
    Err(command_error(label, &output.stderr))
}

fn delete_result(label: &str, output: std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if output.status.code() == Some(3)
        || stderr.contains("not found")
        || stderr.contains("doesn't exist")
    {
        return Ok(());
    }
    Err(command_error(label, &output.stderr))
}

fn command_ok(label: &str, output: std::process::Output) -> Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(label, &output.stderr))
    }
}

fn command_error(label: &str, stderr: &[u8]) -> anyhow::Error {
    let message = String::from_utf8_lossy(stderr);
    let message = message.trim();
    anyhow::anyhow!(
        "{label} 失败：{}",
        if message.is_empty() {
            "未返回错误详情"
        } else {
            message
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ObjectStore, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "rf-object-store-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let cfg = StorageConfig {
            local_dir: Some(root.clone()),
            ..StorageConfig::default()
        };
        (ObjectStore::open(&root, &cfg).unwrap(), root)
    }

    #[tokio::test]
    async fn local_objects_are_content_addressed_and_verified() {
        let (store, root) = store();
        let sha = store
            .put(&StorageLocation::Local, b"hello object")
            .await
            .unwrap();
        assert!(store.exists(&StorageLocation::Local, &sha).await.unwrap());
        assert_eq!(
            store.get(&StorageLocation::Local, &sha).await.unwrap(),
            b"hello object"
        );
        assert!(store
            .put_verified(&StorageLocation::Local, &[0; 32], b"wrong")
            .await
            .is_err());
        store.delete(&StorageLocation::Local, &sha).await.unwrap();
        assert!(!store.exists(&StorageLocation::Local, &sha).await.unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn rclone_backend_round_trips_through_an_alias_remote_when_available() {
        let available = std::process::Command::new("rclone")
            .arg("version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !available {
            return;
        }

        let root = std::env::temp_dir().join(format!(
            "rf-rclone-store-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let remote_root = root.join("remote");
        std::fs::create_dir_all(&remote_root).unwrap();
        let config_path = root.join("rclone.conf");
        std::fs::write(
            &config_path,
            format!(
                "[fixture]\ntype = alias\nremote = {}\n",
                remote_root.display()
            ),
        )
        .unwrap();
        let config = StorageConfig {
            local_dir: Some(root.join("local")),
            rclone_binary: Some(PathBuf::from("rclone")),
            rclone_config: Some(config_path),
            rclone_timeout_seconds: 15,
        };
        let store = ObjectStore::open(&root, &config).unwrap();
        let location = StorageLocation::Rclone {
            remote: "fixture".into(),
            prefix: "tenant-a".into(),
        };
        store.probe("fixture", "tenant-a").await.unwrap();
        let sha = store.put(&location, b"rclone bytes").await.unwrap();
        assert!(store.exists(&location, &sha).await.unwrap());
        assert_eq!(store.get(&location, &sha).await.unwrap(), b"rclone bytes");
        store.delete(&location, &sha).await.unwrap();
        assert!(!store.exists(&location, &sha).await.unwrap());

        let shard = StorageLocation::RcloneShard {
            remote: "fixture".into(),
            prefix: "flat-shard".into(),
        };
        let shard_sha = store.put(&shard, b"flat shard bytes").await.unwrap();
        assert!(remote_root
            .join("flat-shard")
            .join(hex::encode(shard_sha))
            .is_file());
        assert!(!remote_root.join("flat-shard/blobs").exists());
        assert_eq!(
            store.get(&shard, &shard_sha).await.unwrap(),
            b"flat shard bytes"
        );
        store.delete(&shard, &shard_sha).await.unwrap();
        assert!(!store.exists(&shard, &shard_sha).await.unwrap());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rclone_locations_reject_option_and_path_injection() {
        assert!(StorageLocation::Rclone {
            remote: "-config".into(),
            prefix: String::new(),
        }
        .validate()
        .is_err());
        assert!(StorageLocation::Rclone {
            remote: "archive".into(),
            prefix: "../escape".into(),
        }
        .validate()
        .is_err());
        assert!(StorageLocation::Rclone {
            remote: "b2-hot".into(),
            prefix: "randallflare/prod".into(),
        }
        .validate()
        .is_ok());
    }
}
