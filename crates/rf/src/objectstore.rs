//! Content-addressed object bytes for R2, pipelines, mail and binaries.
//!
//! Metadata lives in a per-resource micro-quorum. Bytes live either on the
//! node's local object root or on a named rclone remote. The rclone config and
//! its credentials are node-local; replicated bucket specs contain only the
//! remote name and an optional key prefix.

use crate::blob::sha256_hex;
use crate::config::StorageConfig;
use anyhow::{bail, Context, Result};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::process::Command;

pub type ObjectByteStream = Pin<
    Box<
        dyn futures_util::Stream<Item = std::result::Result<axum::body::Bytes, std::io::Error>>
            + Send,
    >,
>;

pub struct VerifiedObjectFile {
    path: PathBuf,
    remove_on_drop: bool,
    size: u64,
}

pub struct StagedObjectFile {
    path: PathBuf,
    size: u64,
    sha256: [u8; 32],
    md5: [u8; 16],
}

impl StagedObjectFile {
    pub(crate) fn from_verified_parts(
        path: PathBuf,
        size: u64,
        sha256: [u8; 32],
        md5: [u8; 16],
    ) -> Self {
        Self {
            path,
            size,
            sha256,
            md5,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub fn md5(&self) -> [u8; 16] {
        self.md5
    }

    pub async fn stream(&self) -> Result<ObjectByteStream> {
        stream_file(&self.path, 0, self.size, None).await
    }
}

/// Consume exactly `length` plaintext bytes from a stream while preserving any
/// remainder of the final chunk. This keeps length-prefixed metadata bounded
/// without forcing the following object body into memory.
pub async fn split_stream_prefix(
    mut stream: ObjectByteStream,
    length: usize,
) -> Result<(Vec<u8>, ObjectByteStream)> {
    use futures_util::StreamExt as _;

    let mut prefix = Vec::with_capacity(length);
    let mut remainder = None;
    while prefix.len() < length {
        let chunk = stream
            .next()
            .await
            .context("上传流在元数据结束前提前关闭")??;
        let needed = length - prefix.len();
        if chunk.len() <= needed {
            prefix.extend_from_slice(&chunk);
        } else {
            prefix.extend_from_slice(&chunk[..needed]);
            remainder = Some(chunk.slice(needed..));
        }
    }
    let leading = futures_util::stream::iter(remainder.into_iter().map(Ok::<_, std::io::Error>));
    Ok((prefix, Box::pin(leading.chain(stream))))
}

impl Drop for StagedObjectFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl VerifiedObjectFile {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn stream(self, offset: u64, length: u64) -> Result<ObjectByteStream> {
        if offset > self.size || length > self.size.saturating_sub(offset) {
            bail!("对象流范围超出文件边界");
        }
        let path = self.path.clone();
        stream_file(&path, offset, length, Some(self)).await
    }
}

impl Drop for VerifiedObjectFile {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

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

    /// Publish an already-spooled file without reading it into memory. The
    /// source is hashed again before any backend mutation, so callers cannot
    /// use a forged expected digest to select a content-addressed path.
    pub async fn put_file_verified(
        &self,
        location: &StorageLocation,
        expected: &[u8; 32],
        source: &Path,
    ) -> Result<u64> {
        location.validate()?;
        let mut file = tokio::fs::File::open(source)
            .await
            .with_context(|| format!("打开待发布对象 {}", source.display()))?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            size = size.checked_add(read as u64).context("对象文件大小溢出")?;
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != *expected {
            bail!(
                "object hash mismatch: expected {} got {}",
                hex::encode(expected),
                hex::encode(actual)
            );
        }

        match location {
            StorageLocation::Local => {
                let target = self.local_path(expected);
                if target.is_file()
                    && hash_file(&target).await.is_ok_and(|(digest, target_size)| {
                        digest == *expected && target_size == size
                    })
                {
                    return Ok(size);
                }
                tokio::fs::create_dir_all(target.parent().context("对象路径没有父目录")?).await?;
                let temporary = target.with_extension(format!(
                    "tmp-{}-{}",
                    std::process::id(),
                    rand::random::<u64>()
                ));
                tokio::fs::copy(source, &temporary).await?;
                tokio::fs::rename(&temporary, target).await?;
            }
            StorageLocation::Rclone { remote, prefix } => {
                self.rclone_file(source, size, rclone_target(remote, prefix, expected))
                    .await?;
            }
            StorageLocation::RcloneShard { remote, prefix } => {
                self.rclone_file(source, size, rclone_shard_target(remote, prefix, expected))
                    .await?;
            }
        }
        Ok(size)
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

    /// Materialize a fully verified file suitable for bounded-memory HTTP
    /// streaming. Remote data is spooled and authenticated before callers can
    /// construct a response, preserving fail-closed content integrity.
    pub async fn materialize_verified(
        &self,
        location: &StorageLocation,
        sha: &[u8; 32],
    ) -> Result<VerifiedObjectFile> {
        location.validate()?;
        match location {
            StorageLocation::Local => {
                let path = self.local_path(sha);
                let (actual, size) = hash_file(&path)
                    .await
                    .with_context(|| format!("object {} not on local disk", hex::encode(sha)))?;
                if actual != *sha {
                    bail!(
                        "对象内容摘要校验失败：期望 {}，实际 {}",
                        hex::encode(sha),
                        hex::encode(actual)
                    );
                }
                Ok(VerifiedObjectFile {
                    path,
                    remove_on_drop: false,
                    size,
                })
            }
            StorageLocation::Rclone { remote, prefix } => {
                self.materialize_rclone(rclone_target(remote, prefix, sha), sha)
                    .await
            }
            StorageLocation::RcloneShard { remote, prefix } => {
                self.materialize_rclone(rclone_shard_target(remote, prefix, sha), sha)
                    .await
            }
        }
    }

    pub async fn materialize_bytes_verified(
        &self,
        expected: &[u8; 32],
        bytes: &[u8],
    ) -> Result<VerifiedObjectFile> {
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if actual != *expected {
            bail!("对象内容摘要校验失败");
        }
        let spool_dir = self.local_root.join(".read-spool");
        tokio::fs::create_dir_all(&spool_dir).await?;
        let path = spool_dir.join(format!(
            "{}-{}-{}.tmp",
            hex::encode(expected),
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::write(&path, bytes).await?;
        Ok(VerifiedObjectFile {
            path,
            remove_on_drop: true,
            size: bytes.len() as u64,
        })
    }

    /// Spool an authenticated peer stream without buffering the object in
    /// memory. Size and SHA-256 are checked before the file guard is returned;
    /// every failure removes the partial file.
    pub async fn materialize_stream_verified(
        &self,
        expected: &[u8; 32],
        expected_size: u64,
        mut stream: ObjectByteStream,
    ) -> Result<VerifiedObjectFile> {
        use futures_util::StreamExt as _;

        let spool_dir = self.local_root.join(".read-spool");
        tokio::fs::create_dir_all(&spool_dir).await?;
        let path = spool_dir.join(format!(
            "{}-{}-{}.tmp",
            hex::encode(expected),
            std::process::id(),
            rand::random::<u64>()
        ));
        let transfer = async {
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .await?;
            let mut hasher = Sha256::new();
            let mut size = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                size = size
                    .checked_add(chunk.len() as u64)
                    .context("peer 对象大小溢出")?;
                if size > expected_size {
                    bail!("peer 返回的对象超过多数派元数据大小");
                }
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            file.sync_data().await?;
            drop(file);
            Ok::<_, anyhow::Error>((hasher.finalize().into(), size))
        };
        let (actual, size): ([u8; 32], u64) = match transfer.await {
            Ok(result) => result,
            Err(error) => {
                let _ = tokio::fs::remove_file(&path).await;
                return Err(error);
            }
        };
        if size != expected_size || actual != *expected {
            let _ = tokio::fs::remove_file(&path).await;
            bail!("peer 返回的对象大小或 SHA-256 与多数派元数据不一致");
        }
        Ok(VerifiedObjectFile {
            path,
            remove_on_drop: true,
            size,
        })
    }

    /// Persist an untrusted bounded stream while calculating its digest. The
    /// returned guard owns cleanup; callers decide whether the staged bytes
    /// become a direct object, multipart part or peer replica.
    pub async fn spool_stream(
        &self,
        max_size: u64,
        mut stream: ObjectByteStream,
    ) -> Result<StagedObjectFile> {
        use futures_util::StreamExt as _;

        let spool_dir = self.local_root.join(".upload-spool");
        tokio::fs::create_dir_all(&spool_dir).await?;
        let path = spool_dir.join(format!(
            "{}-{}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        let transfer = async {
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .await?;
            let mut hasher = Sha256::new();
            let mut md5 = Md5::new();
            let mut size = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                size = size
                    .checked_add(chunk.len() as u64)
                    .context("上传对象大小溢出")?;
                if size > max_size {
                    bail!("上传对象超过当前操作的大小上限");
                }
                hasher.update(&chunk);
                md5.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            file.sync_data().await?;
            drop(file);
            Ok::<_, anyhow::Error>((hasher.finalize().into(), md5.finalize().into(), size))
        };
        let (sha256, md5, size): ([u8; 32], [u8; 16], u64) = match transfer.await {
            Ok(result) => result,
            Err(error) => {
                let _ = tokio::fs::remove_file(&path).await;
                return Err(error);
            }
        };
        Ok(StagedObjectFile {
            path,
            size,
            sha256,
            md5,
        })
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

    async fn rclone_file(&self, source: &Path, size: u64, target: String) -> Result<()> {
        let runtime = self.rclone()?;
        let mut child = runtime
            .command("rcat")
            .arg(&target)
            .arg("--size")
            .arg(size.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("启动 rclone 文件流写入")?;
        let mut stdin = child.stdin.take().context("打开 rclone 标准输入")?;
        let mut file = tokio::fs::File::open(source).await?;
        let transfer = async move {
            tokio::io::copy(&mut file, &mut stdin).await?;
            stdin.shutdown().await?;
            drop(stdin);
            child.wait_with_output().await.map_err(anyhow::Error::from)
        };
        let output = tokio::time::timeout(runtime.timeout, transfer)
            .await
            .context("rclone 文件流写入超时")??;
        command_ok("rclone rcat", output)
    }

    async fn materialize_rclone(
        &self,
        target: String,
        expected: &[u8; 32],
    ) -> Result<VerifiedObjectFile> {
        let runtime = self.rclone()?;
        let spool_dir = self.local_root.join(".read-spool");
        tokio::fs::create_dir_all(&spool_dir).await?;
        let path = spool_dir.join(format!(
            "{}-{}-{}.tmp",
            hex::encode(expected),
            std::process::id(),
            rand::random::<u64>()
        ));
        let transfer = async {
            let mut child = runtime
                .command("cat")
                .arg(&target)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("启动 rclone 流式读取")?;
            let mut stdout = child.stdout.take().context("打开 rclone 标准输出")?;
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .await?;
            let mut hasher = Sha256::new();
            let mut size = 0u64;
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let read = stdout.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                file.write_all(&buffer[..read]).await?;
                size = size.checked_add(read as u64).context("rclone 对象过大")?;
            }
            file.flush().await?;
            file.sync_data().await?;
            drop(file);
            let output = child.wait_with_output().await?;
            command_ok("rclone cat", output)?;
            Ok::<_, anyhow::Error>((hasher.finalize().into(), size))
        };
        let result = tokio::time::timeout(runtime.timeout, transfer).await;
        let (actual, size): ([u8; 32], u64) = match result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                let _ = tokio::fs::remove_file(&path).await;
                return Err(error);
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&path).await;
                bail!("rclone 流式读取超时");
            }
        };
        if actual != *expected {
            let _ = tokio::fs::remove_file(&path).await;
            bail!(
                "对象内容摘要校验失败：期望 {}，实际 {}",
                hex::encode(expected),
                hex::encode(actual)
            );
        }
        Ok(VerifiedObjectFile {
            path,
            remove_on_drop: true,
            size,
        })
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

async fn hash_file(path: &Path) -> Result<([u8; 32], u64)> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size.checked_add(read as u64).context("对象文件大小溢出")?;
    }
    Ok((hasher.finalize().into(), size))
}

async fn stream_file(
    path: &Path,
    offset: u64,
    length: u64,
    guard: Option<VerifiedObjectFile>,
) -> Result<ObjectByteStream> {
    let mut file = tokio::fs::File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let stream = futures_util::stream::try_unfold(
        (file, length, guard),
        |(mut file, remaining, guard)| async move {
            if remaining == 0 {
                return Ok(None);
            }
            let capacity = remaining.min(1024 * 1024) as usize;
            let mut buffer = vec![0u8; capacity];
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "verified object file was truncated while streaming",
                ));
            }
            buffer.truncate(read);
            Ok(Some((
                axum::body::Bytes::from(buffer),
                (file, remaining - read as u64, guard),
            )))
        },
    );
    Ok(Box::pin(stream))
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
    use futures_util::TryStreamExt;

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

        let source = root.join("streamed-source.bin");
        let streamed = vec![0x5au8; 2 * 1024 * 1024 + 17];
        std::fs::write(&source, &streamed).unwrap();
        let streamed_sha: [u8; 32] = Sha256::digest(&streamed).into();
        assert_eq!(
            store
                .put_file_verified(&StorageLocation::Local, &streamed_sha, &source)
                .await
                .unwrap(),
            streamed.len() as u64
        );
        assert_eq!(
            store
                .get(&StorageLocation::Local, &streamed_sha)
                .await
                .unwrap(),
            streamed
        );
        std::fs::write(store.local_path(&streamed_sha), b"corrupt replica").unwrap();
        store
            .put_file_verified(&StorageLocation::Local, &streamed_sha, &source)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(&StorageLocation::Local, &streamed_sha)
                .await
                .unwrap(),
            streamed
        );
        assert!(store
            .put_file_verified(&StorageLocation::Local, &[0; 32], &source)
            .await
            .is_err());
        let verified = store
            .materialize_verified(&StorageLocation::Local, &streamed_sha)
            .await
            .unwrap();
        assert!(!verified.remove_on_drop);
        let chunks = verified
            .stream(1024, 4096)
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert_eq!(
            chunks.into_iter().flatten().collect::<Vec<_>>(),
            streamed[1024..5120]
        );
        store.delete(&StorageLocation::Local, &sha).await.unwrap();
        assert!(!store.exists(&StorageLocation::Local, &sha).await.unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn peer_streams_spool_verify_and_clean_partial_files() {
        let (store, root) = store();
        let bytes: Vec<u8> = (0..2 * 1024 * 1024 + 313)
            .map(|index| (index % 251) as u8)
            .collect();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let chunks = bytes
            .chunks(173_111)
            .map(|chunk| Ok(axum::body::Bytes::copy_from_slice(chunk)))
            .collect::<Vec<std::result::Result<_, std::io::Error>>>();
        let verified = store
            .materialize_stream_verified(
                &digest,
                bytes.len() as u64,
                Box::pin(futures_util::stream::iter(chunks)),
            )
            .await
            .unwrap();
        let path = verified.path().to_path_buf();
        assert!(path.is_file());
        let received = verified
            .stream(1_000_000, 512_345)
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(received, bytes[1_000_000..1_512_345]);
        assert!(!path.exists());

        let truncated = vec![Ok(axum::body::Bytes::copy_from_slice(&bytes[..1024]))];
        assert!(store
            .materialize_stream_verified(
                &digest,
                bytes.len() as u64,
                Box::pin(futures_util::stream::iter(truncated)),
            )
            .await
            .is_err());
        assert_eq!(
            std::fs::read_dir(root.join(".read-spool")).unwrap().count(),
            0
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn upload_streams_spool_hash_bound_and_clean_temporary_files() {
        let (store, root) = store();
        let bytes: Vec<u8> = (0..2 * 1024 * 1024 + 73)
            .map(|index| (index % 239) as u8)
            .collect();
        let chunks = bytes
            .chunks(91_117)
            .map(|chunk| Ok(axum::body::Bytes::copy_from_slice(chunk)))
            .collect::<Vec<std::result::Result<_, std::io::Error>>>();
        let staged = store
            .spool_stream(
                bytes.len() as u64,
                Box::pin(futures_util::stream::iter(chunks)),
            )
            .await
            .unwrap();
        let expected_sha256: [u8; 32] = Sha256::digest(&bytes).into();
        let expected_md5: [u8; 16] = Md5::digest(&bytes).into();
        assert_eq!(staged.size(), bytes.len() as u64);
        assert_eq!(staged.sha256(), expected_sha256);
        assert_eq!(staged.md5(), expected_md5);
        let path = staged.path().to_path_buf();
        assert!(path.is_file());
        let received = staged
            .stream()
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(received, bytes);
        drop(staged);
        assert!(!path.exists());

        let too_large = vec![Ok(axum::body::Bytes::from_static(b"too large"))];
        assert!(store
            .spool_stream(3, Box::pin(futures_util::stream::iter(too_large)))
            .await
            .is_err());
        assert_eq!(
            std::fs::read_dir(root.join(".upload-spool"))
                .unwrap()
                .count(),
            0
        );
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

        let source = root.join("rclone-stream-source.bin");
        let streamed = vec![0xa5u8; 2 * 1024 * 1024 + 31];
        std::fs::write(&source, &streamed).unwrap();
        let streamed_sha: [u8; 32] = Sha256::digest(&streamed).into();
        assert_eq!(
            store
                .put_file_verified(&location, &streamed_sha, &source)
                .await
                .unwrap(),
            streamed.len() as u64
        );
        assert_eq!(store.get(&location, &streamed_sha).await.unwrap(), streamed);
        let verified = store
            .materialize_verified(&location, &streamed_sha)
            .await
            .unwrap();
        let spool = verified.path.clone();
        assert!(verified.remove_on_drop);
        let chunks = verified
            .stream(17, 8192)
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert_eq!(
            chunks.into_iter().flatten().collect::<Vec<_>>(),
            streamed[17..17 + 8192]
        );
        assert!(!spool.exists());
        store.delete(&location, &streamed_sha).await.unwrap();

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
