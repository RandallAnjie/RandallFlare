//! R2-compatible object metadata and bytes.
//!
//! Bucket definitions are operator-signed platform resources. Object metadata
//! is strongly consistent in a per-bucket D1 micro-quorum; immutable bytes are
//! content-addressed in local storage or a node-local rclone remote. A crash
//! between byte upload and metadata commit can only leave an unreferenced blob,
//! which the storage reconciler may safely collect later.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::objectstore::{StagedObjectFile, StorageLocation};
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use md5::Md5;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

pub const BUCKET_KIND: &str = "r2_bucket";
pub const MAX_OBJECT_KEY_BYTES: usize = 1024;
pub const MAX_LIST_LIMIT: usize = 1000;
/// Cloudflare-compatible external upload limits. Buffered internal producers
/// keep their smaller bounds below; network-facing paths spool to disk.
pub const MAX_DIRECT_OBJECT_BYTES: usize = 5 * 1024 * 1024 * 1024;
pub const MAX_MULTIPART_PART_BYTES: usize = 5 * 1024 * 1024 * 1024;
pub const MAX_MULTIPART_OBJECT_BYTES: u64 =
    5 * 1024 * 1024 * 1024 * 1024 - MAX_MULTIPART_PART_BYTES as u64;
pub const MIN_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;
pub const MAX_BUFFERED_OBJECT_BYTES: usize = 63 * 1024 * 1024;
pub const MAX_BUFFERED_MULTIPART_PART_BYTES: usize = 63 * 1024 * 1024;
pub const MAX_MULTIPART_PARTS: usize = 10_000;
const MULTIPART_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const ORPHAN_GRACE_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_PUT_OPTIONS_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketSpec {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub public_access: bool,
    pub storage: StorageLocation,
    /// Opt into a signed dynamic shard set. `storage` remains `local` as a
    /// backwards-compatible placeholder; every new blob is resolved to and
    /// recorded with one concrete `rclone_shard` location.
    #[serde(default)]
    pub storage_policy: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub max_objects: Option<u64>,
    #[serde(default)]
    pub expire_objects_after_days: Option<u32>,
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Additional public object-serving hostnames. A deterministic
    /// `r2-<bucket>.<ingress.default_domain>` hostname is derived locally and
    /// does not need to be stored here.
    #[serde(default)]
    pub hostnames: Vec<String>,
}

impl BucketSpec {
    pub fn validate(&self) -> Result<()> {
        if self.description.len() > 2_000 {
            bail!("R2 bucket 描述不得超过 2000 个字符");
        }
        self.storage.validate()?;
        if matches!(self.storage, StorageLocation::RcloneShard { .. }) {
            bail!("R2 bucket 不能直接指定内部 rclone_shard 位置；请使用签名存储策略");
        }
        if let Some(policy) = &self.storage_policy {
            if policy != crate::storage_policy::DEFAULT_POLICY_NAME {
                bail!("R2 bucket 引用了未知存储策略：{policy}");
            }
            if self.storage != StorageLocation::Local {
                bail!("使用存储策略的 bucket 不能同时指定固定 rclone remote");
            }
        }
        if self.max_bytes == Some(0) || self.max_objects == Some(0) {
            bail!("R2 bucket 配额必须大于零；不限制时请留空");
        }
        if self
            .expire_objects_after_days
            .is_some_and(|days| days == 0 || days > 36_500)
        {
            bail!("R2 生命周期天数必须介于 1 和 36500 之间");
        }
        if self.cors_origins.len() > 256 {
            bail!("R2 CORS 来源不得超过 256 项");
        }
        for origin in &self.cors_origins {
            if origin != "*" && !(origin.starts_with("https://") || origin.starts_with("http://")) {
                bail!("R2 CORS 来源必须是 http(s) origin 或 *：{origin}");
            }
            if origin.len() > 512 || origin.contains(['\r', '\n']) {
                bail!("R2 CORS 来源无效");
            }
        }
        if self.hostnames.len() > 64 {
            bail!("R2 自定义域名不得超过 64 个");
        }
        for hostname in &self.hostnames {
            if !rf_core::manifest::valid_hostname(hostname) {
                bail!("R2 自定义域名无效：{hostname}");
            }
        }
        Ok(())
    }

    pub fn uses_local_storage(&self) -> bool {
        self.storage_policy.is_none() && self.storage == StorageLocation::Local
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub key: String,
    pub sha256: String,
    pub size: u64,
    pub etag: String,
    pub content_type: Option<String>,
    pub custom_metadata: serde_json::Map<String, Value>,
    pub http_metadata: serde_json::Map<String, Value>,
    pub storage: StorageLocation,
    pub uploaded_at_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PutOptions {
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub custom_metadata: serde_json::Map<String, Value>,
    #[serde(default)]
    pub http_metadata: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectList {
    pub objects: Vec<ObjectMeta>,
    #[serde(default)]
    pub delimited_prefixes: Vec<String>,
    pub truncated: bool,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct BucketUsage {
    pub bytes: u64,
    pub objects: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageUsage {
    pub storage: StorageLocation,
    pub bytes: u64,
    pub objects: u64,
    pub buckets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub key: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUploadSummary {
    pub upload_id: String,
    pub key: String,
    pub content_type: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub part_count: u64,
    pub uploaded_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUploadPage {
    pub uploads: Vec<MultipartUploadSummary>,
    pub truncated: bool,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUploadDetail {
    #[serde(flatten)]
    pub upload: MultipartUploadSummary,
    pub custom_metadata: serde_json::Map<String, Value>,
    pub http_metadata: serde_json::Map<String, Value>,
    pub storage: StorageLocation,
    pub storage_policy: Option<String>,
    pub parts: Vec<UploadedPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadedPart {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedPart {
    pub part_number: u32,
    pub etag: String,
}

pub fn bucket_record(node: &Node, name: &str) -> Option<(ResourceView, BucketSpec)> {
    let view = resource::head(node, BUCKET_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = bucket_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn bucket_records(node: &Node) -> Vec<(ResourceView, BucketSpec)> {
    resource::heads(node, Some(BUCKET_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| bucket_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn prepare_bucket(
    node: &Node,
    name: &str,
    spec: BucketSpec,
    deleted: bool,
) -> Result<ResourceRecord> {
    spec.validate()?;
    resource::prepare(
        node,
        BUCKET_KIND,
        name,
        serde_json::to_value(spec)?,
        deleted,
    )
}

pub fn prepare_bucket_after(
    name: &str,
    spec: BucketSpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.validate()?;
    resource::prepare_after(
        BUCKET_KIND,
        name,
        serde_json::to_value(spec)?,
        deleted,
        head,
    )
}

pub fn bucket_spec(resource: &ResourceRecord) -> Result<BucketSpec> {
    if resource.kind != BUCKET_KIND {
        bail!("平台资源不是 R2 bucket");
    }
    let spec: BucketSpec = serde_json::from_value(resource.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn validate_bucket_admission(node: &Node, resource: &ResourceRecord) -> Result<()> {
    let spec = bucket_spec(resource)?;
    if resource.deleted {
        let (_, storage) = crate::storage_policy::current(node)?;
        if let Some(backup) = storage
            .d1_backups
            .iter()
            .find(|backup| backup.bucket == resource.name)
        {
            bail!(
                "R2 bucket {} 仍被 D1 数据库 {} 的自动备份策略使用",
                resource.name,
                backup.database
            );
        }
    }
    if let Some(policy) = &spec.storage_policy {
        crate::storage_policy::resolve(node, policy, &[0u8; 32])?;
    }
    Ok(())
}

pub fn metadata_database(bucket: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("r2/{bucket}").as_bytes()));
    format!("r2-{}", &digest[..32])
}

fn resolve_write_storage(
    node: &Node,
    spec: &BucketSpec,
    sha: &[u8; 32],
) -> Result<StorageLocation> {
    match &spec.storage_policy {
        Some(policy) => crate::storage_policy::resolve(node, policy, sha),
        None => Ok(spec.storage.clone()),
    }
}

fn resolve_multipart_storage(
    node: &Node,
    upload: &MultipartRow,
    sha: &[u8; 32],
) -> Result<StorageLocation> {
    match &upload.storage_policy {
        Some(policy) => crate::storage_policy::resolve(node, policy, sha),
        None => Ok(upload.storage.clone()),
    }
}

fn validate_write_backend(node: &Node, spec: &BucketSpec) -> Result<()> {
    let probe_digest = [0u8; 32];
    let storage = resolve_write_storage(node, spec, &probe_digest)?;
    if !node.objects.supports(&storage)
        && !node
            .peers()
            .values()
            .any(|peer| peer.api_addr.is_some() && peer.capabilities.contains("rclone"))
    {
        bail!("集群中没有可用的 rclone 存储节点");
    }
    Ok(())
}

pub async fn put_object(
    node: &Node,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    options: PutOptions,
) -> Result<ObjectMeta> {
    validate_key(key)?;
    validate_metadata(&options)?;
    if bytes.len() > MAX_BUFFERED_OBJECT_BYTES {
        bail!("R2 内存直传对象不得超过 63 MiB；大对象必须使用流式入口");
    }
    commit_object(node, bucket, key, bytes, options).await
}

pub async fn put_object_file(
    node: &Node,
    bucket: &str,
    key: &str,
    staged: &StagedObjectFile,
    options: PutOptions,
) -> Result<ObjectMeta> {
    validate_key(key)?;
    validate_metadata(&options)?;
    if staged.size() > MAX_DIRECT_OBJECT_BYTES as u64 {
        bail!("R2 单次直传对象不得超过 5 GiB；更大的对象请使用分片上传");
    }
    commit_object_file(
        node,
        bucket,
        key,
        staged,
        hex::encode(staged.md5()),
        options,
    )
    .await
}

async fn commit_object(
    node: &Node,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    options: PutOptions,
) -> Result<ObjectMeta> {
    let (_, spec) = bucket_record(node, bucket).context("R2 bucket 不存在")?;
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let storage = resolve_write_storage(node, &spec, &sha)?;
    if !node.objects.supports(&storage) {
        return forward_put_to_storage_peer(node, bucket, key, bytes, options).await;
    }
    let group = ensure_schema(node, bucket).await?;
    let _quota_guard = node.r2_quota_gate.lock().await;
    let previous = head_object(node, bucket, key).await?;
    crate::quota::validate_r2_write(node, bucket, previous.as_ref(), bytes.len() as u64).await?;
    // Failed quota admission must not consume unindexed local/rclone storage.
    node.objects.put_verified(&storage, &sha, bytes).await?;
    if storage == StorageLocation::Local {
        replicate_local_blob(node, &group, &sha, bytes).await?;
    }

    index_committed_object(
        node,
        bucket,
        key,
        sha,
        bytes.len() as u64,
        hex::encode(Md5::digest(bytes)),
        storage,
        options,
        &spec,
        previous,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn index_committed_object(
    node: &Node,
    bucket: &str,
    key: &str,
    sha: [u8; 32],
    size: u64,
    etag: String,
    storage: StorageLocation,
    options: PutOptions,
    spec: &BucketSpec,
    previous: Option<ObjectMeta>,
) -> Result<ObjectMeta> {
    let max_bytes = spec.max_bytes.unwrap_or(0);
    let max_objects = spec.max_objects.unwrap_or(0);
    let sha256 = hex::encode(sha);
    let uploaded_at_ms = now_ms();
    let result = exec(
        node,
        bucket,
        r#"INSERT INTO objects
           (key, sha256, size, etag, content_type, custom_metadata, http_metadata, storage_json, uploaded_at_ms)
           SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
           WHERE
             (?10 = 0 OR
              (SELECT COALESCE(SUM(size), 0) FROM objects)
                - COALESCE((SELECT size FROM objects WHERE key = ?1), 0)
                + ?3 <= ?10)
             AND
             (?11 = 0 OR EXISTS(SELECT 1 FROM objects WHERE key = ?1)
                OR (SELECT COUNT(*) FROM objects) < ?11)
           ON CONFLICT(key) DO UPDATE SET
             sha256=excluded.sha256,
             size=excluded.size,
             etag=excluded.etag,
             content_type=excluded.content_type,
             custom_metadata=excluded.custom_metadata,
             http_metadata=excluded.http_metadata,
             storage_json=excluded.storage_json,
             uploaded_at_ms=excluded.uploaded_at_ms"#,
        json!([
            key,
            sha256,
            size,
            etag,
            options.content_type,
            serde_json::to_string(&options.custom_metadata)?,
            serde_json::to_string(&options.http_metadata)?,
            serde_json::to_string(&storage)?,
            uploaded_at_ms,
            max_bytes,
            max_objects,
        ]),
    )
    .await?;
    if result["rows_affected"].as_u64() != Some(1) {
        bail!("R2 bucket 配额不足，未写入对象索引");
    }
    if let Some(previous) = previous.filter(|previous| previous.sha256 != sha256) {
        schedule_orphan(node, bucket, &previous).await?;
    }
    Ok(ObjectMeta {
        key: key.into(),
        sha256,
        size,
        etag,
        content_type: options.content_type,
        custom_metadata: options.custom_metadata,
        http_metadata: options.http_metadata,
        storage,
        uploaded_at_ms,
    })
}

async fn commit_object_file(
    node: &Node,
    bucket: &str,
    key: &str,
    staged: &StagedObjectFile,
    etag: String,
    options: PutOptions,
) -> Result<ObjectMeta> {
    let size = staged.size();
    let sha = staged.sha256();
    let (_, spec) = bucket_record(node, bucket).context("R2 bucket 不存在")?;
    let storage = resolve_write_storage(node, &spec, &sha)?;
    if !node.objects.supports(&storage) {
        return forward_put_file_to_storage_peer(node, bucket, key, staged, options).await;
    }
    let group = ensure_schema(node, bucket).await?;
    let _quota_guard = node.r2_quota_gate.lock().await;
    let previous = head_object(node, bucket, key).await?;
    crate::quota::validate_r2_write(node, bucket, previous.as_ref(), size).await?;
    let stored_size = node
        .objects
        .put_file_verified(&storage, &sha, staged.path())
        .await?;
    if stored_size != size {
        bail!("R2 流式对象大小在发布前发生变化");
    }
    if storage == StorageLocation::Local {
        replicate_local_blob_file(node, &group, staged).await?;
    }
    index_committed_object(
        node, bucket, key, sha, size, etag, storage, options, &spec, previous,
    )
    .await
}

pub async fn create_multipart_upload(
    node: &Node,
    bucket: &str,
    key: &str,
    options: PutOptions,
) -> Result<MultipartUpload> {
    validate_key(key)?;
    validate_metadata(&options)?;
    let (_, spec) = bucket_record(node, bucket).context("R2 bucket 不存在")?;
    validate_write_backend(node, &spec)?;
    ensure_schema(node, bucket).await?;
    let upload_id = hex::encode(rand::random::<[u8; 20]>());
    let expires_at_ms = now_ms().saturating_add(MULTIPART_TTL_MS);
    exec(
        node,
        bucket,
        "INSERT INTO multipart_uploads (upload_id, key, content_type, custom_metadata, http_metadata, storage_json, storage_policy, created_at_ms, expires_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        json!([
            upload_id,
            key,
            options.content_type,
            serde_json::to_string(&options.custom_metadata)?,
            serde_json::to_string(&options.http_metadata)?,
            serde_json::to_string(&spec.storage)?,
            spec.storage_policy,
            now_ms(),
            expires_at_ms,
        ]),
    )
    .await?;
    Ok(MultipartUpload {
        upload_id,
        key: key.into(),
        expires_at_ms,
    })
}

pub async fn upload_part(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    bytes: &[u8],
) -> Result<UploadedPart> {
    validate_key(key)?;
    validate_upload_id(upload_id)?;
    if !(1..=MAX_MULTIPART_PARTS as u32).contains(&part_number) {
        bail!("R2 分片编号必须介于 1 和 10000 之间");
    }
    if bytes.len() > MAX_BUFFERED_MULTIPART_PART_BYTES {
        bail!("R2 内存上传分片不得超过 63 MiB；大分片必须使用流式入口");
    }
    ensure_schema(node, bucket).await?;
    let upload = multipart_row(node, bucket, key, upload_id).await?;
    if upload.expires_at_ms <= now_ms() {
        bail!("R2 分片上传已过期");
    }
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let storage = resolve_multipart_storage(node, &upload, &sha)?;
    if !node.objects.supports(&storage) {
        return forward_upload_part_to_storage_peer(
            node,
            bucket,
            key,
            upload_id,
            part_number,
            bytes,
        )
        .await;
    }
    node.objects.put_verified(&storage, &sha, bytes).await?;
    index_uploaded_part(
        node,
        bucket,
        key,
        upload_id,
        part_number,
        sha,
        hex::encode(Md5::digest(bytes)),
        bytes.len() as u64,
        storage,
    )
    .await
}

pub async fn upload_part_file(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    staged: &StagedObjectFile,
) -> Result<UploadedPart> {
    validate_key(key)?;
    validate_upload_id(upload_id)?;
    if !(1..=MAX_MULTIPART_PARTS as u32).contains(&part_number) {
        bail!("R2 分片编号必须介于 1 和 10000 之间");
    }
    if staged.size() > MAX_MULTIPART_PART_BYTES as u64 {
        bail!("R2 单个分片不得超过 5 GiB");
    }
    ensure_schema(node, bucket).await?;
    let upload = multipart_row(node, bucket, key, upload_id).await?;
    if upload.expires_at_ms <= now_ms() {
        bail!("R2 分片上传已过期");
    }
    let sha = staged.sha256();
    let storage = resolve_multipart_storage(node, &upload, &sha)?;
    if !node.objects.supports(&storage) {
        return forward_upload_part_file_to_storage_peer(
            node,
            bucket,
            key,
            upload_id,
            part_number,
            staged,
        )
        .await;
    }
    let stored_size = node
        .objects
        .put_file_verified(&storage, &sha, staged.path())
        .await?;
    if stored_size != staged.size() {
        bail!("R2 流式分片大小在发布前发生变化");
    }
    index_uploaded_part(
        node,
        bucket,
        key,
        upload_id,
        part_number,
        sha,
        hex::encode(staged.md5()),
        staged.size(),
        storage,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn index_uploaded_part(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    sha: [u8; 32],
    etag: String,
    size: u64,
    storage: StorageLocation,
) -> Result<UploadedPart> {
    let sha256 = hex::encode(sha);
    let result = exec(
        node,
        bucket,
        "INSERT INTO multipart_parts (upload_id, part_number, sha256, size, etag, storage_json, uploaded_at_ms) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE EXISTS (SELECT 1 FROM multipart_uploads WHERE upload_id = ?1 AND key = ?8 AND expires_at_ms > ?7) ON CONFLICT(upload_id, part_number) DO UPDATE SET sha256=excluded.sha256, size=excluded.size, etag=excluded.etag, storage_json=excluded.storage_json, uploaded_at_ms=excluded.uploaded_at_ms",
        json!([
            upload_id,
            part_number,
            sha256,
            size,
            etag,
            serde_json::to_string(&storage)?,
            now_ms(),
            key
        ]),
    )
    .await?;
    if result["rows_affected"].as_u64() != Some(1) {
        bail!("R2 分片上传不存在、已中止或已过期");
    }
    Ok(UploadedPart {
        part_number,
        etag,
        size,
    })
}

pub async fn complete_multipart_upload(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[PublishedPart],
) -> Result<ObjectMeta> {
    validate_key(key)?;
    validate_upload_id(upload_id)?;
    validate_published_parts(parts)?;
    ensure_schema(node, bucket).await?;
    let upload = multipart_row(node, bucket, key, upload_id).await?;
    if upload.expires_at_ms <= now_ms() {
        bail!("R2 分片上传已过期");
    }
    if multipart_requires_rclone(&upload) && node.cfg.storage.rclone_binary.is_none() {
        return forward_complete_to_storage_peer(node, bucket, key, upload_id, parts).await;
    }
    let assembly_dir = node.objects.local_root().join(".multipart-assembly");
    tokio::fs::create_dir_all(&assembly_dir).await?;
    let assembly_path = assembly_dir.join(format!(
        "{upload_id}-{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let max_object_bytes = MAX_MULTIPART_OBJECT_BYTES;
    let assembled = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&assembly_path)
            .await?;
        let mut hasher = Sha256::new();
        let mut object_md5 = Md5::new();
        let mut multipart_etag = Md5::new();
        let mut assembled_size = 0u64;
        let mut consumed_parts = Vec::new();
        let mut regular_part_size = None;
        for (part_index, published) in parts.iter().enumerate() {
            let result = exec(
                node,
                bucket,
                "SELECT sha256, size, etag, storage_json FROM multipart_parts WHERE upload_id = ?1 AND part_number = ?2",
                json!([upload_id, published.part_number]),
            )
            .await?;
            let row = result["rows"]
                .as_array()
                .and_then(|rows| rows.first())
                .and_then(Value::as_object)
                .with_context(|| format!("R2 分片 {} 不存在", published.part_number))?;
            let etag = row
                .get("etag")
                .and_then(Value::as_str)
                .context("R2 分片缺少 ETag")?;
            if !constant_time_string_eq(etag, published.etag.trim_matches('"')) {
                bail!("R2 分片 {} 的 ETag 不匹配", published.part_number);
            }
            let sha: [u8; 32] = hex::decode(
                row.get("sha256")
                    .and_then(Value::as_str)
                    .context("R2 分片缺少摘要")?,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("R2 分片摘要长度无效"))?;
            let declared_size = row
                .get("size")
                .and_then(Value::as_u64)
                .context("R2 分片缺少大小")?;
            let is_last = part_index + 1 == parts.len();
            if !is_last {
                if declared_size < MIN_MULTIPART_PART_BYTES {
                    bail!(
                        "R2 除最后一个分片外，每个分片至少为 5 MiB（分片 {}）",
                        published.part_number
                    );
                }
                match regular_part_size {
                    Some(expected) if expected != declared_size => {
                        bail!("R2 除最后一个分片外，所有分片大小必须一致");
                    }
                    None => regular_part_size = Some(declared_size),
                    _ => {}
                }
            } else if regular_part_size.is_some_and(|expected| declared_size > expected) {
                bail!("R2 最后一个分片不得大于前面的分片");
            }
            assembled_size = assembled_size
                .checked_add(declared_size)
                .context("R2 分片合并大小溢出")?;
            if assembled_size > max_object_bytes {
                bail!(
                    "R2 分片合并后的对象超过当前后端上限 {} 字节",
                    max_object_bytes
                );
            }
            let storage: StorageLocation = serde_json::from_str(
                row.get("storage_json")
                    .and_then(Value::as_str)
                    .context("R2 分片缺少存储位置")?,
            )?;
            let verified = node.objects.materialize_verified(&storage, &sha).await?;
            if verified.size() != declared_size {
                bail!("R2 分片 {} 的大小校验失败", published.part_number);
            }
            let mut stream = verified.stream(0, declared_size).await?;
            let mut streamed_size = 0u64;
            let mut part_md5 = Md5::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                streamed_size = streamed_size
                    .checked_add(chunk.len() as u64)
                    .context("R2 分片流大小溢出")?;
                hasher.update(&chunk);
                object_md5.update(&chunk);
                part_md5.update(&chunk);
                file.write_all(&chunk).await?;
            }
            if streamed_size != declared_size {
                bail!("R2 分片 {} 在合并期间被截断", published.part_number);
            }
            let part_md5: [u8; 16] = part_md5.finalize().into();
            if etag.len() == 32 && !constant_time_string_eq(etag, &hex::encode(part_md5)) {
                bail!("R2 分片 {} 的 MD5 ETag 校验失败", published.part_number);
            }
            multipart_etag.update(part_md5);
            consumed_parts.push((hex::encode(sha), declared_size, storage));
        }
        file.flush().await?;
        file.sync_data().await?;
        drop(file);
        let sha: [u8; 32] = hasher.finalize().into();
        let md5: [u8; 16] = object_md5.finalize().into();
        let completed_etag = format!("{}-{}", hex::encode(multipart_etag.finalize()), parts.len());
        let staged = StagedObjectFile::from_verified_parts(
            assembly_path.clone(),
            assembled_size,
            sha,
            md5,
        );
        let metadata = commit_object_file(
            node,
            bucket,
            key,
            &staged,
            completed_etag,
            upload.options.clone(),
        )
        .await?;
        Ok::<_, anyhow::Error>((metadata, consumed_parts))
    }
    .await;
    let _ = tokio::fs::remove_file(&assembly_path).await;
    let (metadata, consumed_parts) = assembled?;
    // Metadata is removed only after the final object has committed. A retry
    // after a timeout is therefore safe until this point; afterwards it sees a
    // clear no-such-upload result instead of assembling an incomplete object.
    exec(
        node,
        bucket,
        "DELETE FROM multipart_parts WHERE upload_id = ?1",
        json!([upload_id]),
    )
    .await?;
    exec(
        node,
        bucket,
        "DELETE FROM multipart_uploads WHERE upload_id = ?1 AND key = ?2",
        json!([upload_id, key]),
    )
    .await?;
    for (sha256, size, storage) in consumed_parts {
        schedule_orphan_parts(node, bucket, &sha256, size, &storage).await?;
    }
    Ok(metadata)
}

pub async fn abort_multipart_upload(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<()> {
    validate_key(key)?;
    validate_upload_id(upload_id)?;
    ensure_schema(node, bucket).await?;
    multipart_row(node, bucket, key, upload_id).await?;
    let part_rows = exec(
        node,
        bucket,
        "SELECT sha256, size, storage_json FROM multipart_parts WHERE upload_id = ?1",
        json!([upload_id]),
    )
    .await?;
    let result = exec(
        node,
        bucket,
        "DELETE FROM multipart_uploads WHERE upload_id = ?1 AND key = ?2",
        json!([upload_id, key]),
    )
    .await?;
    if result["rows_affected"].as_u64().unwrap_or(0) == 0 {
        bail!("R2 分片上传不存在");
    }
    exec(
        node,
        bucket,
        "DELETE FROM multipart_parts WHERE upload_id = ?1",
        json!([upload_id]),
    )
    .await?;
    for row in part_rows["rows"].as_array().into_iter().flatten() {
        if let (Some(sha256), Some(size), Some(storage_json)) = (
            row.get("sha256").and_then(Value::as_str),
            row.get("size").and_then(Value::as_u64),
            row.get("storage_json").and_then(Value::as_str),
        ) {
            let storage: StorageLocation = serde_json::from_str(storage_json)?;
            schedule_orphan_parts(node, bucket, sha256, size, &storage).await?;
        }
    }
    Ok(())
}

/// List active multipart sessions without loading their staged object bytes.
/// Upload IDs are random and immutable, which makes them safe continuation
/// cursors even while other sessions are created or removed.
pub async fn list_multipart_uploads(
    node: &Node,
    bucket: &str,
    prefix: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<MultipartUploadPage> {
    bucket_record(node, bucket).context("R2 bucket 不存在")?;
    if prefix.len() > MAX_OBJECT_KEY_BYTES || cursor.is_some_and(|value| value.len() > 64) {
        bail!("R2 分片上传列表参数过长");
    }
    if let Some(cursor) = cursor.filter(|value| !value.is_empty()) {
        validate_upload_id(cursor)?;
    }
    ensure_schema(node, bucket).await?;
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let result = exec(
        node,
        bucket,
        r#"SELECT u.upload_id, u.key, u.content_type, u.created_at_ms, u.expires_at_ms,
                  COUNT(p.part_number) AS part_count, COALESCE(SUM(p.size), 0) AS uploaded_bytes
           FROM multipart_uploads u
           LEFT JOIN multipart_parts p ON p.upload_id = u.upload_id
           WHERE u.key LIKE (?1 || '%') ESCAPE '\' AND u.upload_id > ?2
           GROUP BY u.upload_id, u.key, u.content_type, u.created_at_ms, u.expires_at_ms
           ORDER BY u.upload_id LIMIT ?3"#,
        json!([escape_like(prefix), cursor.unwrap_or(""), limit + 1]),
    )
    .await?;
    let mut uploads = result["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .map(row_to_multipart_summary)
        .collect::<Result<Vec<_>>>()?;
    let truncated = uploads.len() > limit;
    uploads.truncate(limit);
    let cursor = truncated
        .then(|| uploads.last().map(|upload| upload.upload_id.clone()))
        .flatten();
    Ok(MultipartUploadPage {
        uploads,
        truncated,
        cursor,
    })
}

/// Inspect one multipart session, including all uploaded part numbers and
/// checksums. The protocol caps a session at 10,000 parts, so this response is
/// strictly bounded and suitable for operator diagnostics.
pub async fn multipart_upload_detail(
    node: &Node,
    bucket: &str,
    upload_id: &str,
) -> Result<MultipartUploadDetail> {
    validate_upload_id(upload_id)?;
    bucket_record(node, bucket).context("R2 bucket 不存在")?;
    ensure_schema(node, bucket).await?;
    let upload_result = exec(
        node,
        bucket,
        r#"SELECT u.upload_id, u.key, u.content_type, u.custom_metadata, u.http_metadata,
                  u.storage_json, u.storage_policy, u.created_at_ms, u.expires_at_ms,
                  COUNT(p.part_number) AS part_count, COALESCE(SUM(p.size), 0) AS uploaded_bytes
           FROM multipart_uploads u
           LEFT JOIN multipart_parts p ON p.upload_id = u.upload_id
           WHERE u.upload_id = ?1
           GROUP BY u.upload_id, u.key, u.content_type, u.custom_metadata, u.http_metadata,
                    u.storage_json, u.storage_policy, u.created_at_ms, u.expires_at_ms"#,
        json!([upload_id]),
    )
    .await?;
    let row = upload_result["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(Value::as_object)
        .context("R2 分片上传不存在")?;
    let upload = row_to_multipart_summary(&Value::Object(row.clone()))?;
    let text = |name: &str| -> Result<&str> {
        row.get(name)
            .and_then(Value::as_str)
            .with_context(|| format!("R2 分片上传缺少 {name}"))
    };
    let parts_result = exec(
        node,
        bucket,
        "SELECT part_number, etag, size FROM multipart_parts WHERE upload_id = ?1 ORDER BY part_number",
        json!([upload_id]),
    )
    .await?;
    let parts = parts_result["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            Ok(UploadedPart {
                part_number: row["part_number"]
                    .as_u64()
                    .context("R2 分片缺少 part_number")?
                    .try_into()
                    .context("R2 分片编号超出范围")?,
                etag: row["etag"]
                    .as_str()
                    .context("R2 分片缺少 etag")?
                    .to_string(),
                size: row["size"].as_u64().context("R2 分片缺少 size")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(MultipartUploadDetail {
        upload,
        custom_metadata: serde_json::from_str(text("custom_metadata")?)?,
        http_metadata: serde_json::from_str(text("http_metadata")?)?,
        storage: serde_json::from_str(text("storage_json")?)?,
        storage_policy: row
            .get("storage_policy")
            .and_then(Value::as_str)
            .map(str::to_string),
        parts,
    })
}

pub async fn abort_multipart_upload_by_id(
    node: &Node,
    bucket: &str,
    upload_id: &str,
) -> Result<()> {
    let detail = multipart_upload_detail(node, bucket, upload_id).await?;
    abort_multipart_upload(node, bucket, &detail.upload.key, upload_id).await
}

fn row_to_multipart_summary(row: &Value) -> Result<MultipartUploadSummary> {
    let text = |name: &str| -> Result<&str> {
        row.get(name)
            .and_then(Value::as_str)
            .with_context(|| format!("R2 分片上传缺少 {name}"))
    };
    Ok(MultipartUploadSummary {
        upload_id: text("upload_id")?.to_string(),
        key: text("key")?.to_string(),
        content_type: row
            .get("content_type")
            .and_then(Value::as_str)
            .map(str::to_string),
        created_at_ms: row["created_at_ms"]
            .as_u64()
            .context("R2 分片上传缺少 created_at_ms")?,
        expires_at_ms: row["expires_at_ms"]
            .as_u64()
            .context("R2 分片上传缺少 expires_at_ms")?,
        part_count: row["part_count"]
            .as_u64()
            .context("R2 分片上传缺少 part_count")?,
        uploaded_bytes: row["uploaded_bytes"]
            .as_u64()
            .context("R2 分片上传缺少 uploaded_bytes")?,
    })
}

struct MultipartRow {
    storage: StorageLocation,
    storage_policy: Option<String>,
    options: PutOptions,
    expires_at_ms: u64,
}

fn multipart_requires_rclone(upload: &MultipartRow) -> bool {
    upload.storage_policy.is_some()
        || matches!(
            upload.storage,
            StorageLocation::Rclone { .. } | StorageLocation::RcloneShard { .. }
        )
}

async fn multipart_row(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<MultipartRow> {
    let result = exec(
        node,
        bucket,
        "SELECT content_type, custom_metadata, http_metadata, storage_json, storage_policy, expires_at_ms FROM multipart_uploads WHERE upload_id = ?1 AND key = ?2",
        json!([upload_id, key]),
    )
    .await?;
    let row = result["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(Value::as_object)
        .context("R2 分片上传不存在")?;
    let text = |name: &str| -> Result<&str> {
        row.get(name)
            .and_then(Value::as_str)
            .with_context(|| format!("R2 分片上传缺少 {name}"))
    };
    Ok(MultipartRow {
        storage: serde_json::from_str(text("storage_json")?)?,
        storage_policy: row
            .get("storage_policy")
            .and_then(Value::as_str)
            .map(str::to_string),
        options: PutOptions {
            content_type: row
                .get("content_type")
                .and_then(Value::as_str)
                .map(str::to_string),
            custom_metadata: serde_json::from_str(text("custom_metadata")?)?,
            http_metadata: serde_json::from_str(text("http_metadata")?)?,
        },
        expires_at_ms: row
            .get("expires_at_ms")
            .and_then(Value::as_u64)
            .context("R2 分片上传缺少 expires_at_ms")?,
    })
}

pub async fn head_object(node: &Node, bucket: &str, key: &str) -> Result<Option<ObjectMeta>> {
    validate_key(key)?;
    bucket_record(node, bucket).context("R2 bucket 不存在")?;
    ensure_schema(node, bucket).await?;
    let result = exec(
        node,
        bucket,
        "SELECT key, sha256, size, etag, content_type, custom_metadata, http_metadata, storage_json, uploaded_at_ms FROM objects WHERE key = ?1",
        json!([key]),
    )
    .await?;
    result["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .map(row_to_meta)
        .transpose()
}

pub async fn get_object(
    node: &Node,
    bucket: &str,
    key: &str,
) -> Result<Option<(ObjectMeta, Vec<u8>)>> {
    let Some((meta, file)) = materialize_object(node, bucket, key).await? else {
        return Ok(None);
    };
    let bytes = tokio::fs::read(file.path()).await?;
    if bytes.len() as u64 != meta.size {
        bail!("R2 对象在校验后读取期间发生截断");
    }
    if hex::encode(Sha256::digest(&bytes)) != meta.sha256 {
        bail!("R2 对象在校验后读取期间发生内容变化");
    }
    Ok(Some((meta, bytes)))
}

pub async fn materialize_object(
    node: &Node,
    bucket: &str,
    key: &str,
) -> Result<Option<(ObjectMeta, crate::objectstore::VerifiedObjectFile)>> {
    let Some(meta) = head_object(node, bucket, key).await? else {
        return Ok(None);
    };
    let sha: [u8; 32] = hex::decode(&meta.sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("R2 对象摘要长度无效"))?;
    let file = match node.objects.materialize_verified(&meta.storage, &sha).await {
        Ok(file) => file,
        Err(local_error) if meta.storage == StorageLocation::Local => {
            repair_local_file(node, bucket, key, &meta)
                .await
                .with_context(|| {
                    format!("本地 R2 对象缺失，且集群修复失败；原始错误：{local_error:#}")
                })?
        }
        Err(remote_error) if meta.storage != StorageLocation::Local => {
            borrow_remote_file(node, bucket, key, &meta, remote_error).await?
        }
        Err(error) => return Err(error),
    };
    if file.size() != meta.size {
        bail!("R2 对象大小与多数派元数据不一致");
    }
    Ok(Some((meta, file)))
}

async fn forward_put_to_storage_peer(
    node: &Node,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    options: PutOptions,
) -> Result<ObjectMeta> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let mut errors = Vec::new();
    for (id, peer) in node.peers() {
        if !peer.capabilities.contains("rclone") {
            continue;
        }
        let Some(address) = peer.api_addr else {
            continue;
        };
        match client
            .r2_put(&address.to_string(), bucket, key, bytes, &options)
            .await
        {
            Ok(meta) => return Ok(meta),
            Err(error) => errors.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "当前节点没有所需 rclone 能力，且无法借用可达节点{}",
        if errors.is_empty() {
            String::new()
        } else {
            format!("：{}", errors.join("；"))
        }
    )
}

async fn forward_put_file_to_storage_peer(
    node: &Node,
    bucket: &str,
    key: &str,
    staged: &StagedObjectFile,
    options: PutOptions,
) -> Result<ObjectMeta> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let mut errors = Vec::new();
    for (id, peer) in node.peers() {
        if !peer.capabilities.contains("rclone") {
            continue;
        }
        let Some(address) = peer.api_addr else {
            continue;
        };
        match client
            .r2_put_stream(&address.to_string(), bucket, key, staged, &options)
            .await
        {
            Ok(meta) => return Ok(meta),
            Err(error) => errors.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "当前节点没有所需 rclone 能力，且无法流式转交 R2 对象{}",
        storage_peer_errors(&errors)
    )
}

async fn forward_upload_part_to_storage_peer(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    bytes: &[u8],
) -> Result<UploadedPart> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let mut errors = Vec::new();
    for (id, peer) in node.peers() {
        if !peer.capabilities.contains("rclone") {
            continue;
        }
        let Some(address) = peer.api_addr else {
            continue;
        };
        match client
            .r2_upload_part(
                &address.to_string(),
                bucket,
                key,
                upload_id,
                part_number,
                bytes,
            )
            .await
        {
            Ok(part) => return Ok(part),
            Err(error) => errors.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "当前节点没有所需 rclone 能力，且无法转交 R2 multipart 分片{}",
        storage_peer_errors(&errors)
    )
}

async fn forward_upload_part_file_to_storage_peer(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    staged: &StagedObjectFile,
) -> Result<UploadedPart> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let mut errors = Vec::new();
    for (id, peer) in node.peers() {
        if !peer.capabilities.contains("rclone") {
            continue;
        }
        let Some(address) = peer.api_addr else {
            continue;
        };
        match client
            .r2_upload_part_stream(
                &address.to_string(),
                bucket,
                key,
                upload_id,
                part_number,
                staged,
            )
            .await
        {
            Ok(part) => return Ok(part),
            Err(error) => errors.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "当前节点没有所需 rclone 能力，且无法流式转交 R2 multipart 分片{}",
        storage_peer_errors(&errors)
    )
}

async fn forward_complete_to_storage_peer(
    node: &Node,
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[PublishedPart],
) -> Result<ObjectMeta> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let mut errors = Vec::new();
    for (id, peer) in node.peers() {
        if !peer.capabilities.contains("rclone") {
            continue;
        }
        let Some(address) = peer.api_addr else {
            continue;
        };
        match client
            .r2_complete_multipart(&address.to_string(), bucket, key, upload_id, parts)
            .await
        {
            Ok(metadata) => return Ok(metadata),
            Err(error) => errors.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "当前节点没有所需 rclone 能力，且无法转交 R2 multipart 完成请求{}",
        storage_peer_errors(&errors)
    )
}

fn storage_peer_errors(errors: &[String]) -> String {
    if errors.is_empty() {
        String::new()
    } else {
        format!("：{}", errors.join("；"))
    }
}

async fn borrow_remote_file(
    node: &Node,
    bucket: &str,
    key: &str,
    expected: &ObjectMeta,
    original: anyhow::Error,
) -> Result<crate::objectstore::VerifiedObjectFile> {
    let candidates = node
        .peers()
        .into_iter()
        .filter(|(_, peer)| peer.capabilities.contains("rclone"))
        .filter_map(|(id, peer)| peer.api_addr.map(|address| (id, address.to_string())))
        .collect();
    borrow_file_from_candidates(
        node,
        bucket,
        key,
        expected,
        candidates,
        vec![format!("本机：{original:#}")],
    )
    .await
}

async fn repair_local_file(
    node: &Node,
    bucket: &str,
    key: &str,
    expected: &ObjectMeta,
) -> Result<crate::objectstore::VerifiedObjectFile> {
    let group = d1::ensure_database(node, &metadata_database(bucket))?;
    let peers = node.peers();
    let candidates = group
        .into_iter()
        .filter(|member| *member != node.id())
        .filter_map(|member| {
            peers
                .get(&member.to_string())
                .and_then(|peer| peer.api_addr)
                .map(|address| (member.to_string(), address.to_string()))
        })
        .collect();
    let downloaded =
        borrow_file_from_candidates(node, bucket, key, expected, candidates, Vec::new()).await?;
    let digest: [u8; 32] = hex::decode(&expected.sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("R2 对象摘要长度无效"))?;
    let stored_size = node
        .objects
        .put_file_verified(&StorageLocation::Local, &digest, downloaded.path())
        .await?;
    if stored_size != expected.size {
        bail!("修复后的 R2 对象大小不一致");
    }
    drop(downloaded);
    node.objects
        .materialize_verified(&StorageLocation::Local, &digest)
        .await
}

async fn borrow_file_from_candidates(
    node: &Node,
    bucket: &str,
    key: &str,
    expected: &ObjectMeta,
    candidates: Vec<(String, String)>,
    mut errors: Vec<String>,
) -> Result<crate::objectstore::VerifiedObjectFile> {
    let digest: [u8; 32] = hex::decode(&expected.sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("R2 对象摘要长度无效"))?;
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let header_timeout =
        Duration::from_secs(node.cfg.storage.rclone_timeout_seconds.saturating_add(30));
    for (id, address) in candidates {
        match client
            .r2_stream_object(&address, bucket, key, &expected.sha256, header_timeout)
            .await
        {
            Ok(Some(stream)) => {
                match node
                    .objects
                    .materialize_stream_verified(&digest, expected.size, stream)
                    .await
                {
                    Ok(file) => return Ok(file),
                    Err(error) => errors.push(format!("{id}: 流校验失败：{error:#}")),
                }
            }
            Ok(None) => errors.push(format!("{id}: 对象不存在")),
            Err(error) => errors.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "R2 对象的加密节点流式借用失败{}",
        storage_peer_errors(&errors)
    )
}

pub async fn delete_object(node: &Node, bucket: &str, key: &str) -> Result<bool> {
    validate_key(key)?;
    bucket_record(node, bucket).context("R2 bucket 不存在")?;
    ensure_schema(node, bucket).await?;
    let previous = head_object(node, bucket, key).await?;
    let result = exec(
        node,
        bucket,
        "DELETE FROM objects WHERE key = ?1",
        json!([key]),
    )
    .await?;
    let deleted = result["rows_affected"].as_u64().unwrap_or(0) > 0;
    if deleted {
        if let Some(previous) = previous {
            schedule_orphan(node, bucket, &previous).await?;
        }
    }
    Ok(deleted)
}

pub async fn list_objects(
    node: &Node,
    bucket: &str,
    prefix: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<ObjectList> {
    bucket_record(node, bucket).context("R2 bucket 不存在")?;
    if prefix.len() > MAX_OBJECT_KEY_BYTES || cursor.is_some_and(|value| value.len() > 2048) {
        bail!("R2 列表参数过长");
    }
    ensure_schema(node, bucket).await?;
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let escaped_prefix = escape_like(prefix);
    let result = exec(
        node,
        bucket,
        "SELECT key, sha256, size, etag, content_type, custom_metadata, http_metadata, storage_json, uploaded_at_ms FROM objects WHERE key LIKE (?1 || '%') ESCAPE '\\' AND key > ?2 ORDER BY key LIMIT ?3",
        json!([escaped_prefix, cursor.unwrap_or(""), limit + 1]),
    )
    .await?;
    let mut objects = result["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .map(row_to_meta)
        .collect::<Result<Vec<_>>>()?;
    let truncated = objects.len() > limit;
    objects.truncate(limit);
    let cursor = truncated
        .then(|| objects.last().map(|object| object.key.clone()))
        .flatten();
    Ok(ObjectList {
        objects,
        delimited_prefixes: vec![],
        truncated,
        cursor,
    })
}

/// Strongly-consistent usage counters for one bucket. The bytes value counts
/// logical object bytes (not multipart staging or deduplicated physical
/// blobs); callers decide whether the bucket's backing store is local/rclone.
pub async fn bucket_usage(node: &Node, bucket: &str) -> Result<BucketUsage> {
    bucket_record(node, bucket).context("R2 bucket 不存在")?;
    ensure_schema(node, bucket).await?;
    let result = exec(
        node,
        bucket,
        "SELECT COALESCE(SUM(size), 0) AS bytes, COUNT(*) AS objects FROM objects",
        json!([]),
    )
    .await?;
    let row = result["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(Value::as_object)
        .context("R2 使用量统计缺失")?;
    Ok(BucketUsage {
        bytes: row.get("bytes").and_then(Value::as_u64).unwrap_or(0),
        objects: row.get("objects").and_then(Value::as_u64).unwrap_or(0),
    })
}

pub async fn storage_distribution(node: &Node) -> Result<Vec<StorageUsage>> {
    let mut totals: BTreeMap<String, StorageUsage> = BTreeMap::new();
    for (view, _) in bucket_records(node) {
        let bucket = view.resource.name;
        ensure_schema(node, &bucket).await?;
        let result = exec(
            node,
            &bucket,
            "SELECT storage_json, COUNT(*) AS objects, COALESCE(SUM(size), 0) AS bytes FROM objects GROUP BY storage_json",
            json!([]),
        )
        .await?;
        for row in result["rows"].as_array().into_iter().flatten() {
            let raw = row
                .get("storage_json")
                .and_then(Value::as_str)
                .context("R2 存储分布缺少位置")?;
            let storage: StorageLocation = serde_json::from_str(raw)?;
            let entry = totals.entry(raw.to_string()).or_insert(StorageUsage {
                storage,
                bytes: 0,
                objects: 0,
                buckets: 0,
            });
            entry.bytes = entry
                .bytes
                .saturating_add(row.get("bytes").and_then(Value::as_u64).unwrap_or(0));
            entry.objects = entry
                .objects
                .saturating_add(row.get("objects").and_then(Value::as_u64).unwrap_or(0));
            entry.buckets = entry.buckets.saturating_add(1);
        }
    }
    Ok(totals.into_values().collect())
}

/// Count every live metadata reference to a concrete policy shard, including
/// in-flight multipart parts. Storage-policy admission uses this to prevent a
/// remote from being removed while any committed or staged byte still relies
/// on it.
pub(crate) async fn shard_references(node: &Node) -> Result<BTreeMap<String, u64>> {
    let mut totals = BTreeMap::new();
    for (view, _) in bucket_records(node) {
        let bucket = view.resource.name;
        ensure_schema(node, &bucket).await?;
        let result = exec(
            node,
            &bucket,
            r#"SELECT storage_json, COUNT(*) AS references_count
               FROM (
                 SELECT storage_json FROM objects
                 UNION ALL
                 SELECT storage_json FROM multipart_parts
               )
               GROUP BY storage_json"#,
            json!([]),
        )
        .await?;
        for row in result["rows"].as_array().into_iter().flatten() {
            let storage: StorageLocation = serde_json::from_str(
                row.get("storage_json")
                    .and_then(Value::as_str)
                    .context("R2 分片引用缺少存储位置")?,
            )?;
            if let StorageLocation::RcloneShard { remote, .. } = storage {
                let count = row
                    .get("references_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let total = totals.entry(remote).or_insert(0u64);
                *total = total.saturating_add(count);
            }
        }
    }
    Ok(totals)
}

/// Folder-style listing compatible with R2/S3 delimiter semantics. Objects
/// beneath the same immediate prefix count as one result and cursors remain an
/// exclusive raw-key lower bound, so pagination never leaks keys outside the
/// requested prefix.
pub async fn list_objects_delimited(
    node: &Node,
    bucket: &str,
    prefix: &str,
    cursor: Option<&str>,
    limit: usize,
    delimiter: &str,
) -> Result<ObjectList> {
    if delimiter.is_empty() {
        return list_objects(node, bucket, prefix, cursor, limit).await;
    }
    if delimiter.len() > 64 || delimiter.contains(['\0', '\r', '\n']) {
        bail!("R2 列表 delimiter 无效");
    }
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let mut objects = Vec::new();
    let mut prefixes = Vec::new();
    let mut seen = HashSet::new();
    let mut after = cursor.map(str::to_string);
    let mut last_consumed = after.clone();
    let mut truncated = false;

    // A huge virtual folder may require scanning substantially more keys than
    // the requested result count. Bound each request to 20,000 metadata rows;
    // a continuation cursor lets the caller resume without unbounded work.
    'batches: for _ in 0..20 {
        let page = list_objects(node, bucket, prefix, after.as_deref(), MAX_LIST_LIMIT).await?;
        if page.objects.is_empty() {
            truncated = false;
            break;
        }
        let page_truncated = page.truncated;
        let page_last = page.objects.last().map(|object| object.key.clone());
        for object in page.objects {
            let remainder = object.key.strip_prefix(prefix).unwrap_or(&object.key);
            if let Some(index) = remainder.find(delimiter) {
                let grouped = format!("{prefix}{}", &remainder[..index + delimiter.len()]);
                if seen.insert(grouped.clone()) {
                    if objects.len() + prefixes.len() >= limit {
                        truncated = true;
                        break 'batches;
                    }
                    prefixes.push(grouped);
                }
            } else {
                if objects.len() + prefixes.len() >= limit {
                    truncated = true;
                    break 'batches;
                }
                objects.push(object.clone());
            }
            last_consumed = Some(object.key);
        }
        if !page_truncated {
            truncated = false;
            break;
        }
        after = page_last;
        truncated = true;
    }

    Ok(ObjectList {
        objects,
        delimited_prefixes: prefixes,
        truncated,
        cursor: truncated.then_some(last_consumed).flatten(),
    })
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SweepResult {
    pub expired_objects: u64,
    pub expired_uploads: u64,
    pub collected_blobs: u64,
    pub retained_blobs: u64,
    pub stale_assembly_files: u64,
    pub stale_read_spool_files: u64,
}

/// Apply bucket lifecycle rules, expire abandoned multipart uploads and safely
/// collect content-addressed bytes after a grace period. Before deleting a
/// blob, every signed bucket catalog is queried for object and in-flight-part
/// references. Any unavailable quorum makes the sweep fail closed.
pub async fn sweep_lifecycle(node: &Node) -> Result<SweepResult> {
    let now = now_ms();
    let mut outcome = SweepResult::default();
    let all_buckets: Vec<(String, bool, BucketSpec)> = resource::heads(node, Some(BUCKET_KIND))
        .into_iter()
        .filter_map(|view| {
            bucket_spec(&view.resource)
                .ok()
                .map(|spec| (view.resource.name, view.resource.deleted, spec))
        })
        .collect();

    for (bucket, deleted, spec) in &all_buckets {
        ensure_schema(node, bucket).await?;
        let lifecycle_cutoff = if *deleted {
            Some(u64::MAX)
        } else {
            spec.expire_objects_after_days
                .map(|days| now.saturating_sub(days as u64 * 24 * 60 * 60 * 1000))
        };
        if let Some(cutoff) = lifecycle_cutoff {
            loop {
                let result = exec(
                        node,
                        bucket,
                        "SELECT key, sha256, size, etag, content_type, custom_metadata, http_metadata, storage_json, uploaded_at_ms FROM objects WHERE uploaded_at_ms <= ?1 ORDER BY uploaded_at_ms LIMIT 500",
                        json!([cutoff]),
                    )
                    .await?;
                let expired = result["rows"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(row_to_meta)
                    .collect::<Result<Vec<_>>>()?;
                if expired.is_empty() {
                    break;
                }
                for object in expired {
                    let deleted = exec(
                            node,
                            bucket,
                            "DELETE FROM objects WHERE key = ?1 AND sha256 = ?2 AND uploaded_at_ms = ?3",
                            json!([&object.key, &object.sha256, object.uploaded_at_ms]),
                        )
                        .await?;
                    if deleted["rows_affected"].as_u64() == Some(1) {
                        schedule_orphan(node, bucket, &object).await?;
                        outcome.expired_objects += 1;
                    }
                }
                if result["rows"].as_array().map_or(0, Vec::len) < 500 {
                    break;
                }
            }
        }

        let uploads = exec(
            node,
            bucket,
            "SELECT upload_id, key FROM multipart_uploads WHERE expires_at_ms <= ?1 LIMIT 500",
            json!([if *deleted { u64::MAX } else { now }]),
        )
        .await?;
        for upload in uploads["rows"].as_array().into_iter().flatten() {
            let Some(upload_id) = upload.get("upload_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(key) = upload.get("key").and_then(Value::as_str) else {
                continue;
            };
            if abort_multipart_upload(node, bucket, key, upload_id)
                .await
                .is_ok()
            {
                outcome.expired_uploads += 1;
            }
        }
    }

    for (bucket, _, _) in &all_buckets {
        let candidates = exec(
            node,
            bucket,
            "SELECT sha256, storage_json FROM orphan_candidates WHERE eligible_at_ms <= ?1 LIMIT 500",
            json!([now]),
        )
        .await?;
        for candidate in candidates["rows"].as_array().into_iter().flatten() {
            let Some(sha256) = candidate.get("sha256").and_then(Value::as_str) else {
                continue;
            };
            let Some(storage_json) = candidate.get("storage_json").and_then(Value::as_str) else {
                continue;
            };
            if blob_referenced_anywhere(node, &all_buckets, sha256, storage_json).await? {
                remove_orphan_candidate(node, bucket, sha256, storage_json).await?;
                outcome.retained_blobs += 1;
                continue;
            }
            let storage: StorageLocation = serde_json::from_str(storage_json)?;
            let sha: [u8; 32] = hex::decode(sha256)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("R2 待回收对象摘要长度无效"))?;
            node.objects.delete(&storage, &sha).await?;
            remove_orphan_candidate(node, bucket, sha256, storage_json).await?;
            outcome.collected_blobs += 1;
        }
    }
    let assembly_dir = node.objects.local_root().join(".multipart-assembly");
    if let Ok(mut entries) = tokio::fs::read_dir(&assembly_dir).await {
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("tmp") {
                continue;
            }
            let modified = entry.metadata().await?.modified()?;
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            if age.as_millis() >= MULTIPART_TTL_MS as u128
                && tokio::fs::remove_file(path).await.is_ok()
            {
                outcome.stale_assembly_files += 1;
            }
        }
    }
    let read_spool = node.objects.local_root().join(".read-spool");
    if let Ok(mut entries) = tokio::fs::read_dir(&read_spool).await {
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("tmp") {
                continue;
            }
            let modified = entry.metadata().await?.modified()?;
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            if age.as_millis() >= MULTIPART_TTL_MS as u128
                && tokio::fs::remove_file(path).await.is_ok()
            {
                outcome.stale_read_spool_files += 1;
            }
        }
    }
    Ok(outcome)
}

async fn schedule_orphan(node: &Node, bucket: &str, object: &ObjectMeta) -> Result<()> {
    schedule_orphan_parts(node, bucket, &object.sha256, object.size, &object.storage).await
}

async fn schedule_orphan_parts(
    node: &Node,
    bucket: &str,
    sha256: &str,
    size: u64,
    storage: &StorageLocation,
) -> Result<()> {
    exec(
        node,
        bucket,
        "INSERT INTO orphan_candidates (sha256, storage_json, size, eligible_at_ms) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(sha256, storage_json) DO UPDATE SET eligible_at_ms = MAX(orphan_candidates.eligible_at_ms, excluded.eligible_at_ms)",
        json!([
            sha256,
            serde_json::to_string(storage)?,
            size,
            now_ms().saturating_add(ORPHAN_GRACE_MS),
        ]),
    )
    .await?;
    Ok(())
}

async fn blob_referenced_anywhere(
    node: &Node,
    buckets: &[(String, bool, BucketSpec)],
    sha256: &str,
    storage_json: &str,
) -> Result<bool> {
    for (bucket, deleted, _) in buckets {
        if *deleted {
            continue;
        }
        let result = exec(
            node,
            bucket,
            "SELECT 1 AS present FROM objects WHERE sha256 = ?1 AND storage_json = ?2 UNION ALL SELECT 1 AS present FROM multipart_parts WHERE sha256 = ?1 AND storage_json = ?2 LIMIT 1",
            json!([sha256, storage_json]),
        )
        .await?;
        if result["rows"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn remove_orphan_candidate(
    node: &Node,
    bucket: &str,
    sha256: &str,
    storage_json: &str,
) -> Result<()> {
    exec(
        node,
        bucket,
        "DELETE FROM orphan_candidates WHERE sha256 = ?1 AND storage_json = ?2",
        json!([sha256, storage_json]),
    )
    .await?;
    Ok(())
}

/// Encode upload options and bytes into one authenticated/encrypted request
/// body. Keeping options in the body (rather than ordinary HTTP headers)
/// prevents an on-path peer from changing object metadata.
pub fn encode_put_request(options: &PutOptions, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_BUFFERED_OBJECT_BYTES {
        bail!("R2 内存直传对象不得超过 63 MiB；大对象必须使用流式入口");
    }
    let mut payload = encode_put_options_prefix(options)?;
    payload.extend_from_slice(bytes);
    Ok(payload)
}

pub fn encode_put_options_prefix(options: &PutOptions) -> Result<Vec<u8>> {
    validate_metadata(options)?;
    let encoded = serde_json::to_vec(options)?;
    if encoded.len() > MAX_PUT_OPTIONS_BYTES {
        bail!("R2 上传选项不得超过 32 KiB");
    }
    let mut payload = Vec::with_capacity(4 + encoded.len());
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

pub fn decode_put_request(payload: &[u8]) -> Result<(PutOptions, &[u8])> {
    if payload.len() < 4 {
        bail!("R2 上传请求不完整");
    }
    let options_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
    if options_len > MAX_PUT_OPTIONS_BYTES || payload.len() < 4 + options_len {
        bail!("R2 上传选项长度无效");
    }
    let options: PutOptions = serde_json::from_slice(&payload[4..4 + options_len])?;
    validate_metadata(&options)?;
    let bytes = &payload[4 + options_len..];
    if bytes.len() > MAX_BUFFERED_OBJECT_BYTES {
        bail!("R2 内存直传对象不得超过 63 MiB；大对象必须使用流式入口");
    }
    Ok((options, bytes))
}

pub fn encode_get_response(metadata: &ObjectMeta, bytes: &[u8]) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(metadata)?;
    if encoded.len() > MAX_PUT_OPTIONS_BYTES {
        bail!("R2 对象元数据响应过大");
    }
    let mut payload = Vec::with_capacity(4 + encoded.len() + bytes.len());
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    payload.extend_from_slice(bytes);
    Ok(payload)
}

pub fn decode_get_response(payload: &[u8]) -> Result<(ObjectMeta, Vec<u8>)> {
    if payload.len() < 4 {
        bail!("R2 对象响应不完整");
    }
    let metadata_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
    if metadata_len > MAX_PUT_OPTIONS_BYTES || payload.len() < 4 + metadata_len {
        bail!("R2 对象元数据响应长度无效");
    }
    let metadata = serde_json::from_slice(&payload[4..4 + metadata_len])?;
    Ok((metadata, payload[4 + metadata_len..].to_vec()))
}

async fn ensure_schema(node: &Node, bucket: &str) -> Result<Vec<rf_core::identity::PublicId>> {
    let database = metadata_database(bucket);
    let group = d1::ensure_database(node, &database)?;
    if node.r2_schema_ready(&database) {
        return Ok(group);
    }
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS objects (
             key TEXT PRIMARY KEY,
             sha256 TEXT NOT NULL,
             size INTEGER NOT NULL CHECK(size >= 0),
             etag TEXT NOT NULL,
             content_type TEXT,
             custom_metadata TEXT NOT NULL,
             http_metadata TEXT NOT NULL,
             storage_json TEXT NOT NULL,
             uploaded_at_ms INTEGER NOT NULL
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS orphan_candidates (
             sha256 TEXT NOT NULL,
             storage_json TEXT NOT NULL,
             size INTEGER NOT NULL CHECK(size >= 0),
             eligible_at_ms INTEGER NOT NULL,
             PRIMARY KEY(sha256, storage_json)
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS multipart_uploads (
             upload_id TEXT PRIMARY KEY,
             key TEXT NOT NULL,
             content_type TEXT,
             custom_metadata TEXT NOT NULL,
             http_metadata TEXT NOT NULL,
             storage_json TEXT NOT NULL,
             storage_policy TEXT,
             created_at_ms INTEGER NOT NULL,
             expires_at_ms INTEGER NOT NULL
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS multipart_parts (
             upload_id TEXT NOT NULL,
             part_number INTEGER NOT NULL CHECK(part_number BETWEEN 1 AND 10000),
             sha256 TEXT NOT NULL,
             size INTEGER NOT NULL CHECK(size >= 0),
             etag TEXT NOT NULL,
             storage_json TEXT NOT NULL,
             uploaded_at_ms INTEGER NOT NULL,
             PRIMARY KEY(upload_id, part_number)
           )"#,
        json!([]),
    )
    .await?;
    ensure_column(
        node,
        &database,
        "multipart_uploads",
        "storage_policy",
        "TEXT",
    )
    .await?;
    ensure_column(node, &database, "multipart_parts", "storage_json", "TEXT").await?;
    // Legacy in-flight parts inherited the fixed upload location. Populate
    // the new per-part pin before any read/GC path relies on it.
    exec_database(
        node,
        &database,
        r#"UPDATE multipart_parts
           SET storage_json = (
             SELECT storage_json FROM multipart_uploads
             WHERE multipart_uploads.upload_id = multipart_parts.upload_id
           )
           WHERE storage_json IS NULL OR storage_json = ''"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        "CREATE INDEX IF NOT EXISTS multipart_upload_expiry ON multipart_uploads(expires_at_ms)",
        json!([]),
    )
    .await?;
    node.mark_r2_schema_ready(database);
    Ok(group)
}

async fn ensure_column(
    node: &Node,
    database: &str,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let info = exec_database(
        node,
        database,
        &format!("PRAGMA table_info({table})"),
        json!([]),
    )
    .await?;
    let present = info["rows"].as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row.get("name").and_then(Value::as_str) == Some(column))
    });
    if !present {
        exec_database(
            node,
            database,
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            json!([]),
        )
        .await?;
    }
    Ok(())
}

async fn replicate_local_blob(
    node: &Node,
    group: &[rf_core::identity::PublicId],
    sha: &[u8; 32],
    bytes: &[u8],
) -> Result<()> {
    let required = group.len() / 2 + 1;
    let mut stored = HashSet::new();
    if group.contains(&node.id()) {
        stored.insert(node.id());
    }
    let peers = node.peers();
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    for member in group {
        if stored.len() >= required {
            break;
        }
        if member == &node.id() {
            continue;
        }
        let Some(api) = peers
            .get(&member.to_string())
            .and_then(|peer| peer.api_addr)
            .map(|address| address.to_string())
        else {
            continue;
        };
        match client.r2_put_blob(&api, bytes).await {
            Ok(remote_sha) if &remote_sha == sha => {
                stored.insert(*member);
            }
            Ok(_) => tracing::warn!("R2 replica {member} returned a different digest"),
            Err(error) => tracing::warn!("R2 replica write to {member} failed: {error:#}"),
        }
    }
    if stored.len() < required {
        bail!(
            "R2 对象只写入 {} 个副本，未达到数据组多数派 {}；未提交元数据",
            stored.len(),
            required
        );
    }
    Ok(())
}

async fn replicate_local_blob_file(
    node: &Node,
    group: &[rf_core::identity::PublicId],
    staged: &StagedObjectFile,
) -> Result<()> {
    let required = group.len() / 2 + 1;
    let mut stored = HashSet::new();
    if group.contains(&node.id()) {
        stored.insert(node.id());
    }
    let peers = node.peers();
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    for member in group {
        if stored.len() >= required {
            break;
        }
        if member == &node.id() {
            continue;
        }
        let Some(api) = peers
            .get(&member.to_string())
            .and_then(|peer| peer.api_addr)
            .map(|address| address.to_string())
        else {
            continue;
        };
        match client.r2_put_blob_stream(&api, staged).await {
            Ok(remote_sha) if remote_sha == staged.sha256() => {
                stored.insert(*member);
            }
            Ok(_) => tracing::warn!("R2 replica {member} returned a different digest"),
            Err(error) => tracing::warn!("R2 streamed replica write to {member} failed: {error:#}"),
        }
    }
    if stored.len() < required {
        bail!(
            "R2 对象只写入 {} 个副本，未达到数据组多数派 {}；未提交元数据",
            stored.len(),
            required
        );
    }
    Ok(())
}

async fn exec(node: &Node, bucket: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &metadata_database(bucket), sql, params).await
}

async fn exec_database(node: &Node, database: &str, sql: &str, params: Value) -> Result<Value> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let listen = node.cfg.peer_api.listen;
    let base = if listen.is_ipv6() {
        format!("[::1]:{}", listen.port())
    } else {
        format!("127.0.0.1:{}", listen.port())
    };
    client.d1_exec(&base, database, sql, params).await
}

fn row_to_meta(row: &Value) -> Result<ObjectMeta> {
    let object = row.as_object().context("R2 元数据行不是对象")?;
    let string = |name: &str| -> Result<String> {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .with_context(|| format!("R2 元数据缺少 {name}"))
    };
    let optional_string = |name: &str| -> Option<String> {
        object.get(name).and_then(Value::as_str).map(str::to_string)
    };
    let parse_map = |name: &str| -> Result<serde_json::Map<String, Value>> {
        let raw = string(name)?;
        serde_json::from_str::<Value>(&raw)?
            .as_object()
            .cloned()
            .with_context(|| format!("R2 元数据 {name} 不是对象"))
    };
    Ok(ObjectMeta {
        key: string("key")?,
        sha256: string("sha256")?,
        size: object
            .get("size")
            .and_then(Value::as_u64)
            .context("R2 元数据缺少 size")?,
        etag: string("etag")?,
        content_type: optional_string("content_type"),
        custom_metadata: parse_map("custom_metadata")?,
        http_metadata: parse_map("http_metadata")?,
        storage: serde_json::from_str(&string("storage_json")?)?,
        uploaded_at_ms: object
            .get("uploaded_at_ms")
            .and_then(Value::as_u64)
            .context("R2 元数据缺少 uploaded_at_ms")?,
    })
}

pub(crate) fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > MAX_OBJECT_KEY_BYTES
        || key.as_bytes().contains(&0)
        || key.contains(['\r', '\n'])
    {
        bail!("R2 对象键必须是 1 至 1024 字节且不能包含控制分隔符");
    }
    Ok(())
}

fn validate_upload_id(upload_id: &str) -> Result<()> {
    if upload_id.len() != 40 || !upload_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("R2 分片上传 ID 无效");
    }
    Ok(())
}

fn validate_published_parts(parts: &[PublishedPart]) -> Result<()> {
    if parts.is_empty() || parts.len() > MAX_MULTIPART_PARTS {
        bail!("R2 完成分片上传时必须提交 1 至 10000 个分片");
    }
    let mut previous = 0;
    for part in parts {
        if !(1..=MAX_MULTIPART_PARTS as u32).contains(&part.part_number)
            || part.part_number <= previous
            || part.etag.len() > 256
        {
            bail!("R2 已发布分片必须按编号严格递增，且 ETag 有效");
        }
        previous = part.part_number;
    }
    Ok(())
}

fn constant_time_string_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn validate_metadata(options: &PutOptions) -> Result<()> {
    if options
        .content_type
        .as_ref()
        .is_some_and(|value| value.len() > 512 || value.contains(['\r', '\n']))
    {
        bail!("R2 Content-Type 无效");
    }
    let custom_size = serde_json::to_vec(&options.custom_metadata)?.len();
    let http_size = serde_json::to_vec(&options.http_metadata)?.len();
    if custom_size > 8 * 1024 || http_size > 8 * 1024 {
        bail!("R2 对象元数据不得超过 8 KiB");
    }
    Ok(())
}

fn escape_like(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len());
    for character in prefix.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use futures_util::TryStreamExt;
    use rf_core::envelope::Envelope;
    use rf_core::identity::{AnyKeypair, Keypair};
    use std::sync::Arc;

    #[test]
    fn bucket_specs_validate_rclone_without_credentials() {
        let spec = BucketSpec {
            description: "archive".into(),
            public_access: false,
            storage: StorageLocation::Rclone {
                remote: "b2-hot".into(),
                prefix: "randallflare".into(),
            },
            storage_policy: None,
            max_bytes: Some(1024),
            max_objects: Some(10),
            expire_objects_after_days: Some(30),
            cors_origins: vec!["https://console.example".into()],
            hostnames: vec!["objects.example.com".into()],
        };
        spec.validate().unwrap();
        let mut internal_location = spec.clone();
        internal_location.storage = StorageLocation::RcloneShard {
            remote: "b2-hot".into(),
            prefix: "randallflare".into(),
        };
        assert!(internal_location.validate().is_err());
        let encoded = serde_json::to_string(&spec).unwrap();
        assert!(!encoded.to_ascii_lowercase().contains("secret"));
        assert_eq!(metadata_database("events").len(), 35);
    }

    #[test]
    fn object_keys_and_metadata_are_bounded() {
        assert_eq!(MAX_DIRECT_OBJECT_BYTES as u64, 5 * 1024 * 1024 * 1024);
        assert_eq!(MAX_MULTIPART_PART_BYTES as u64, 5 * 1024 * 1024 * 1024);
        assert_eq!(
            MAX_MULTIPART_OBJECT_BYTES,
            5 * 1024 * 1024 * 1024 * 1024 - 5 * 1024 * 1024 * 1024
        );
        assert!(validate_key("").is_err());
        assert!(validate_key("hello/world.json").is_ok());
        assert!(validate_key(&"x".repeat(1025)).is_err());
        assert!(validate_metadata(&PutOptions {
            content_type: Some("text/plain\r\nbad: yes".into()),
            ..PutOptions::default()
        })
        .is_err());
        assert_eq!(escape_like("100%_done\\raw"), "100\\%\\_done\\\\raw");
        assert!(validate_upload_id(&"ab".repeat(20)).is_ok());
        assert!(validate_upload_id("../escape").is_err());
        assert!(validate_published_parts(&[
            PublishedPart {
                part_number: 1,
                etag: "a".into(),
            },
            PublishedPart {
                part_number: 2,
                etag: "b".into(),
            },
        ])
        .is_ok());
        assert!(validate_published_parts(&[
            PublishedPart {
                part_number: 2,
                etag: "a".into(),
            },
            PublishedPart {
                part_number: 1,
                etag: "b".into(),
            },
        ])
        .is_err());
    }

    #[test]
    fn upload_framing_round_trips_metadata_and_binary_bytes() {
        let options = PutOptions {
            content_type: Some("application/octet-stream".into()),
            custom_metadata: serde_json::Map::from_iter([(
                "来源".into(),
                Value::String("测试".into()),
            )]),
            ..PutOptions::default()
        };
        let bytes = b"\0\x01binary";
        let encoded = encode_put_request(&options, bytes).unwrap();
        let (decoded, decoded_bytes) = decode_put_request(&encoded).unwrap();
        assert_eq!(decoded.content_type, options.content_type);
        assert_eq!(decoded.custom_metadata, options.custom_metadata);
        assert_eq!(decoded_bytes, bytes);

        let metadata = ObjectMeta {
            key: "bin/data".into(),
            sha256: "ab".repeat(32),
            size: bytes.len() as u64,
            etag: "ab".repeat(32),
            content_type: options.content_type,
            custom_metadata: options.custom_metadata,
            http_metadata: Default::default(),
            storage: StorageLocation::Local,
            uploaded_at_ms: 42,
        };
        let encoded = encode_get_response(&metadata, bytes).unwrap();
        let (decoded_metadata, decoded_bytes) = decode_get_response(&encoded).unwrap();
        assert_eq!(decoded_metadata.key, metadata.key);
        assert_eq!(decoded_bytes, bytes);
    }

    #[tokio::test]
    async fn signed_bucket_round_trips_over_encrypted_peer_api_and_d1() {
        let peer_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        drop(peer_listener);
        let gossip_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gossip_addr = gossip_listener.local_addr().unwrap();
        drop(gossip_listener);

        let root = std::env::temp_dir().join(format!(
            "rf-r2-e2e-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let operator = AnyKeypair::Ed(Keypair::from_seed([81; 32]));
        let config: NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {root:?}
            operator = "{}"
            cluster_secret = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            [gossip]
            listen = "{gossip_addr}"
            [peer_api]
            listen = "{peer_addr}"
            [ingress]
            default_domain = "workers.test"
            "#,
            operator.signer_id(),
        ))
        .unwrap();
        let node = Arc::new(Node::open(config, Keypair::from_seed([82; 32])).unwrap());
        let bucket = prepare_bucket(
            &node,
            "e2e-bucket",
            BucketSpec {
                description: "端到端测试".into(),
                public_access: false,
                storage: StorageLocation::Local,
                storage_policy: None,
                max_bytes: Some(8 * 1024 * 1024),
                max_objects: Some(10),
                expire_objects_after_days: None,
                cors_origins: vec![],
                hostnames: vec![],
            },
            false,
        )
        .unwrap();
        resource::ingest(&node, &Envelope::seal_any(&bucket, &operator)).unwrap();

        let registry: crate::d1::Registry = Default::default();
        let leadership: crate::d1::Leadership = Default::default();
        let durable =
            crate::durable::Coordinator::new(node.clone(), registry.clone(), leadership.clone());
        let (address, server) =
            crate::peerapi::serve_managed(node.clone(), registry.clone(), durable.clone())
                .await
                .unwrap();
        let manager = crate::d1::spawn_manager(node.clone(), registry.clone(), leadership);
        let client = PeerClient::new(node.cfg.cluster_secret_bytes().unwrap());
        let base = address.to_string();

        // Reproduce the pre-storage-policy multipart schema. The first normal
        // R2 operation must add and backfill the new columns online without
        // invalidating an otherwise usable bucket database.
        let database = metadata_database("e2e-bucket");
        crate::d1::ensure_database(&node, &database).unwrap();
        exec_database(
            &node,
            &database,
            r#"CREATE TABLE multipart_uploads (
                 upload_id TEXT PRIMARY KEY,
                 key TEXT NOT NULL,
                 content_type TEXT,
                 custom_metadata TEXT NOT NULL,
                 http_metadata TEXT NOT NULL,
                 storage_json TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 expires_at_ms INTEGER NOT NULL
               )"#,
            json!([]),
        )
        .await
        .unwrap();
        exec_database(
            &node,
            &database,
            r#"CREATE TABLE multipart_parts (
                 upload_id TEXT NOT NULL,
                 part_number INTEGER NOT NULL,
                 sha256 TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 etag TEXT NOT NULL,
                 uploaded_at_ms INTEGER NOT NULL,
                 PRIMARY KEY(upload_id, part_number)
               )"#,
            json!([]),
        )
        .await
        .unwrap();
        let legacy_upload_id = "11".repeat(20);
        let legacy_bytes = b"legacy multipart part";
        let legacy_sha = node
            .objects
            .put(&StorageLocation::Local, legacy_bytes)
            .await
            .unwrap();
        exec_database(
            &node,
            &database,
            "INSERT INTO multipart_uploads (upload_id, key, content_type, custom_metadata, http_metadata, storage_json, created_at_ms, expires_at_ms) VALUES (?1, ?2, NULL, '{}', '{}', ?3, ?4, ?5)",
            json!([
                legacy_upload_id,
                "legacy.bin",
                serde_json::to_string(&StorageLocation::Local).unwrap(),
                now_ms(),
                now_ms() + 60_000,
            ]),
        )
        .await
        .unwrap();
        exec_database(
            &node,
            &database,
            "INSERT INTO multipart_parts (upload_id, part_number, sha256, size, etag, uploaded_at_ms) VALUES (?1, 1, ?2, ?3, ?2, ?4)",
            json!([
                legacy_upload_id,
                hex::encode(legacy_sha),
                legacy_bytes.len(),
                now_ms(),
            ]),
        )
        .await
        .unwrap();

        let options = PutOptions {
            content_type: Some("text/plain; charset=utf-8".into()),
            ..PutOptions::default()
        };
        let metadata = client
            .r2_put(
                &base,
                "e2e-bucket",
                "metrics%_exact.txt",
                b"hello R2",
                &options,
            )
            .await
            .unwrap();
        assert_eq!(metadata.size, 8);
        assert_eq!(metadata.etag, hex::encode(Md5::digest(b"hello R2")));
        let legacy_location = exec_database(
            &node,
            &database,
            "SELECT storage_json FROM multipart_parts WHERE upload_id = ?1",
            json!([legacy_upload_id.clone()]),
        )
        .await
        .unwrap();
        assert_eq!(
            legacy_location["rows"][0]["storage_json"].as_str(),
            Some(r#"{"type":"local"}"#)
        );
        abort_multipart_upload(&node, "e2e-bucket", "legacy.bin", &legacy_upload_id)
            .await
            .unwrap();
        client
            .r2_put(
                &base,
                "e2e-bucket",
                "metricsXXother.txt",
                b"other",
                &options,
            )
            .await
            .unwrap();
        let listed = client
            .r2_list(&base, "e2e-bucket", "metrics%_", None, 100)
            .await
            .unwrap();
        assert_eq!(
            listed
                .objects
                .iter()
                .map(|object| object.key.as_str())
                .collect::<Vec<_>>(),
            vec!["metrics%_exact.txt"]
        );
        let (fetched, bytes) = client
            .r2_get(&base, "e2e-bucket", "metrics%_exact.txt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.content_type, options.content_type);
        assert_eq!(bytes, b"hello R2");
        let streamed = client
            .r2_stream_object(
                &base,
                "e2e-bucket",
                "metrics%_exact.txt",
                &fetched.sha256,
                Duration::from_secs(5),
            )
            .await
            .unwrap()
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(streamed, b"hello R2");
        assert!(client
            .r2_stream_object(
                &base,
                "e2e-bucket",
                "metrics%_exact.txt",
                &"0".repeat(64),
                Duration::from_secs(5),
            )
            .await
            .is_err());
        let large_streamed = vec![0x6du8; 2 * 1024 * 1024 + 257];
        let upload_chunks = large_streamed
            .chunks(137_111)
            .map(|chunk| Ok(axum::body::Bytes::copy_from_slice(chunk)))
            .collect::<Vec<std::result::Result<_, std::io::Error>>>();
        let staged = node
            .objects
            .spool_stream(
                large_streamed.len() as u64,
                Box::pin(futures_util::stream::iter(upload_chunks)),
            )
            .await
            .unwrap();
        let large_metadata = client
            .r2_put_stream(
                &base,
                "e2e-bucket",
                "encrypted-stream.bin",
                &staged,
                &PutOptions::default(),
            )
            .await
            .unwrap();
        let large_chunks = client
            .r2_stream_object(
                &base,
                "e2e-bucket",
                "encrypted-stream.bin",
                &large_metadata.sha256,
                Duration::from_secs(5),
            )
            .await
            .unwrap()
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert_eq!(
            large_chunks
                .iter()
                .map(|chunk| chunk.len())
                .collect::<Vec<_>>(),
            vec![1024 * 1024, 1024 * 1024, 257]
        );
        assert_eq!(
            large_chunks.into_iter().flatten().collect::<Vec<_>>(),
            large_streamed
        );
        assert!(client
            .r2_delete(&base, "e2e-bucket", "encrypted-stream.bin")
            .await
            .unwrap());
        assert!(client
            .r2_delete(&base, "e2e-bucket", "metrics%_exact.txt")
            .await
            .unwrap());
        assert!(client
            .r2_get(&base, "e2e-bucket", "metrics%_exact.txt")
            .await
            .unwrap()
            .is_none());

        let upload =
            create_multipart_upload(&node, "e2e-bucket", "large/report.txt", options.clone())
                .await
                .unwrap();
        let first_bytes = vec![b'h'; MIN_MULTIPART_PART_BYTES as usize];
        let first = upload_part(
            &node,
            "e2e-bucket",
            "large/report.txt",
            &upload.upload_id,
            1,
            &first_bytes,
        )
        .await
        .unwrap();
        let second = upload_part(
            &node,
            "e2e-bucket",
            "large/report.txt",
            &upload.upload_id,
            2,
            b"multipart",
        )
        .await
        .unwrap();
        assert_eq!(first.etag, hex::encode(Md5::digest(&first_bytes)));
        assert_eq!(second.etag, hex::encode(Md5::digest(b"multipart")));
        let mut completed_etag = Md5::new();
        completed_etag.update(hex::decode(&first.etag).unwrap());
        completed_etag.update(hex::decode(&second.etag).unwrap());
        let expected_completed_etag = format!("{}-2", hex::encode(completed_etag.finalize()));
        let active = client
            .r2_multipart_list(&base, "e2e-bucket", "large/", None, 1)
            .await
            .unwrap();
        assert_eq!(active.uploads.len(), 1);
        assert_eq!(active.uploads[0].upload_id, upload.upload_id);
        assert_eq!(active.uploads[0].part_count, 2);
        assert_eq!(
            active.uploads[0].uploaded_bytes,
            MIN_MULTIPART_PART_BYTES + 9
        );
        let inspected = client
            .r2_multipart_detail(&base, "e2e-bucket", &upload.upload_id)
            .await
            .unwrap();
        assert_eq!(inspected.upload.key, "large/report.txt");
        assert_eq!(
            inspected
                .parts
                .iter()
                .map(|part| part.part_number)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        let completed = complete_multipart_upload(
            &node,
            "e2e-bucket",
            "large/report.txt",
            &upload.upload_id,
            &[
                PublishedPart {
                    part_number: 1,
                    etag: first.etag.clone(),
                },
                PublishedPart {
                    part_number: 2,
                    etag: second.etag.clone(),
                },
            ],
        )
        .await
        .unwrap();
        assert_eq!(completed.size, MIN_MULTIPART_PART_BYTES + 9);
        assert_eq!(completed.etag, expected_completed_etag);
        assert_eq!(
            std::fs::read_dir(node.objects.local_root().join(".multipart-assembly"))
                .unwrap()
                .count(),
            0
        );
        let completed_bytes = get_object(&node, "e2e-bucket", "large/report.txt")
            .await
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(completed_bytes.len(), first_bytes.len() + 9);
        assert_eq!(
            &completed_bytes[..first_bytes.len()],
            first_bytes.as_slice()
        );
        assert_eq!(&completed_bytes[first_bytes.len()..], b"multipart");
        let r2bind_port = crate::r2bind::serve(node.clone()).await.unwrap();
        let binding_response = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{r2bind_port}/"))
            .header(crate::r2bind::BUCKET_HEADER, "e2e-bucket")
            .header(
                "cf-r2-request",
                serde_json::json!({
                    "version": 1,
                    "method": "get",
                    "object": "large/report.txt",
                    "range": { "offset": first_bytes.len().to_string(), "length": "9" }
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(binding_response.status(), reqwest::StatusCode::OK);
        let metadata_size = binding_response
            .headers()
            .get("cf-r2-metadata-size")
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let binding_body = binding_response.bytes().await.unwrap();
        let binding_metadata: Value =
            serde_json::from_slice(&binding_body[..metadata_size]).unwrap();
        assert_eq!(
            binding_metadata["range"]["offset"],
            first_bytes.len() as u64
        );
        assert_eq!(binding_metadata["range"]["length"], 9);
        assert_eq!(&binding_body[metadata_size..], b"multipart");
        let binding_upload = vec![0x4bu8; 1024 * 1024 + 257];
        let binding_request = serde_json::json!({
            "version": 1,
            "method": "put",
            "object": "binding-stream.bin",
            "sha256": hex::encode(Sha256::digest(&binding_upload)),
        })
        .to_string();
        let mut binding_chunks = vec![Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(
            binding_request.as_bytes(),
        ))];
        binding_chunks.extend(
            binding_upload
                .chunks(71_111)
                .map(|chunk| Ok(axum::body::Bytes::copy_from_slice(chunk))),
        );
        let binding_put = reqwest::Client::new()
            .put(format!("http://127.0.0.1:{r2bind_port}/"))
            .header(crate::r2bind::BUCKET_HEADER, "e2e-bucket")
            .header("cf-r2-metadata-size", binding_request.len())
            .body(reqwest::Body::wrap_stream(futures_util::stream::iter(
                binding_chunks,
            )))
            .send()
            .await
            .unwrap();
        assert_eq!(binding_put.status(), reqwest::StatusCode::OK);
        assert_eq!(
            get_object(&node, "e2e-bucket", "binding-stream.bin")
                .await
                .unwrap()
                .unwrap()
                .1,
            binding_upload
        );
        assert!(complete_multipart_upload(
            &node,
            "e2e-bucket",
            "large/report.txt",
            &upload.upload_id,
            &[PublishedPart {
                part_number: 1,
                etag: "stale".into(),
            }],
        )
        .await
        .is_err());

        let aborted = create_multipart_upload(
            &node,
            "e2e-bucket",
            "large/aborted.bin",
            PutOptions::default(),
        )
        .await
        .unwrap();
        upload_part(
            &node,
            "e2e-bucket",
            "large/aborted.bin",
            &aborted.upload_id,
            1,
            b"temporary",
        )
        .await
        .unwrap();
        client
            .r2_multipart_abort(&base, "e2e-bucket", &aborted.upload_id)
            .await
            .unwrap();
        assert!(upload_part(
            &node,
            "e2e-bucket",
            "large/aborted.bin",
            &aborted.upload_id,
            1,
            b"late",
        )
        .await
        .is_err());

        for key in [
            "docs/a.txt",
            "docs/folder/b.txt",
            "docs/folder/c.txt",
            "docs/z.txt",
        ] {
            client
                .r2_put(&base, "e2e-bucket", key, key.as_bytes(), &options)
                .await
                .unwrap();
        }
        let folder_page = list_objects_delimited(&node, "e2e-bucket", "docs/", None, 10, "/")
            .await
            .unwrap();
        assert_eq!(
            folder_page
                .objects
                .iter()
                .map(|object| object.key.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/a.txt", "docs/z.txt"]
        );
        assert_eq!(folder_page.delimited_prefixes, vec!["docs/folder/"]);
        assert!(!folder_page.truncated);

        let current = resource::head(&node, BUCKET_KIND, "e2e-bucket").unwrap();
        let mut public_spec = bucket_spec(&current.resource).unwrap();
        public_spec.public_access = true;
        public_spec.cors_origins = vec!["https://app.example".into()];
        let public_record =
            prepare_bucket_after("e2e-bucket", public_spec, false, Some(&current)).unwrap();
        resource::ingest(&node, &Envelope::seal_any(&public_record, &operator)).unwrap();
        let (ingress_address, ingress_server) = crate::ingress::serve_managed(
            node.clone(),
            durable.clone(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let public_response = reqwest::Client::new()
            .get(format!("http://{ingress_address}/large/report.txt"))
            .header("host", "r2-e2e-bucket.workers.test")
            .header("origin", "https://app.example")
            .header("range", format!("bytes={}-", first_bytes.len()))
            .send()
            .await
            .unwrap();
        assert_eq!(
            public_response.status(),
            reqwest::StatusCode::PARTIAL_CONTENT
        );
        assert_eq!(
            public_response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://app.example"
        );
        assert_eq!(
            public_response.bytes().await.unwrap().as_ref(),
            b"multipart"
        );

        client
            .r2_put(&base, "e2e-bucket", "expired.txt", b"old", &options)
            .await
            .unwrap();
        exec(
            &node,
            "e2e-bucket",
            "UPDATE objects SET uploaded_at_ms = 0 WHERE key = ?1",
            json!(["expired.txt"]),
        )
        .await
        .unwrap();
        let current = resource::head(&node, BUCKET_KIND, "e2e-bucket").unwrap();
        let mut lifecycle_spec = bucket_spec(&current.resource).unwrap();
        lifecycle_spec.expire_objects_after_days = Some(1);
        let lifecycle_record =
            prepare_bucket_after("e2e-bucket", lifecycle_spec, false, Some(&current)).unwrap();
        resource::ingest(&node, &Envelope::seal_any(&lifecycle_record, &operator)).unwrap();
        let swept = sweep_lifecycle(&node).await.unwrap();
        assert_eq!(swept.expired_objects, 1);
        assert!(head_object(&node, "e2e-bucket", "expired.txt")
            .await
            .unwrap()
            .is_none());

        ingress_server.abort();
        server.abort();
        manager.abort();
        drop(client);
        drop(durable);
        drop(registry);
        drop(node);
        tokio::task::yield_now().await;
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn signed_storage_policy_pins_each_rclone_shard_without_migration() {
        let available = std::process::Command::new("rclone")
            .arg("version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !available {
            return;
        }

        let peer_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        drop(peer_listener);
        let gossip_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gossip_addr = gossip_listener.local_addr().unwrap();
        drop(gossip_listener);
        let root = std::env::temp_dir().join(format!(
            "rf-r2-shards-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let remote_a = root.join("remote-a");
        let remote_b = root.join("remote-b");
        std::fs::create_dir_all(&remote_a).unwrap();
        std::fs::create_dir_all(&remote_b).unwrap();
        let rclone_config = root.join("rclone.conf");
        std::fs::write(
            &rclone_config,
            format!(
                "[drive-a]\ntype = alias\nremote = {}\n[drive-b]\ntype = alias\nremote = {}\n",
                remote_a.display(),
                remote_b.display()
            ),
        )
        .unwrap();

        let operator = AnyKeypair::Ed(Keypair::from_seed([91; 32]));
        let config: NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {root:?}
            operator = "{}"
            cluster_secret = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            [gossip]
            listen = "{gossip_addr}"
            [peer_api]
            listen = "{peer_addr}"
            [ingress]
            default_domain = "workers.test"
            [storage]
            local_dir = {local:?}
            rclone_binary = "rclone"
            rclone_config = {rclone_config:?}
            rclone_timeout_seconds = 15
            "#,
            operator.signer_id(),
            local = root.join("local"),
        ))
        .unwrap();
        let node = Arc::new(Node::open(config, Keypair::from_seed([92; 32])).unwrap());

        let first_policy = crate::storage_policy::prepare_after(
            crate::storage_policy::StoragePolicy {
                schema: crate::storage_policy::STORAGE_POLICY_SCHEMA,
                new_bucket_backend: crate::storage_policy::NewBucketBackend::RcloneSharded,
                shard_remotes: vec!["drive-a".into()],
                shard_prefix: "rf-shards".into(),
                d1_backups: Vec::new(),
            },
            None,
        )
        .unwrap();
        resource::ingest(&node, &Envelope::seal_any(&first_policy, &operator)).unwrap();
        let bucket = prepare_bucket(
            &node,
            "sharded",
            BucketSpec {
                description: "签名分片策略测试".into(),
                public_access: false,
                storage: StorageLocation::Local,
                storage_policy: Some(crate::storage_policy::DEFAULT_POLICY_NAME.into()),
                max_bytes: None,
                max_objects: None,
                expire_objects_after_days: None,
                cors_origins: vec![],
                hostnames: vec![],
            },
            false,
        )
        .unwrap();
        resource::ingest(&node, &Envelope::seal_any(&bucket, &operator)).unwrap();

        let registry: crate::d1::Registry = Default::default();
        let leadership: crate::d1::Leadership = Default::default();
        let durable =
            crate::durable::Coordinator::new(node.clone(), registry.clone(), leadership.clone());
        let (address, server) =
            crate::peerapi::serve_managed(node.clone(), registry.clone(), durable.clone())
                .await
                .unwrap();
        let manager = crate::d1::spawn_manager(node.clone(), registry.clone(), leadership);
        let client = PeerClient::new(node.cfg.cluster_secret_bytes().unwrap());
        let base = address.to_string();

        let before = (0u32..)
            .map(|index| format!("written before expansion {index}"))
            .find(|candidate| {
                let sha: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
                crate::storage_policy::shard_index(&sha, 2) == Some(0)
            })
            .unwrap();
        let before_meta = put_object(
            &node,
            "sharded",
            "before.txt",
            before.as_bytes(),
            PutOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            before_meta.storage,
            StorageLocation::RcloneShard {
                remote: "drive-a".into(),
                prefix: "rf-shards".into(),
            }
        );
        assert!(remote_a
            .join("rf-shards")
            .join(&before_meta.sha256)
            .is_file());

        let policy_head = resource::head(
            &node,
            crate::storage_policy::STORAGE_POLICY_KIND,
            crate::storage_policy::DEFAULT_POLICY_NAME,
        )
        .unwrap();
        let expanded_policy = crate::storage_policy::prepare_after(
            crate::storage_policy::StoragePolicy {
                schema: crate::storage_policy::STORAGE_POLICY_SCHEMA,
                new_bucket_backend: crate::storage_policy::NewBucketBackend::RcloneSharded,
                shard_remotes: vec!["drive-a".into(), "drive-b".into()],
                shard_prefix: "rf-shards".into(),
                d1_backups: Vec::new(),
            },
            Some(&policy_head),
        )
        .unwrap();
        resource::ingest(&node, &Envelope::seal_any(&expanded_policy, &operator)).unwrap();

        let after = (0u32..)
            .map(|index| format!("written after expansion {index}"))
            .find(|candidate| {
                let sha: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
                crate::storage_policy::shard_index(&sha, 2) == Some(1)
            })
            .unwrap();
        let after_meta = put_object(
            &node,
            "sharded",
            "after.txt",
            after.as_bytes(),
            PutOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            after_meta.storage,
            StorageLocation::RcloneShard {
                remote: "drive-b".into(),
                prefix: "rf-shards".into(),
            }
        );
        assert!(remote_b
            .join("rf-shards")
            .join(&after_meta.sha256)
            .is_file());

        // The first object's metadata remains pinned to drive-a after policy
        // expansion; no background migration or rewritten lookup is needed.
        let (pinned_before, fetched_before) = get_object(&node, "sharded", "before.txt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pinned_before.storage, before_meta.storage);
        assert_eq!(fetched_before, before.as_bytes());
        let (_, fetched_after) = get_object(&node, "sharded", "after.txt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched_after, after.as_bytes());

        let multipart =
            create_multipart_upload(&node, "sharded", "multipart.bin", PutOptions::default())
                .await
                .unwrap();
        let mut first_part_bytes = vec![0u8; MIN_MULTIPART_PART_BYTES as usize];
        let mut found_drive_a = false;
        for marker in 0u8..=u8::MAX {
            first_part_bytes[0] = marker;
            let digest: [u8; 32] = Sha256::digest(&first_part_bytes).into();
            if crate::storage_policy::shard_index(&digest, 2) == Some(0) {
                found_drive_a = true;
                break;
            }
        }
        assert!(found_drive_a);
        let upload_chunks = first_part_bytes
            .chunks(211_111)
            .map(|chunk| Ok(axum::body::Bytes::copy_from_slice(chunk)))
            .collect::<Vec<std::result::Result<_, std::io::Error>>>();
        let staged_part = node
            .objects
            .spool_stream(
                first_part_bytes.len() as u64,
                Box::pin(futures_util::stream::iter(upload_chunks)),
            )
            .await
            .unwrap();
        let first_part = client
            .r2_upload_part_stream(
                &base,
                "sharded",
                "multipart.bin",
                &multipart.upload_id,
                1,
                &staged_part,
            )
            .await
            .unwrap();
        let second_part = client
            .r2_upload_part(
                &base,
                "sharded",
                "multipart.bin",
                &multipart.upload_id,
                2,
                after.as_bytes(),
            )
            .await
            .unwrap();
        let part_locations = exec(
            &node,
            "sharded",
            "SELECT storage_json FROM multipart_parts WHERE upload_id = ?1 ORDER BY part_number",
            json!([multipart.upload_id.clone()]),
        )
        .await
        .unwrap();
        let locations = part_locations["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                serde_json::from_str::<StorageLocation>(row["storage_json"].as_str().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            locations,
            vec![before_meta.storage.clone(), after_meta.storage.clone()]
        );
        let completed = client
            .r2_complete_multipart(
                &base,
                "sharded",
                "multipart.bin",
                &multipart.upload_id,
                &[
                    PublishedPart {
                        part_number: 1,
                        etag: first_part.etag,
                    },
                    PublishedPart {
                        part_number: 2,
                        etag: second_part.etag,
                    },
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            completed.size,
            (first_part_bytes.len() + after.len()) as u64
        );
        let (_, multipart_bytes) = get_object(&node, "sharded", "multipart.bin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            &multipart_bytes[..first_part_bytes.len()],
            first_part_bytes.as_slice()
        );
        assert_eq!(&multipart_bytes[first_part_bytes.len()..], after.as_bytes());

        let distribution = storage_distribution(&node).await.unwrap();
        assert_eq!(distribution.iter().map(|item| item.objects).sum::<u64>(), 3);
        assert!(distribution
            .iter()
            .any(|item| item.storage == before_meta.storage));
        assert!(distribution
            .iter()
            .any(|item| item.storage == after_meta.storage));

        let current_policy = resource::head(
            &node,
            crate::storage_policy::STORAGE_POLICY_KIND,
            crate::storage_policy::DEFAULT_POLICY_NAME,
        )
        .unwrap();
        let destructive_removal = crate::storage_policy::prepare_after(
            crate::storage_policy::StoragePolicy {
                schema: crate::storage_policy::STORAGE_POLICY_SCHEMA,
                new_bucket_backend: crate::storage_policy::NewBucketBackend::RcloneSharded,
                shard_remotes: vec!["drive-b".into()],
                shard_prefix: "rf-shards".into(),
                d1_backups: Vec::new(),
            },
            Some(&current_policy),
        )
        .unwrap();
        let error = crate::storage_policy::validate_transition(&node, &destructive_removal)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("drive-a"));

        server.abort();
        manager.abort();
        drop(durable);
        drop(registry);
        drop(node);
        tokio::task::yield_now().await;
        let _ = std::fs::remove_dir_all(root);
    }
}
