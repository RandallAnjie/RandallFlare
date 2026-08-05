//! R2-compatible object metadata and bytes.
//!
//! Bucket definitions are operator-signed platform resources. Object metadata
//! is strongly consistent in a per-bucket D1 micro-quorum; immutable bytes are
//! content-addressed in local storage or a node-local rclone remote. A crash
//! between byte upload and metadata commit can only leave an unreferenced blob,
//! which the storage reconciler may safely collect later.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::objectstore::StorageLocation;
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const BUCKET_KIND: &str = "r2_bucket";
pub const MAX_OBJECT_KEY_BYTES: usize = 1024;
pub const MAX_LIST_LIMIT: usize = 1000;
pub const MAX_DIRECT_OBJECT_BYTES: usize = 63 * 1024 * 1024;
pub const MAX_MULTIPART_PART_BYTES: usize = 63 * 1024 * 1024;
pub const MAX_MULTIPART_OBJECT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_MULTIPART_PARTS: usize = 10_000;
const MULTIPART_TTL_MS: u64 = 24 * 60 * 60 * 1000;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub key: String,
    pub expires_at_ms: u64,
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

pub fn metadata_database(bucket: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("r2/{bucket}").as_bytes()));
    format!("r2-{}", &digest[..32])
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
    if bytes.len() > MAX_DIRECT_OBJECT_BYTES {
        bail!("R2 单次直传对象不得超过 63 MiB；更大的对象请使用分片上传");
    }
    commit_object(node, bucket, key, bytes, options).await
}

async fn commit_object(
    node: &Node,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    options: PutOptions,
) -> Result<ObjectMeta> {
    let (_, spec) = bucket_record(node, bucket).context("R2 bucket 不存在")?;
    if !node.objects.supports(&spec.storage) {
        bail!("当前节点不具备此 bucket 所需的存储后端");
    }
    let group = ensure_schema(node, bucket).await?;
    let _quota_guard = node.r2_quota_gate.lock().await;
    let previous = head_object(node, bucket, key).await?;
    crate::quota::validate_r2_write(node, bucket, previous.as_ref(), bytes.len() as u64).await?;
    // Failed quota admission must not consume unindexed local/rclone storage.
    let sha = node.objects.put(&spec.storage, bytes).await?;
    let sha256 = hex::encode(sha);
    let etag = sha256.clone();
    let uploaded_at_ms = now_ms();
    if spec.storage == StorageLocation::Local {
        replicate_local_blob(node, &group, &sha, bytes).await?;
    }

    let max_bytes = spec.max_bytes.unwrap_or(0);
    let max_objects = spec.max_objects.unwrap_or(0);
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
            bytes.len(),
            etag,
            options.content_type,
            serde_json::to_string(&options.custom_metadata)?,
            serde_json::to_string(&options.http_metadata)?,
            serde_json::to_string(&spec.storage)?,
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
        size: bytes.len() as u64,
        etag,
        content_type: options.content_type,
        custom_metadata: options.custom_metadata,
        http_metadata: options.http_metadata,
        storage: spec.storage,
        uploaded_at_ms,
    })
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
    if !node.objects.supports(&spec.storage) {
        bail!("当前节点不具备此 bucket 所需的存储后端");
    }
    ensure_schema(node, bucket).await?;
    let upload_id = hex::encode(rand::random::<[u8; 20]>());
    let expires_at_ms = now_ms().saturating_add(MULTIPART_TTL_MS);
    exec(
        node,
        bucket,
        "INSERT INTO multipart_uploads (upload_id, key, content_type, custom_metadata, http_metadata, storage_json, created_at_ms, expires_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        json!([
            upload_id,
            key,
            options.content_type,
            serde_json::to_string(&options.custom_metadata)?,
            serde_json::to_string(&options.http_metadata)?,
            serde_json::to_string(&spec.storage)?,
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
    if bytes.len() > MAX_MULTIPART_PART_BYTES {
        bail!("R2 单个分片不得超过 63 MiB");
    }
    ensure_schema(node, bucket).await?;
    let upload = multipart_row(node, bucket, key, upload_id).await?;
    if upload.expires_at_ms <= now_ms() {
        bail!("R2 分片上传已过期");
    }
    let sha = node.objects.put(&upload.storage, bytes).await?;
    let etag = hex::encode(sha);
    let result = exec(
        node,
        bucket,
        "INSERT INTO multipart_parts (upload_id, part_number, sha256, size, etag, uploaded_at_ms) SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE EXISTS (SELECT 1 FROM multipart_uploads WHERE upload_id = ?1 AND key = ?7 AND expires_at_ms > ?6) ON CONFLICT(upload_id, part_number) DO UPDATE SET sha256=excluded.sha256, size=excluded.size, etag=excluded.etag, uploaded_at_ms=excluded.uploaded_at_ms",
        json!([upload_id, part_number, etag, bytes.len(), etag, now_ms(), key]),
    )
    .await?;
    if result["rows_affected"].as_u64() != Some(1) {
        bail!("R2 分片上传不存在、已中止或已过期");
    }
    Ok(UploadedPart {
        part_number,
        etag,
        size: bytes.len() as u64,
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
    let mut assembled = Vec::new();
    let mut consumed_parts = Vec::new();
    for published in parts {
        let result = exec(
            node,
            bucket,
            "SELECT sha256, size, etag FROM multipart_parts WHERE upload_id = ?1 AND part_number = ?2",
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
        if assembled.len().saturating_add(declared_size as usize) > MAX_MULTIPART_OBJECT_BYTES {
            bail!("R2 分片合并后的对象不得超过 512 MiB");
        }
        let bytes = node.objects.get(&upload.storage, &sha).await?;
        if bytes.len() as u64 != declared_size {
            bail!("R2 分片 {} 的大小校验失败", published.part_number);
        }
        assembled.extend_from_slice(&bytes);
        consumed_parts.push((hex::encode(sha), declared_size));
    }
    let metadata = commit_object(node, bucket, key, &assembled, upload.options).await?;
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
    for (sha256, size) in consumed_parts {
        schedule_orphan_parts(node, bucket, &sha256, size, &upload.storage).await?;
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
    let upload = multipart_row(node, bucket, key, upload_id).await?;
    let part_rows = exec(
        node,
        bucket,
        "SELECT sha256, size FROM multipart_parts WHERE upload_id = ?1",
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
        if let (Some(sha256), Some(size)) = (
            row.get("sha256").and_then(Value::as_str),
            row.get("size").and_then(Value::as_u64),
        ) {
            schedule_orphan_parts(node, bucket, sha256, size, &upload.storage).await?;
        }
    }
    Ok(())
}

struct MultipartRow {
    storage: StorageLocation,
    options: PutOptions,
    expires_at_ms: u64,
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
        "SELECT content_type, custom_metadata, http_metadata, storage_json, expires_at_ms FROM multipart_uploads WHERE upload_id = ?1 AND key = ?2",
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
    let Some(meta) = head_object(node, bucket, key).await? else {
        return Ok(None);
    };
    let sha: [u8; 32] = hex::decode(&meta.sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("R2 对象摘要长度无效"))?;
    let bytes = match node.objects.get(&meta.storage, &sha).await {
        Ok(bytes) => bytes,
        Err(local_error) if meta.storage == StorageLocation::Local => {
            repair_local_blob(node, bucket, &sha)
                .await
                .with_context(|| {
                    format!("本地 R2 对象缺失，且集群修复失败；原始错误：{local_error:#}")
                })?
        }
        Err(error) => return Err(error),
    };
    Ok(Some((meta, bytes)))
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
            "SELECT 1 AS present FROM objects WHERE sha256 = ?1 AND storage_json = ?2 UNION ALL SELECT 1 AS present FROM multipart_parts AS p JOIN multipart_uploads AS u ON u.upload_id = p.upload_id WHERE p.sha256 = ?1 AND u.storage_json = ?2 LIMIT 1",
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
    validate_metadata(options)?;
    if bytes.len() > MAX_DIRECT_OBJECT_BYTES {
        bail!("R2 单次直传对象不得超过 63 MiB；更大的对象请使用分片上传");
    }
    let encoded = serde_json::to_vec(options)?;
    if encoded.len() > MAX_PUT_OPTIONS_BYTES {
        bail!("R2 上传选项不得超过 32 KiB");
    }
    let mut payload = Vec::with_capacity(4 + encoded.len() + bytes.len());
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    payload.extend_from_slice(bytes);
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
    if bytes.len() > MAX_DIRECT_OBJECT_BYTES {
        bail!("R2 单次直传对象不得超过 63 MiB；更大的对象请使用分片上传");
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
             uploaded_at_ms INTEGER NOT NULL,
             PRIMARY KEY(upload_id, part_number)
           )"#,
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

async fn repair_local_blob(node: &Node, bucket: &str, sha: &[u8; 32]) -> Result<Vec<u8>> {
    let group = d1::ensure_database(node, &metadata_database(bucket))?;
    let peers = node.peers();
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    for member in group {
        if member == node.id() {
            continue;
        }
        let Some(api) = peers
            .get(&member.to_string())
            .and_then(|peer| peer.api_addr)
            .map(|address| address.to_string())
        else {
            continue;
        };
        match client.r2_fetch_blob(&api, sha).await {
            Ok(Some(bytes)) if Sha256::digest(&bytes).as_slice() == sha => {
                let stored = node.objects.put(&StorageLocation::Local, &bytes).await?;
                if &stored != sha {
                    bail!("修复后的 R2 对象摘要不一致");
                }
                return Ok(bytes);
            }
            Ok(Some(_)) => tracing::warn!("R2 repair peer {member} sent corrupt bytes"),
            Ok(None) => {}
            Err(error) => tracing::debug!("R2 repair from {member} failed: {error:#}"),
        }
    }
    bail!("数据组中没有可用的 R2 对象副本")
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
            max_bytes: Some(1024),
            max_objects: Some(10),
            expire_objects_after_days: Some(30),
            cors_origins: vec!["https://console.example".into()],
            hostnames: vec!["objects.example.com".into()],
        };
        spec.validate().unwrap();
        let encoded = serde_json::to_string(&spec).unwrap();
        assert!(!encoded.to_ascii_lowercase().contains("secret"));
        assert_eq!(metadata_database("events").len(), 35);
    }

    #[test]
    fn object_keys_and_metadata_are_bounded() {
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
                max_bytes: Some(1024 * 1024),
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
        let first = upload_part(
            &node,
            "e2e-bucket",
            "large/report.txt",
            &upload.upload_id,
            1,
            b"hello ",
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
        let completed = complete_multipart_upload(
            &node,
            "e2e-bucket",
            "large/report.txt",
            &upload.upload_id,
            &[
                PublishedPart {
                    part_number: 1,
                    etag: first.etag,
                },
                PublishedPart {
                    part_number: 2,
                    etag: second.etag,
                },
            ],
        )
        .await
        .unwrap();
        assert_eq!(completed.size, 15);
        assert_eq!(
            get_object(&node, "e2e-bucket", "large/report.txt")
                .await
                .unwrap()
                .unwrap()
                .1,
            b"hello multipart"
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
        abort_multipart_upload(&node, "e2e-bucket", "large/aborted.bin", &aborted.upload_id)
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
        let ingress_address = crate::ingress::serve(
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
            .header("range", "bytes=6-")
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

        server.abort();
        manager.abort();
        drop(client);
        drop(durable);
        drop(registry);
        drop(node);
        tokio::task::yield_now().await;
        let _ = std::fs::remove_dir_all(root);
    }
}
