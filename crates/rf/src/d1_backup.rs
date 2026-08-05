//! Portable D1 snapshots archived into signed R2 buckets.
//!
//! Backup schedules live in the operator-signed global storage policy. A
//! rendezvous-elected live node asks the current D1 leader for an online
//! SQLite backup, verifies its digest, and publishes it through the ordinary
//! R2 path. Consequently local, fixed-rclone and sharded-rclone buckets all
//! use the same implementation.

use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use crate::r2::{self, PutOptions};
use crate::storage_policy::D1BackupPolicy;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D1Backup {
    pub database: String,
    pub bucket: String,
    pub object_key: String,
    pub size: u64,
    pub sha256: String,
    pub created_at_ms: u64,
    pub scheduled_at_ms: Option<u64>,
}

pub async fn backup_now(
    node: &Node,
    database: &str,
    bucket: &str,
    prefix: &str,
) -> Result<D1Backup> {
    validate_target(node, database, bucket, prefix)?;
    let created_at_ms = now_ms();
    let key = backup_key(prefix, database, created_at_ms, false)?;
    backup_to_key(node, database, bucket, &key, created_at_ms, None).await
}

async fn backup_scheduled(
    node: &Node,
    policy: &D1BackupPolicy,
    scheduled_at_ms: u64,
) -> Result<Option<D1Backup>> {
    validate_target(node, &policy.database, &policy.bucket, &policy.prefix)?;
    let key = backup_key(&policy.prefix, &policy.database, scheduled_at_ms, true)?;
    if r2::head_object(node, &policy.bucket, &key).await?.is_some() {
        return Ok(None);
    }
    let backup = backup_to_key(
        node,
        &policy.database,
        &policy.bucket,
        &key,
        now_ms(),
        Some(scheduled_at_ms),
    )
    .await?;
    sweep_retention(node, policy).await?;
    Ok(Some(backup))
}

fn validate_target(node: &Node, database: &str, bucket: &str, prefix: &str) -> Result<()> {
    if !rf_core::manifest::valid_name(database) || !rf_core::manifest::valid_name(bucket) {
        bail!("D1 备份数据库或 R2 bucket 名称无效");
    }
    crate::objectstore::validate_prefix(prefix)?;
    if !crate::d1::database_names(node)
        .iter()
        .any(|name| name == database)
    {
        bail!("D1 数据库不存在：{database}");
    }
    r2::bucket_record(node, bucket).context("D1 备份目标 R2 bucket 不存在")?;
    Ok(())
}

async fn backup_to_key(
    node: &Node,
    database: &str,
    bucket: &str,
    key: &str,
    created_at_ms: u64,
    scheduled_at_ms: Option<u64>,
) -> Result<D1Backup> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let bytes = client
        .d1_export(&loopback_peer_api(node), database)
        .await
        .context("从 D1 leader 创建在线备份失败")?;
    if bytes.is_empty() {
        bail!("D1 leader 返回了空备份");
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let custom_metadata = Map::from_iter([
        ("rf-d1-database".into(), Value::String(database.into())),
        ("rf-d1-backup-sha256".into(), Value::String(sha256.clone())),
        ("rf-d1-backup-created-ms".into(), json!(created_at_ms)),
        (
            "rf-d1-backup-scheduled-ms".into(),
            scheduled_at_ms.map(Value::from).unwrap_or(Value::Null),
        ),
    ]);
    upload(
        node,
        bucket,
        key,
        &bytes,
        PutOptions {
            content_type: Some("application/vnd.sqlite3".into()),
            custom_metadata,
            ..Default::default()
        },
    )
    .await?;
    Ok(D1Backup {
        database: database.into(),
        bucket: bucket.into(),
        object_key: key.into(),
        size: bytes.len() as u64,
        sha256,
        created_at_ms,
        scheduled_at_ms,
    })
}

async fn upload(
    node: &Node,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    options: PutOptions,
) -> Result<()> {
    if bytes.len() <= r2::MAX_BUFFERED_OBJECT_BYTES {
        r2::put_object(node, bucket, key, bytes, options).await?;
        return Ok(());
    }
    let multipart = r2::create_multipart_upload(node, bucket, key, options).await?;
    let mut parts = Vec::new();
    for (index, chunk) in bytes
        .chunks(r2::MAX_BUFFERED_MULTIPART_PART_BYTES)
        .enumerate()
    {
        match r2::upload_part(
            node,
            bucket,
            key,
            &multipart.upload_id,
            index as u32 + 1,
            chunk,
        )
        .await
        {
            Ok(part) => parts.push(r2::PublishedPart {
                part_number: part.part_number,
                etag: part.etag,
            }),
            Err(error) => {
                let _ = r2::abort_multipart_upload(node, bucket, key, &multipart.upload_id).await;
                return Err(error);
            }
        }
    }
    r2::complete_multipart_upload(node, bucket, key, &multipart.upload_id, &parts).await?;
    Ok(())
}

async fn sweep_retention(node: &Node, policy: &D1BackupPolicy) -> Result<u64> {
    let cutoff = now_ms().saturating_sub(u64::from(policy.retention_days) * 86_400_000);
    let prefix = database_prefix(&policy.prefix, &policy.database);
    let mut cursor = None;
    let mut expired = Vec::new();
    loop {
        let page =
            r2::list_objects(node, &policy.bucket, &prefix, cursor.as_deref(), 1_000).await?;
        for object in page.objects {
            let created = object
                .custom_metadata
                .get("rf-d1-backup-created-ms")
                .and_then(Value::as_u64)
                .unwrap_or(object.uploaded_at_ms);
            if created < cutoff {
                expired.push(object.key);
            }
        }
        if !page.truncated || expired.len() >= 10_000 {
            break;
        }
        cursor = page.cursor;
    }
    for key in &expired {
        r2::delete_object(node, &policy.bucket, key).await?;
    }
    Ok(expired.len() as u64)
}

fn database_prefix(prefix: &str, database: &str) -> String {
    if prefix.is_empty() {
        format!("{database}/")
    } else {
        format!("{}/{database}/", prefix.trim_matches('/'))
    }
}

fn backup_key(prefix: &str, database: &str, timestamp_ms: u64, scheduled: bool) -> Result<String> {
    let timestamp =
        time::OffsetDateTime::from_unix_timestamp_nanos(timestamp_ms as i128 * 1_000_000)
            .context("D1 备份时间戳超出支持范围")?;
    let suffix = if scheduled { "scheduled" } else { "manual" };
    Ok(format!(
        "{}year={:04}/month={:02}/day={:02}/{}-{timestamp_ms}.sqlite",
        database_prefix(prefix, database),
        timestamp.year(),
        timestamp.month() as u8,
        timestamp.day(),
        suffix,
    ))
}

fn loopback_peer_api(node: &Node) -> String {
    let listen = node.cfg.peer_api.listen;
    if listen.is_ipv6() {
        format!("[::1]:{}", listen.port())
    } else {
        format!("127.0.0.1:{}", listen.port())
    }
}

fn elected(node: &Node, database: &str, slot: u64) -> bool {
    let mut universe = vec![node.id()];
    universe.extend(
        node.peers()
            .into_iter()
            .filter(|(_, peer)| peer.api_addr.is_some())
            .filter_map(|(id, _)| id.parse::<rf_core::identity::PublicId>().ok()),
    );
    universe.sort();
    universe.dedup();
    rf_core::quorum::rendezvous_group(&format!("d1-backup/{database}/{slot}"), &universe, 1).first()
        == Some(&node.id())
}

pub fn spawn_driver(node: Arc<Node>) {
    tokio::spawn(async move {
        loop {
            let now = now_ms();
            match crate::storage_policy::current(&node) {
                Ok((_, storage)) => {
                    for policy in storage.d1_backups.iter().filter(|policy| !policy.suspended) {
                        let interval_ms = u64::from(policy.interval_hours) * 60 * 60 * 1_000;
                        let slot = now / interval_ms;
                        if !elected(&node, &policy.database, slot) {
                            continue;
                        }
                        let scheduled_at_ms = slot * interval_ms;
                        match backup_scheduled(&node, policy, scheduled_at_ms).await {
                            Ok(Some(backup)) => tracing::info!(
                                database = %backup.database,
                                bucket = %backup.bucket,
                                key = %backup.object_key,
                                "D1 自动备份已写入 R2"
                            ),
                            Ok(None) => {}
                            Err(error) => tracing::warn!(
                                database = %policy.database,
                                "D1 自动备份失败：{error:#}"
                            ),
                        }
                    }
                }
                Err(error) => tracing::warn!("读取 D1 自动备份策略失败：{error:#}"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_keys_are_stable_partitioned_and_safe() {
        let key = backup_key("backups", "appdb", 1_725_148_800_000, true).unwrap();
        assert_eq!(
            key,
            "backups/appdb/year=2024/month=09/day=01/scheduled-1725148800000.sqlite"
        );
        assert_eq!(database_prefix("", "appdb"), "appdb/");
    }
}
