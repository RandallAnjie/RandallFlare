//! Privacy-preserving KV and D1 mutation proofs.
//!
//! Entries deliberately contain no KV keys, values, SQL text or parameters.
//! Deterministic ids let live nodes merge replicated observations without a
//! central audit database.

use rf_core::kv::KvEntry;
use rf_core::quorum::Entry;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write as _;

pub const DATA_AUDIT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_DATA_AUDIT_PAGE: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataMutationAudit {
    pub id: String,
    pub kind: String,
    pub resource: String,
    pub subject_sha256: String,
    pub content_sha256: String,
    pub bytes: u64,
    pub sequence: Option<u64>,
    pub occurred_at_ms: u64,
    pub observed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAuditSnapshot {
    pub node: String,
    pub label: String,
    pub entries: Vec<DataMutationAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAuditArchive {
    pub bucket: String,
    pub object_key: String,
    pub entries: usize,
    pub compressed_bytes: u64,
    pub sha256: String,
    pub first_occurred_at_ms: u64,
    pub last_occurred_at_ms: u64,
}

pub fn kv_mutation(namespace: &str, key: &str, entry: &KvEntry) -> Option<DataMutationAudit> {
    if namespace.starts_with("__rf") {
        return None;
    }
    let kind = if entry.value.is_some() {
        "kv_put"
    } else {
        "kv_delete"
    };
    let subject_sha256 = hex::encode(Sha256::digest(key.as_bytes()));
    let mut content = Sha256::new();
    match &entry.value {
        Some(value) => {
            content.update([1]);
            content.update((value.len() as u64).to_be_bytes());
            content.update(value);
        }
        None => content.update([0]),
    }
    match entry.expires_at_ms {
        Some(expires_at_ms) => {
            content.update([1]);
            content.update(expires_at_ms.to_be_bytes());
        }
        None => content.update([0]),
    }
    let content_sha256 = hex::encode(content.finalize());
    let mut identity = Sha256::new();
    identity.update(b"rf-data-audit/kv/v1\0");
    identity.update((namespace.len() as u64).to_be_bytes());
    identity.update(namespace.as_bytes());
    identity.update((key.len() as u64).to_be_bytes());
    identity.update(key.as_bytes());
    identity.update(entry.hlc.wall_ms.to_be_bytes());
    identity.update(entry.hlc.logical.to_be_bytes());
    identity.update(entry.writer.0);
    identity.update(content_sha256.as_bytes());
    Some(DataMutationAudit {
        id: hex::encode(identity.finalize()),
        kind: kind.into(),
        resource: namespace.into(),
        subject_sha256,
        content_sha256,
        bytes: entry.value.as_ref().map_or(0, |value| value.len() as u64),
        sequence: None,
        occurred_at_ms: entry.hlc.wall_ms,
        observed_by: entry.writer.to_string(),
    })
}

pub fn d1_mutation(
    database: &str,
    entry: &Entry,
    observed_by: String,
    occurred_at_ms: u64,
) -> DataMutationAudit {
    let content_sha256 = hex::encode(Sha256::digest(&entry.cmd));
    let subject_sha256 = hex::encode(Sha256::digest(entry.seq.to_be_bytes()));
    let mut identity = Sha256::new();
    identity.update(b"rf-data-audit/d1/v1\0");
    identity.update((database.len() as u64).to_be_bytes());
    identity.update(database.as_bytes());
    identity.update(entry.epoch.to_be_bytes());
    identity.update(entry.seq.to_be_bytes());
    identity.update(content_sha256.as_bytes());
    DataMutationAudit {
        id: hex::encode(identity.finalize()),
        kind: "d1_commit".into(),
        resource: database.into(),
        subject_sha256,
        content_sha256,
        bytes: entry.cmd.len() as u64,
        sequence: Some(entry.seq),
        occurred_at_ms,
        observed_by,
    }
}

pub fn merge(
    snapshots: impl IntoIterator<Item = Vec<DataMutationAudit>>,
    before_ms: Option<u64>,
    limit: usize,
) -> Vec<DataMutationAudit> {
    let mut unique = BTreeMap::new();
    for entry in snapshots.into_iter().flatten() {
        if before_ms.is_some_and(|before| entry.occurred_at_ms >= before) {
            continue;
        }
        unique
            .entry(entry.id.clone())
            .and_modify(|current: &mut DataMutationAudit| {
                if (entry.occurred_at_ms, &entry.observed_by)
                    < (current.occurred_at_ms, &current.observed_by)
                {
                    *current = entry.clone();
                }
            })
            .or_insert(entry);
    }
    let mut entries = unique.into_values().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .occurred_at_ms
            .cmp(&left.occurred_at_ms)
            .then_with(|| right.id.cmp(&left.id))
    });
    entries.truncate(limit.clamp(1, MAX_DATA_AUDIT_PAGE));
    entries
}

pub async fn cluster_entries(
    node: &crate::node::Node,
    before_ms: Option<u64>,
    limit: usize,
) -> anyhow::Result<Vec<DataMutationAudit>> {
    use futures_util::{stream, StreamExt as _};

    let limit = limit.clamp(1, MAX_DATA_AUDIT_PAGE);
    let mut snapshots = vec![node.store.load_data_audit(before_ms, limit)?];
    let client = crate::peers::PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let peers = node
        .peers()
        .into_values()
        .filter_map(|peer| peer.api_addr.map(|address| address.to_string()))
        .collect::<Vec<_>>();
    let remote = stream::iter(peers.into_iter().map(|address| {
        let client = client.clone();
        async move { client.data_audit(&address, before_ms, limit).await }
    }))
    .buffer_unordered(8)
    .collect::<Vec<_>>()
    .await;
    for snapshot in remote.into_iter().flatten() {
        snapshots.push(snapshot.entries);
    }
    Ok(merge(snapshots, before_ms, limit))
}

pub async fn archive(
    node: &crate::node::Node,
    bucket: &str,
    prefix: &str,
    before_ms: Option<u64>,
) -> anyhow::Result<DataAuditArchive> {
    use anyhow::{bail, Context as _};

    if !rf_core::manifest::valid_name(bucket) {
        bail!("数据审计归档 bucket 名称无效");
    }
    crate::objectstore::validate_prefix(prefix)?;
    crate::r2::bucket_record(node, bucket).context("数据审计归档 R2 bucket 不存在")?;
    let entries = cluster_entries(node, before_ms, MAX_DATA_AUDIT_PAGE).await?;
    if entries.is_empty() {
        bail!("当前时间范围没有可归档的 KV/D1 数据审计");
    }
    let first = entries
        .iter()
        .map(|entry| entry.occurred_at_ms)
        .min()
        .unwrap_or_default();
    let last = entries
        .iter()
        .map(|entry| entry.occurred_at_ms)
        .max()
        .unwrap_or_default();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    for entry in entries.iter().rev() {
        serde_json::to_writer(&mut encoder, entry)?;
        encoder.write_all(b"\n")?;
    }
    let body = encoder.finish()?;
    if body.len() > crate::r2::MAX_BUFFERED_OBJECT_BYTES {
        bail!("单次数据审计归档压缩后超过 63 MiB，请使用更小的时间窗口");
    }
    let created_at_ms = crate::node::now_ms();
    let timestamp =
        time::OffsetDateTime::from_unix_timestamp_nanos(created_at_ms as i128 * 1_000_000)?;
    let root = prefix.trim_matches('/');
    let key = format!(
        "{}{}year={:04}/month={:02}/day={:02}/audit-{}-{}.jsonl.gz",
        root,
        if root.is_empty() { "" } else { "/" },
        timestamp.year(),
        timestamp.month() as u8,
        timestamp.day(),
        &node.id_hex()[..12],
        created_at_ms,
    );
    let custom_metadata = Map::from_iter([
        ("rf-audit-format".into(), Value::String("jsonl-v1".into())),
        ("rf-audit-entries".into(), json!(entries.len())),
        ("rf-audit-first-ms".into(), json!(first)),
        ("rf-audit-last-ms".into(), json!(last)),
    ]);
    let mut http_metadata = Map::new();
    http_metadata.insert("contentEncoding".into(), Value::String("gzip".into()));
    let object = crate::r2::put_object(
        node,
        bucket,
        &key,
        &body,
        crate::r2::PutOptions {
            content_type: Some("application/x-ndjson".into()),
            custom_metadata,
            http_metadata,
        },
    )
    .await?;
    Ok(DataAuditArchive {
        bucket: bucket.into(),
        object_key: key,
        entries: entries.len(),
        compressed_bytes: object.size,
        sha256: object.sha256,
        first_occurred_at_ms: first,
        last_occurred_at_ms: last,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_core::hlc::Hlc;
    use rf_core::identity::PublicId;

    #[test]
    fn kv_proofs_are_deterministic_and_hide_key_and_value() {
        let entry = KvEntry {
            hlc: Hlc {
                wall_ms: 123,
                logical: 4,
            },
            writer: PublicId([7; 32]),
            value: Some(b"private-value".to_vec()),
            expires_at_ms: Some(456),
        };
        let audit = kv_mutation("customer-kv", "private-key", &entry).unwrap();
        assert_eq!(
            audit,
            kv_mutation("customer-kv", "private-key", &entry).unwrap()
        );
        let encoded = serde_json::to_string(&audit).unwrap();
        assert!(!encoded.contains("private-key"));
        assert!(!encoded.contains("private-value"));
        assert!(kv_mutation("__rf", "internal", &entry).is_none());
    }
}
