//! Node-owned Worker request logs and cluster-facing snapshots.
//!
//! Ingress records only routing metadata: no bodies, query strings, headers,
//! cookies, IP addresses or user agents. Each node batches its own rows into
//! the local redb store; readers aggregate encrypted snapshots from live peers.

use crate::node::{now_ms, Node};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

pub const REQUEST_LOG_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const HOUR_MS: u64 = 60 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub id: String,
    pub worker: String,
    pub version: u64,
    pub node: String,
    pub hostname: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub duration_ms: u64,
    pub called_at_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestHour {
    pub start_ms: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub other: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogSnapshot {
    pub node: String,
    pub label: String,
    pub entries: Vec<RequestLogEntry>,
    pub hostnames: Vec<String>,
    pub hours: Vec<RequestHour>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLogSnapshot {
    pub node: String,
    pub label: String,
    pub lines: Vec<crate::node::RuntimeLogLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedRequestLogs {
    pub entries: Vec<RequestLogEntry>,
    pub hostnames: Vec<String>,
    pub hours: Vec<RequestHour>,
}

pub fn merge_snapshots<'a>(
    snapshots: impl IntoIterator<Item = &'a RequestLogSnapshot>,
    limit: usize,
) -> MergedRequestLogs {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut hostnames = BTreeSet::new();
    let mut hours: BTreeMap<u64, RequestHour> = BTreeMap::new();
    for snapshot in snapshots {
        hostnames.extend(snapshot.hostnames.iter().cloned());
        for entry in &snapshot.entries {
            if seen.insert(entry.id.clone()) {
                entries.push(entry.clone());
            }
        }
        for hour in &snapshot.hours {
            let aggregate = hours.entry(hour.start_ms).or_insert_with(|| RequestHour {
                start_ms: hour.start_ms,
                ..Default::default()
            });
            aggregate.status_2xx = aggregate.status_2xx.saturating_add(hour.status_2xx);
            aggregate.status_3xx = aggregate.status_3xx.saturating_add(hour.status_3xx);
            aggregate.status_4xx = aggregate.status_4xx.saturating_add(hour.status_4xx);
            aggregate.status_5xx = aggregate.status_5xx.saturating_add(hour.status_5xx);
            aggregate.other = aggregate.other.saturating_add(hour.other);
        }
    }
    entries.sort_by(|left, right| {
        right
            .called_at_ms
            .cmp(&left.called_at_ms)
            .then_with(|| right.id.cmp(&left.id))
    });
    entries.truncate(limit.clamp(1, 1_000));
    MergedRequestLogs {
        entries,
        hostnames: hostnames.into_iter().collect(),
        hours: hours.into_values().collect(),
    }
}

pub struct RequestObservation<'a> {
    pub worker: &'a str,
    pub version: u64,
    pub hostname: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status_code: u16,
    pub duration_ms: u64,
}

pub fn record(node: &Node, observation: &RequestObservation<'_>) {
    let entry = RequestLogEntry {
        id: hex::encode(rand::random::<[u8; 12]>()),
        worker: truncate(observation.worker, 63),
        version: observation.version,
        node: node.id_hex(),
        hostname: truncate(observation.hostname, 253),
        method: truncate(observation.method, 16),
        path: truncate(observation.path, 2_048),
        status_code: observation.status_code,
        duration_ms: observation.duration_ms,
        called_at_ms: now_ms(),
    };
    node.enqueue_request_log(entry);
}

pub fn snapshot(
    node: &Node,
    worker: &str,
    hostname: Option<&str>,
    status_class: Option<u16>,
    limit: usize,
) -> anyhow::Result<RequestLogSnapshot> {
    let limit = limit.clamp(1, 1_000);
    let mut entries = node
        .store
        .load_request_logs(worker, hostname, status_class, limit)?;
    let current_hour = now_ms() / HOUR_MS * HOUR_MS;
    let first_hour = current_hour.saturating_sub(23 * HOUR_MS);
    let (mut hostnames, mut aggregate) = node
        .store
        .request_log_aggregate(worker, first_hour, hostname)?;
    // Read the pending queue after both persisted views. A concurrent flush
    // may make one refresh briefly omit an entry, but can never double-count
    // the same entry in both the redb aggregate and this pending snapshot.
    let pending = node.pending_request_logs(worker);
    entries.extend(
        pending
            .iter()
            .filter(|entry| entry_matches(entry, hostname, status_class))
            .cloned(),
    );
    entries.sort_by(|left, right| {
        right
            .called_at_ms
            .cmp(&left.called_at_ms)
            .then_with(|| right.id.cmp(&left.id))
    });
    entries.dedup_by(|left, right| left.id == right.id);
    entries.truncate(limit);
    for entry in &pending {
        if entry.called_at_ms < first_hour {
            continue;
        }
        hostnames.insert(entry.hostname.clone());
        if hostname.is_none_or(|selected| selected == entry.hostname) {
            let bucket = entry.called_at_ms / HOUR_MS * HOUR_MS;
            add_status(aggregate.entry(bucket).or_default(), entry.status_code);
        }
    }
    let hours = (0..24)
        .map(|offset| {
            let start_ms = first_hour + offset * HOUR_MS;
            let counts = aggregate.remove(&start_ms).unwrap_or_default();
            RequestHour {
                start_ms,
                status_2xx: counts[0],
                status_3xx: counts[1],
                status_4xx: counts[2],
                status_5xx: counts[3],
                other: counts[4],
            }
        })
        .collect();
    Ok(RequestLogSnapshot {
        node: node.id_hex(),
        label: node.cfg.label.clone(),
        entries,
        hostnames: hostnames.into_iter().collect(),
        hours,
    })
}

pub fn spawn(node: Arc<Node>) {
    tokio::spawn(async move {
        let mut last_cleanup = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let pending = node.take_pending_request_logs();
            if !pending.is_empty() {
                if let Err(error) = node.store.put_request_logs(&pending) {
                    tracing::warn!("持久化 Worker 请求日志失败：{error:#}");
                    node.requeue_request_logs(pending);
                }
            }
            let now = now_ms();
            if now.saturating_sub(last_cleanup) >= HOUR_MS {
                if let Err(error) = node
                    .store
                    .delete_request_logs_before(now.saturating_sub(REQUEST_LOG_RETENTION_MS))
                {
                    tracing::warn!("清理过期 Worker 请求日志失败：{error:#}");
                } else {
                    last_cleanup = now;
                }
                if let Err(error) = node.store.delete_data_audit_before(
                    now.saturating_sub(crate::data_audit::DATA_AUDIT_RETENTION_MS),
                ) {
                    tracing::warn!("清理过期 KV/D1 数据审计失败：{error:#}");
                }
            }
        }
    });
}

pub(crate) fn entry_matches(
    entry: &RequestLogEntry,
    hostname: Option<&str>,
    status_class: Option<u16>,
) -> bool {
    hostname.is_none_or(|value| value == entry.hostname)
        && status_class.is_none_or(|class| entry.status_code / 100 == class)
}

pub(crate) fn add_status(counts: &mut [u64; 5], status: u16) {
    let index = match status / 100 {
        2 => 0,
        3 => 1,
        4 => 2,
        5 => 3,
        _ => 4,
    };
    counts[index] = counts[index].saturating_add(1);
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

pub(crate) type RequestAggregate = (BTreeSet<String>, BTreeMap<u64, [u64; 5]>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_and_status_buckets_do_not_capture_sensitive_data() {
        let entry = RequestLogEntry {
            id: "id".into(),
            worker: "worker".into(),
            version: 1,
            node: "node".into(),
            hostname: "worker.test".into(),
            method: "GET".into(),
            path: "/safe-path".into(),
            status_code: 503,
            duration_ms: 12,
            called_at_ms: 1,
        };
        assert!(entry_matches(&entry, Some("worker.test"), Some(5)));
        assert!(!entry_matches(&entry, Some("other.test"), None));
        let mut counts = [0; 5];
        add_status(&mut counts, 204);
        add_status(&mut counts, 503);
        add_status(&mut counts, 101);
        assert_eq!(counts, [1, 0, 0, 1, 1]);
    }

    #[test]
    fn cluster_merge_deduplicates_entries_and_sums_hours() {
        let entry = RequestLogEntry {
            id: "shared-id".into(),
            worker: "worker".into(),
            version: 1,
            node: "node-a".into(),
            hostname: "worker.test".into(),
            method: "GET".into(),
            path: "/".into(),
            status_code: 200,
            duration_ms: 3,
            called_at_ms: 10,
        };
        let snapshot = |node: &str| RequestLogSnapshot {
            node: node.into(),
            label: node.into(),
            entries: vec![entry.clone()],
            hostnames: vec!["worker.test".into()],
            hours: vec![RequestHour {
                start_ms: 0,
                status_2xx: 1,
                ..Default::default()
            }],
        };
        let snapshots = [snapshot("node-a"), snapshot("node-b")];
        let merged = merge_snapshots(&snapshots, 100);
        assert_eq!(merged.entries, vec![entry]);
        assert_eq!(merged.hostnames, vec!["worker.test"]);
        assert_eq!(merged.hours[0].status_2xx, 2);
    }
}
