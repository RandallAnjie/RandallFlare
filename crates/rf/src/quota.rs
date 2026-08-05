//! Operator-signed, cluster-wide safety quotas.
//!
//! RandallFlare deliberately has no central account database.  The closest
//! decentralized equivalent of the reference plane's per-user quota row is a
//! single operator-signed policy replicated through the platform-resource
//! hash chain.  Admission happens on the node accepting an operator request;
//! already-signed records received through anti-entropy are never discarded.

use crate::node::Node;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use rf_core::manifest::WorkerManifest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const POLICY_KIND: &str = "cluster_policy";
pub const POLICY_NAME: &str = "default";
pub const POLICY_SCHEMA: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterQuotaPolicy {
    pub schema: u8,
    pub max_workers: u32,
    pub max_custom_hostnames: u32,
    pub max_worker_bytes: u64,
    pub max_requests_per_minute: u64,
    pub worker_outbound_allowed: bool,
    pub max_r2_local_bytes: u64,
    pub max_r2_objects: u64,
}

impl Default for ClusterQuotaPolicy {
    fn default() -> Self {
        Self {
            schema: POLICY_SCHEMA,
            max_workers: 50,
            max_custom_hostnames: 10,
            max_worker_bytes: 50_000_000,
            max_requests_per_minute: 10_000,
            worker_outbound_allowed: true,
            max_r2_local_bytes: 1024 * 1024 * 1024,
            max_r2_objects: 10_000,
        }
    }
}

impl ClusterQuotaPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.schema != POLICY_SCHEMA {
            bail!("不支持此版本的集群配额策略");
        }
        if self.max_workers == 0 || self.max_workers > 1_000_000 {
            bail!("Worker 数量配额必须介于 1 和 1000000 之间");
        }
        if self.max_custom_hostnames == 0 || self.max_custom_hostnames > 1_000_000 {
            bail!("自定义域名配额必须介于 1 和 1000000 之间");
        }
        if self.max_worker_bytes == 0 || self.max_worker_bytes > 8 * 1024 * 1024 * 1024 {
            bail!("单个 Worker 内容配额必须介于 1 字节和 8 GiB 之间");
        }
        if self.max_requests_per_minute == 0 || self.max_requests_per_minute > 1_000_000_000 {
            bail!("每分钟请求配额必须介于 1 和 1000000000 之间");
        }
        if self.max_r2_local_bytes == 0 || self.max_r2_local_bytes > i64::MAX as u64 {
            bail!("R2 本地存储配额必须介于 1 字节和 i64::MAX 之间");
        }
        if self.max_r2_objects == 0 || self.max_r2_objects > i64::MAX as u64 {
            bail!("R2 对象数量配额必须介于 1 和 i64::MAX 之间");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ClusterQuotaUsage {
    pub workers: u64,
    pub custom_hostnames: u64,
    pub largest_worker_bytes: u64,
    pub r2_local_bytes: u64,
    pub r2_objects: u64,
}

pub fn policy(node: &Node) -> Result<ClusterQuotaPolicy> {
    let Some(view) = resource::head(node, POLICY_KIND, POLICY_NAME) else {
        return Ok(ClusterQuotaPolicy::default());
    };
    if view.resource.deleted {
        return Ok(ClusterQuotaPolicy::default());
    }
    policy_spec(&view.resource)
}

pub fn policy_spec(record: &ResourceRecord) -> Result<ClusterQuotaPolicy> {
    if record.kind != POLICY_KIND || record.name != POLICY_NAME {
        bail!("平台资源不是默认集群配额策略");
    }
    let policy: ClusterQuotaPolicy = serde_json::from_value(record.spec()?)?;
    policy.validate()?;
    Ok(policy)
}

pub fn prepare_after(
    policy: ClusterQuotaPolicy,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    policy.validate()?;
    resource::prepare_after(
        POLICY_KIND,
        POLICY_NAME,
        serde_json::to_value(policy)?,
        false,
        head,
    )
}

pub fn worker_bytes(manifest: &WorkerManifest) -> u64 {
    manifest
        .modules
        .iter()
        .map(|module| module.size)
        .chain(manifest.assets.iter().map(|asset| asset.size))
        .sum()
}

/// Validate a newly-submitted signed manifest against the local converged
/// view.  Gossip hydration intentionally bypasses this check: rejecting an
/// operator-signed record on only one stale node would split the cluster.
pub fn validate_manifest_admission(node: &Node, manifest: &WorkerManifest) -> Result<()> {
    // A tombstone must always remain available as the escape hatch from an
    // over-quota (or temporarily invalid-policy) state.
    if manifest.deleted {
        return Ok(());
    }
    let quota = policy(node).context("集群配额策略无效；为安全起见拒绝部署")?;
    let bytes = worker_bytes(manifest);
    if bytes > quota.max_worker_bytes {
        bail!(
            "Worker 内容大小 {bytes} 字节超过单项目配额 {} 字节",
            quota.max_worker_bytes
        );
    }
    let existing = node.manifest(&manifest.name);
    if existing.is_none_or(|manifest| manifest.deleted)
        && node.live_manifests().len() as u64 >= quota.max_workers as u64
    {
        bail!("Worker 数量已达到集群配额 {}", quota.max_workers);
    }
    let hostnames = prospective_custom_hostnames(node, Some(manifest), None)?;
    if hostnames.len() as u64 > quota.max_custom_hostnames as u64 {
        bail!(
            "自定义域名数量 {} 超过集群配额 {}",
            hostnames.len(),
            quota.max_custom_hostnames
        );
    }
    Ok(())
}

/// Validate cross-resource constraints for a signed platform-resource write.
pub fn validate_resource_admission(node: &Node, record: &ResourceRecord) -> Result<()> {
    record.validate()?;
    // Deletion is remediation, not additional consumption. In particular,
    // deleting the policy itself restores the safe built-in defaults.
    if record.deleted {
        return Ok(());
    }
    if record.kind == POLICY_KIND {
        policy_spec(record)?;
        return Ok(());
    }
    if record.kind == crate::access::TOKEN_KIND {
        crate::access::token_spec(record)?;
        return Ok(());
    }
    if record.kind == crate::s3::CREDENTIAL_KIND {
        crate::s3::credential_spec(record)?;
        return Ok(());
    }
    if record.kind == crate::binary::BINARY_KIND {
        crate::binary::binary_spec(record)?;
        return Ok(());
    }
    if record.kind == crate::storage_policy::STORAGE_POLICY_KIND {
        crate::storage_policy::validate_admission(node, record)?;
        return Ok(());
    }
    if matches!(
        record.kind.as_str(),
        crate::exit::EXIT_RULE_KIND | crate::exit::DEVICE_KIND
    ) {
        crate::exit::validate_admission(node, record)?;
        return Ok(());
    }
    if record.kind == crate::r2::BUCKET_KIND {
        crate::r2::validate_bucket_admission(node, record)?;
    }
    let quota = policy(node).context("集群配额策略无效；为安全起见拒绝资源变更")?;
    if matches!(
        record.kind.as_str(),
        crate::r2::BUCKET_KIND | crate::pipeline::PIPELINE_KIND | crate::flow::FLOW_KIND
    ) {
        let hostnames = prospective_custom_hostnames(node, None, Some(record))?;
        if hostnames.len() as u64 > quota.max_custom_hostnames as u64 {
            bail!(
                "自定义域名数量 {} 超过集群配额 {}",
                hostnames.len(),
                quota.max_custom_hostnames
            );
        }
    }
    Ok(())
}

fn prospective_custom_hostnames(
    node: &Node,
    replacement_manifest: Option<&WorkerManifest>,
    replacement_resource: Option<&ResourceRecord>,
) -> Result<BTreeSet<String>> {
    let mut hostnames = BTreeSet::new();
    let replacement_worker = replacement_manifest.map(|manifest| manifest.name.as_str());
    for manifest in node.live_manifests() {
        if replacement_worker == Some(manifest.name.as_str()) {
            continue;
        }
        hostnames.extend(manifest.hostnames);
    }
    if let Some(manifest) = replacement_manifest.filter(|manifest| !manifest.deleted) {
        hostnames.extend(manifest.hostnames.iter().cloned());
    }

    for view in resource::heads(node, None) {
        if view.resource.deleted || replaced_by(&view.resource, replacement_resource) {
            continue;
        }
        extend_resource_hostnames(&mut hostnames, &view.resource)?;
    }
    if let Some(record) = replacement_resource.filter(|record| !record.deleted) {
        extend_resource_hostnames(&mut hostnames, record)?;
    }
    Ok(hostnames)
}

fn replaced_by(current: &ResourceRecord, replacement: Option<&ResourceRecord>) -> bool {
    replacement.is_some_and(|replacement| {
        replacement.kind == current.kind && replacement.name == current.name
    })
}

fn extend_resource_hostnames(
    hostnames: &mut BTreeSet<String>,
    record: &ResourceRecord,
) -> Result<()> {
    match record.kind.as_str() {
        crate::r2::BUCKET_KIND => {
            hostnames.extend(crate::r2::bucket_spec(record)?.hostnames);
        }
        crate::pipeline::PIPELINE_KIND => {
            hostnames.extend(crate::pipeline::pipeline_spec(record)?.hostnames);
        }
        crate::flow::FLOW_KIND => {
            hostnames.extend(crate::flow::flow_spec(record)?.hostnames);
        }
        _ => {}
    }
    Ok(())
}

pub async fn usage(node: &Node) -> Result<ClusterQuotaUsage> {
    let manifests = node.live_manifests();
    let mut usage = ClusterQuotaUsage {
        workers: manifests.len() as u64,
        custom_hostnames: prospective_custom_hostnames(node, None, None)?.len() as u64,
        largest_worker_bytes: manifests.iter().map(worker_bytes).max().unwrap_or(0),
        ..Default::default()
    };
    for (view, spec) in crate::r2::bucket_records(node) {
        let bucket = crate::r2::bucket_usage(node, &view.resource.name).await?;
        usage.r2_objects = usage.r2_objects.saturating_add(bucket.objects);
        if spec.uses_local_storage() {
            usage.r2_local_bytes = usage.r2_local_bytes.saturating_add(bucket.bytes);
        }
    }
    Ok(usage)
}

pub async fn validate_r2_write(
    node: &Node,
    bucket: &str,
    previous: Option<&crate::r2::ObjectMeta>,
    incoming_bytes: u64,
) -> Result<()> {
    let quota = policy(node).context("集群配额策略无效；为安全起见拒绝 R2 写入")?;
    let usage = usage(node).await?;
    let (_, bucket_spec) = crate::r2::bucket_record(node, bucket).context("R2 bucket 不存在")?;
    let projected_objects = usage
        .r2_objects
        .saturating_add(u64::from(previous.is_none()));
    let projected_local_bytes = if bucket_spec.uses_local_storage() {
        usage
            .r2_local_bytes
            .saturating_sub(previous.map(|object| object.size).unwrap_or(0))
            .saturating_add(incoming_bytes)
    } else {
        usage.r2_local_bytes
    };
    if projected_local_bytes > quota.max_r2_local_bytes {
        bail!(
            "R2 本地存储配额不足：写入后 {projected_local_bytes} 字节，配额 {} 字节",
            quota.max_r2_local_bytes
        );
    }
    if projected_objects > quota.max_r2_objects {
        bail!(
            "R2 对象数量配额不足：写入后 {projected_objects} 个，配额 {} 个",
            quota.max_r2_objects
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_reference_safety_limits() {
        let policy = ClusterQuotaPolicy::default();
        assert_eq!(policy.max_workers, 50);
        assert_eq!(policy.max_custom_hostnames, 10);
        assert_eq!(policy.max_worker_bytes, 50_000_000);
        assert_eq!(policy.max_requests_per_minute, 10_000);
        assert_eq!(policy.max_r2_local_bytes, 1024 * 1024 * 1024);
        assert_eq!(policy.max_r2_objects, 10_000);
        policy.validate().unwrap();
    }
}
