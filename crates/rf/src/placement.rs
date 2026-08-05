//! Operator-signed node policy and tag-based Worker placement.
//!
//! Node capabilities are not a central registry. Each policy is an immutable,
//! hash-chained platform resource keyed by a deterministic alias of the node's
//! public identity. Every member independently derives the same effective
//! tags and placement decision.

use crate::node::Node;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const NODE_POLICY_KIND: &str = "node_policy";
pub const NODE_POLICY_SCHEMA: u8 = 1;
pub const REQUIRED_TAGS_METADATA_ENV: &str = "__RF_REQUIRED_TAGS_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePolicy {
    pub schema: u8,
    pub node_id: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub drain: bool,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub reason: String,
}

impl NodePolicy {
    pub fn validate(&self) -> Result<()> {
        if self.schema != NODE_POLICY_SCHEMA {
            bail!("不支持此版本的节点策略格式");
        }
        if self.node_id.len() != 64 || !self.node_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("节点身份必须是 64 位十六进制值");
        }
        if !self.region.is_empty() && !valid_tag(&self.region) {
            bail!("节点区域无效");
        }
        validate_tags(&self.tags)?;
        if self.reason.len() > 500 || self.reason.chars().any(char::is_control) {
            bail!("节点暂停原因无效");
        }
        Ok(())
    }
}

pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 40
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !tag.starts_with('-')
        && !tag.ends_with('-')
}

pub fn normalize_tags(tags: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
    let tags = tags
        .into_iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    validate_tags(&tags)?;
    Ok(tags)
}

pub fn validate_tags(tags: &[String]) -> Result<()> {
    if tags.len() > 64 || tags.iter().any(|tag| !valid_tag(tag)) {
        bail!("节点标签最多 64 个，且只能包含小写字母、数字和连字符");
    }
    if tags.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("节点标签必须排序且不能重复");
    }
    Ok(())
}

pub fn resource_name(node_id: &str) -> Result<String> {
    if node_id.len() != 64 || !node_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("节点身份无效");
    }
    Ok(format!(
        "node-{}",
        &hex::encode(Sha256::digest(node_id.as_bytes()))[..32]
    ))
}

pub fn prepare(node: &Node, policy: NodePolicy) -> Result<ResourceRecord> {
    let mut node_id = policy.node_id.clone();
    node_id.make_ascii_lowercase();
    let head = resource::head(node, NODE_POLICY_KIND, &resource_name(&node_id)?);
    prepare_after(policy, head.as_ref())
}

/// Prepare the next signed policy from a head fetched through any node. This
/// keeps the loopback CLI console stateless just like the rest of the control
/// plane.
pub fn prepare_after(
    mut policy: NodePolicy,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    policy.node_id.make_ascii_lowercase();
    policy.region = policy.region.trim().to_ascii_lowercase();
    policy.tags = normalize_tags(policy.tags)?;
    policy.reason = policy.reason.trim().to_string();
    policy.validate()?;
    resource::prepare_after(
        NODE_POLICY_KIND,
        resource_name(&policy.node_id)?,
        serde_json::to_value(policy)?,
        false,
        head,
    )
}

pub fn policy_spec(record: &ResourceRecord) -> Result<NodePolicy> {
    if record.kind != NODE_POLICY_KIND || record.deleted {
        bail!("平台资源不是可用的节点策略");
    }
    let policy: NodePolicy = serde_json::from_str(&record.spec_json)?;
    policy.validate()?;
    if record.name != resource_name(&policy.node_id)? {
        bail!("节点策略资源名与节点身份不一致");
    }
    Ok(policy)
}

pub fn policies(node: &Node) -> Vec<(ResourceView, NodePolicy)> {
    resource::heads(node, Some(NODE_POLICY_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| policy_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn policy(node: &Node, node_id: &str) -> Option<(ResourceView, NodePolicy)> {
    policy_checked(node, node_id).ok().flatten()
}

pub fn policy_checked(node: &Node, node_id: &str) -> Result<Option<(ResourceView, NodePolicy)>> {
    let name = resource_name(node_id)?;
    let Some(view) = resource::head(node, NODE_POLICY_KIND, &name) else {
        return Ok(None);
    };
    if view.resource.deleted {
        return Ok(None);
    }
    let spec = policy_spec(&view.resource)?;
    Ok(Some((view, spec)))
}

pub fn system_tags(node: &Node, node_id: &str) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    if node_id == node.id_hex() {
        if node.cfg.public {
            tags.insert("public".into());
        }
        if node.cfg.email.enabled {
            tags.insert("email".into());
        }
        if node.cfg.build.enabled {
            tags.insert("build".into());
        }
        if crate::build::configured_binary(node.cfg.build.sandbox.as_deref(), "bwrap").is_some() {
            tags.insert("binary".into());
        }
        match crate::binary::current_os_arch() {
            "linux/amd64" => {
                tags.insert("arch-amd64".into());
            }
            "linux/arm64" => {
                tags.insert("arch-arm64".into());
            }
            _ => {}
        }
        if node.cfg.storage.rclone_binary.is_some() && node.cfg.storage.rclone_config.is_some() {
            tags.insert("rclone".into());
        }
    } else if let Some(peer) = node.peers().get(node_id) {
        if peer.public {
            tags.insert("public".into());
        }
        tags.extend(peer.capabilities.iter().cloned());
    }
    tags
}

pub fn effective_tags(node: &Node, node_id: &str) -> BTreeSet<String> {
    let mut tags = system_tags(node, node_id);
    if let Some((_, policy)) = policy(node, node_id) {
        tags.extend(policy.tags);
        if !policy.region.is_empty() {
            tags.insert(format!("region-{}", policy.region.to_ascii_lowercase()));
        }
    }
    tags
}

pub fn required_tags(manifest: &rf_core::manifest::WorkerManifest) -> Vec<String> {
    required_tags_checked(manifest).unwrap_or_default()
}

pub fn required_tags_checked(manifest: &rf_core::manifest::WorkerManifest) -> Result<Vec<String>> {
    manifest
        .env
        .get(REQUIRED_TAGS_METADATA_ENV)
        .map(|raw| {
            let tags: Vec<String> =
                serde_json::from_str(raw).context("Worker 节点标签元数据无效")?;
            validate_tags(&tags)?;
            Ok(tags)
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

pub fn eligible(node: &Node, node_id: &str, manifest: &rf_core::manifest::WorkerManifest) -> bool {
    let policy = match policy_checked(node, node_id) {
        Ok(policy) => policy.map(|(_, policy)| policy),
        Err(_) => return false,
    };
    if policy.as_ref().is_some_and(|policy| policy.suspended) {
        return false;
    }
    let tags = effective_tags(node, node_id);
    workload_required_tags(node, manifest)
        .is_ok_and(|required| required.iter().all(|tag| tags.contains(tag)))
}

pub fn workload_required_tags(
    node: &Node,
    manifest: &rf_core::manifest::WorkerManifest,
) -> Result<BTreeSet<String>> {
    let mut required = required_tags_checked(manifest)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    for bucket in crate::deploy::r2_bindings(manifest).values() {
        let (_, spec) = crate::r2::bucket_record(node, bucket)
            .with_context(|| format!("Worker 引用的 R2 bucket 不存在：{bucket}"))?;
        if !spec.uses_local_storage() {
            required.insert("rclone".into());
        }
    }
    for binary_name in crate::deploy::binary_bindings(manifest).values() {
        let (_, spec) = crate::binary::record(node, binary_name)
            .with_context(|| format!("Worker 引用的 Binary 不存在：{binary_name}"))?;
        required.insert("binary".into());
        required.extend(spec.required_tags);
        required.insert(match spec.os_arch.as_str() {
            "linux/amd64" => "arch-amd64".into(),
            "linux/arm64" => "arch-arm64".into(),
            _ => bail!("Binary {binary_name} 的架构无效"),
        });
    }
    Ok(required)
}

pub fn accepts_dns(node: &Node, node_id: &str) -> bool {
    match policy_checked(node, node_id) {
        Ok(Some((_, policy))) => !policy.drain && !policy.suspended,
        Ok(None) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn tags_are_canonical_and_node_alias_is_stable() {
        assert_eq!(
            normalize_tags(vec!["gpu".into(), " asia ".into(), "gpu".into()]).unwrap(),
            vec!["asia", "gpu"]
        );
        assert!(normalize_tags(vec!["Bad_Tag".into()]).is_err());
        let id = "ab".repeat(32);
        let name = resource_name(&id).unwrap();
        assert_eq!(name.len(), 37);
        assert_eq!(name, resource_name(&id).unwrap());
    }

    #[test]
    fn malformed_signed_worker_metadata_does_not_become_unconstrained() {
        let mut manifest = rf_core::manifest::WorkerManifest {
            name: "demo".into(),
            version: 1,
            prev: None,
            deleted: false,
            main: String::new(),
            modules: vec![],
            assets: vec![],
            hostnames: vec![],
            env: BTreeMap::new(),
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-08-04".into(),
        };
        manifest
            .env
            .insert(REQUIRED_TAGS_METADATA_ENV.into(), "not-json".into());
        assert!(required_tags_checked(&manifest).is_err());
    }
}
