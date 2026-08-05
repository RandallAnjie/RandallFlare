//! Operator-signed platform resources.
//!
//! Workers have a purpose-built manifest, while buckets, pipelines,
//! workflows, queues, email domains and future platform objects share this
//! small generic envelope. The signed record contains canonical JSON but no
//! node-local credentials. Immutable envelopes replicate through the existing
//! KV anti-entropy path and form an append-only hash chain per resource.

use crate::node::{now_ms, Node};
use anyhow::{bail, Context, Result};
use rf_core::envelope::Envelope;
use rf_core::manifest::valid_name;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

pub const RESOURCE_NAMESPACE: &str = "__rf_platform_resources_v1";
pub const RESOURCE_SCHEMA: u8 = 1;
const MAX_KIND_BYTES: usize = 48;
// Worker preview resources can carry a complete 5,000-file immutable
// manifest. Keep a hard bound, but do not make legitimate large static sites
// impossible to preview.
const MAX_SPEC_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRecord {
    pub schema: u8,
    pub kind: String,
    pub name: String,
    pub version: u64,
    pub prev: Option<[u8; 32]>,
    #[serde(default)]
    pub deleted: bool,
    /// Canonical compact JSON. Stored as text because postcard deliberately
    /// does not support `serde_json::Value`'s deserialize-any data model.
    pub spec_json: String,
}

impl ResourceRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema != RESOURCE_SCHEMA {
            bail!("不支持此版本的平台资源格式");
        }
        if !valid_kind(&self.kind) {
            bail!("平台资源类型必须由小写字母、数字和下划线组成");
        }
        if !valid_name(&self.name) {
            bail!("平台资源名称须由 1 至 63 个小写字母、数字或连字符组成");
        }
        if self.version == 0 || (self.version == 1) != self.prev.is_none() {
            bail!("平台资源版本链无效");
        }
        let spec: Value =
            serde_json::from_str(&self.spec_json).context("平台资源配置不是有效的 JSON")?;
        if self.deleted {
            if !spec.is_null() && spec != Value::Object(Default::default()) {
                bail!("已删除的平台资源不得携带配置");
            }
            return Ok(());
        }
        if !spec.is_object() {
            bail!("平台资源配置必须是 JSON 对象");
        }
        if self.spec_json.len() > MAX_SPEC_BYTES {
            bail!("平台资源配置不得超过 8 MiB");
        }
        Ok(())
    }

    pub fn id(&self) -> String {
        format!("{}/{}", self.kind, self.name)
    }

    pub fn spec(&self) -> Result<Value> {
        serde_json::from_str(&self.spec_json).context("平台资源配置不是有效的 JSON")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceView {
    #[serde(flatten)]
    pub resource: ResourceRecord,
    pub digest: String,
}

pub fn valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= MAX_KIND_BYTES
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub fn prepare(
    node: &Node,
    kind: impl Into<String>,
    name: impl Into<String>,
    spec: Value,
    deleted: bool,
) -> Result<ResourceRecord> {
    let kind = kind.into();
    let name = name.into();
    let head = head(node, &kind, &name);
    prepare_after(kind, name, spec, deleted, head.as_ref())
}

/// Prepare the next record from a head fetched from any cluster node. This is
/// used by the operator CLI, which deliberately has no local control-plane
/// database.
pub fn prepare_after(
    kind: impl Into<String>,
    name: impl Into<String>,
    spec: Value,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    let kind = kind.into();
    let name = name.into();
    if let Some(head) = head {
        if head.resource.kind != kind || head.resource.name != name {
            bail!("平台资源前序版本属于其他资源");
        }
    }
    let record = ResourceRecord {
        schema: RESOURCE_SCHEMA,
        kind,
        name,
        version: head
            .as_ref()
            .map(|view| view.resource.version + 1)
            .unwrap_or(1),
        prev: head
            .as_ref()
            .map(|view| decode_digest(&view.digest))
            .transpose()?,
        deleted,
        spec_json: serde_json::to_string(if deleted { &Value::Null } else { &spec })?,
    };
    record.validate()?;
    Ok(record)
}

pub fn ingest(node: &Node, envelope: &Envelope) -> Result<ResourceRecord> {
    let resource: ResourceRecord = envelope
        .open(Some(&node.cfg.operator))
        .map_err(|error| anyhow::anyhow!("平台资源签名无效：{error}"))?;
    resource.validate()?;
    let digest = hex::encode(envelope.digest());
    let key = format!(
        "{}/{}/{:020}/{}",
        resource.kind, resource.name, resource.version, digest
    );
    if node.kv_get(RESOURCE_NAMESPACE, &key).is_none() {
        node.kv_put(RESOURCE_NAMESPACE, &key, Some(envelope.to_bytes()), None)?;
    }
    if matches!(
        resource.kind.as_str(),
        crate::placement::NODE_POLICY_KIND | crate::quota::POLICY_KIND
    ) {
        // Placement changes affect even assets-only Workers, which have no
        // runtime process whose port change could otherwise trigger gossip.
        // Quota policy changes can alter outbound-network permissions for an
        // otherwise unchanged module Worker.
        node.notify_runtime_changed();
    }
    Ok(resource)
}

pub fn head(node: &Node, kind: &str, name: &str) -> Option<ResourceView> {
    records(node, Some(kind), Some(name))
        .into_iter()
        .filter(|view| view.resource.kind == kind && view.resource.name == name)
        .max_by(|left, right| {
            (left.resource.version, &left.digest).cmp(&(right.resource.version, &right.digest))
        })
}

pub fn heads(node: &Node, kind: Option<&str>) -> Vec<ResourceView> {
    let mut latest: BTreeMap<(String, String), ResourceView> = BTreeMap::new();
    for view in records(node, kind, None) {
        let id = (view.resource.kind.clone(), view.resource.name.clone());
        let replace = latest.get(&id).is_none_or(|current| {
            (view.resource.version, &view.digest) > (current.resource.version, &current.digest)
        });
        if replace {
            latest.insert(id, view);
        }
    }
    latest.into_values().collect()
}

/// Return only records connected to a valid v1 genesis. Out-of-order records
/// remain stored and become visible as soon as their exact predecessor arrives.
pub fn records(node: &Node, kind: Option<&str>, name: Option<&str>) -> Vec<ResourceView> {
    let prefix = match (kind, name) {
        (Some(kind), Some(name)) => format!("{kind}/{name}/"),
        (Some(kind), None) => format!("{kind}/"),
        (None, _) => String::new(),
    };
    let mut candidates: BTreeMap<(String, String), Vec<(ResourceRecord, String)>> = BTreeMap::new();
    for (key, entry) in node.kv_dump(RESOURCE_NAMESPACE) {
        if !key.starts_with(&prefix) {
            continue;
        }
        let Some(bytes) = entry.visible(now_ms()) else {
            continue;
        };
        let Ok(envelope) = Envelope::from_bytes(bytes) else {
            continue;
        };
        let Ok(resource) = envelope.open::<ResourceRecord>(Some(&node.cfg.operator)) else {
            continue;
        };
        if resource.validate().is_err()
            || !key.starts_with(&format!("{}/{}/", resource.kind, resource.name))
        {
            continue;
        }
        candidates
            .entry((resource.kind.clone(), resource.name.clone()))
            .or_default()
            .push((resource, hex::encode(envelope.digest())));
    }

    let mut connected = Vec::new();
    for (_, mut group) in candidates {
        group.sort_by(|left, right| (left.0.version, &left.1).cmp(&(right.0.version, &right.1)));
        let mut accepted: HashMap<String, u64> = HashMap::new();
        for (resource, digest) in group {
            let chain_ok = if resource.version == 1 {
                resource.prev.is_none()
            } else {
                resource
                    .prev
                    .map(hex::encode)
                    .and_then(|previous| accepted.get(&previous).copied())
                    == Some(resource.version - 1)
            };
            if chain_ok {
                accepted.insert(digest.clone(), resource.version);
                connected.push(ResourceView { resource, digest });
            }
        }
    }
    connected
}

fn decode_digest(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .context("平台资源摘要不是十六进制")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("平台资源摘要长度无效"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use rf_core::identity::{AnyKeypair, Keypair};

    fn node(operator: &AnyKeypair) -> (Node, std::path::PathBuf) {
        let data_dir = std::env::temp_dir().join(format!(
            "rf-resource-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let cfg: NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {data_dir:?}
            operator = "{operator}"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:17381"
            [peer_api]
            listen = "127.0.0.1:17382"
            "#,
            data_dir = data_dir.display(),
            operator = operator.signer_id(),
        ))
        .unwrap();
        (
            Node::open(cfg, Keypair::from_seed([52; 32])).unwrap(),
            data_dir,
        )
    }

    #[test]
    fn signed_resources_form_a_verified_chain_and_ignore_forks_without_parent() {
        let operator = AnyKeypair::Ed(Keypair::from_seed([51; 32]));
        let attacker = AnyKeypair::Ed(Keypair::from_seed([53; 32]));
        let (node, dir) = node(&operator);
        let first = prepare(
            &node,
            "r2_bucket",
            "events",
            serde_json::json!({"backend": "local"}),
            false,
        )
        .unwrap();
        ingest(&node, &Envelope::seal_any(&first, &operator)).unwrap();
        let second = prepare(
            &node,
            "r2_bucket",
            "events",
            serde_json::json!({"backend": "rclone", "remote": "archive"}),
            false,
        )
        .unwrap();
        assert_eq!(second.version, 2);
        ingest(&node, &Envelope::seal_any(&second, &operator)).unwrap();
        assert_eq!(head(&node, "r2_bucket", "events").unwrap().resource, second);

        let mut orphan = second.clone();
        orphan.version = 3;
        orphan.prev = Some([7; 32]);
        ingest(&node, &Envelope::seal_any(&orphan, &operator)).unwrap();
        assert_eq!(
            head(&node, "r2_bucket", "events").unwrap().resource.version,
            2
        );
        assert!(ingest(&node, &Envelope::seal_any(&second, &attacker)).is_err());

        drop(node);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resource_validation_rejects_secrets_by_shape_only_when_deleted() {
        let record = ResourceRecord {
            schema: RESOURCE_SCHEMA,
            kind: "pipeline".into(),
            name: "events".into(),
            version: 1,
            prev: None,
            deleted: true,
            spec_json: serde_json::json!({"unexpected": true}).to_string(),
        };
        assert!(record.validate().is_err());
    }
}
