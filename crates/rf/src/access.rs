//! One-way, operator-signed personal access tokens for the public API.
//!
//! A raw `rfp_…` value is returned exactly once. Only its SHA-256 digest and
//! safe display prefix are placed in the signed resource chain. Every node can
//! therefore authenticate and revoke a token without a central database.

use crate::node::{now_ms, Node};
use crate::resource::{self, ResourceRecord};
use anyhow::{bail, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const TOKEN_KIND: &str = "api_access_token";
pub const TOKEN_SCHEMA: u8 = 1;
pub const TOKEN_PREFIX: &str = "rfp_";
const DISPLAY_PREFIX_LEN: usize = 12;

pub const ALL_SCOPES: &[&str] = &[
    "*",
    "worker:read",
    "worker:write",
    "kv:read",
    "kv:write",
    "d1:read",
    "d1:write",
    "r2:read",
    "r2:write",
    "queue:read",
    "queue:write",
    "analytics:read",
    "analytics:write",
    "pipeline:read",
    "pipeline:write",
    "workflow:read",
    "workflow:write",
    "flow:read",
    "flow:write",
    "email:read",
    "email:write",
    "binary:read",
    "binary:write",
    "storage:read",
    "storage:write",
    "node:read",
    "node:write",
    "quota:read",
    "quota:write",
    "audit:read",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessTokenSpec {
    pub schema: u8,
    pub label: String,
    pub prefix: String,
    pub sha256: String,
    pub scopes: Vec<String>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub revoked_at_ms: Option<u64>,
}

impl AccessTokenSpec {
    pub fn validate(&self) -> Result<()> {
        if self.schema != TOKEN_SCHEMA {
            bail!("不支持此版本的 API 访问令牌");
        }
        if self.label.trim().is_empty()
            || self.label.len() > 120
            || self.label.contains(['\r', '\n'])
        {
            bail!("API 访问令牌名称必须为 1 至 120 个字符");
        }
        if self.prefix.len() != DISPLAY_PREFIX_LEN
            || !self.prefix.starts_with(TOKEN_PREFIX)
            || !self
                .prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            bail!("API 访问令牌显示前缀无效");
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("API 访问令牌摘要无效");
        }
        if self.scopes.is_empty() || self.scopes.len() > ALL_SCOPES.len() {
            bail!("API 访问令牌至少需要一个有效作用域");
        }
        let known = ALL_SCOPES.iter().copied().collect::<BTreeSet<_>>();
        let scopes = self
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if scopes.len() != self.scopes.len() || scopes.iter().any(|scope| !known.contains(scope)) {
            bail!("API 访问令牌包含重复或未知作用域");
        }
        if scopes.contains("*") && scopes.len() != 1 {
            bail!("通配作用域 * 必须单独使用");
        }
        if self.created_at_ms == 0 {
            bail!("API 访问令牌创建时间无效");
        }
        if self
            .expires_at_ms
            .is_some_and(|expires| expires <= self.created_at_ms)
        {
            bail!("API 访问令牌到期时间必须晚于创建时间");
        }
        if self
            .revoked_at_ms
            .is_some_and(|revoked| revoked < self.created_at_ms)
        {
            bail!("API 访问令牌撤销时间无效");
        }
        Ok(())
    }

    pub fn active(&self, at_ms: u64) -> bool {
        self.revoked_at_ms.is_none() && self.expires_at_ms.is_none_or(|expires| expires > at_ms)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessTokenView {
    pub id: String,
    pub version: u64,
    pub label: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub revoked_at_ms: Option<u64>,
    pub last_used_at_ms: Option<u64>,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct AccessPrincipal {
    pub id: String,
    pub label: String,
    pub scopes: BTreeSet<String>,
}

impl AccessPrincipal {
    pub fn allows(&self, required: &str) -> bool {
        self.scopes.contains("*") || self.scopes.contains(required)
    }
}

pub fn mint(
    node: &Node,
    label: String,
    scopes: Vec<String>,
    expires_at_ms: Option<u64>,
) -> Result<(ResourceRecord, String)> {
    let raw = format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    );
    let digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let name = format!("pat-{}", &digest[..20]);
    if resource::head(node, TOKEN_KIND, &name).is_some() {
        bail!("API 访问令牌随机标识碰撞，请重试");
    }
    let spec = AccessTokenSpec {
        schema: TOKEN_SCHEMA,
        label: label.trim().to_string(),
        prefix: raw[..DISPLAY_PREFIX_LEN].to_string(),
        sha256: digest,
        scopes,
        created_at_ms: now_ms(),
        expires_at_ms,
        revoked_at_ms: None,
    };
    spec.validate()?;
    let record =
        resource::prepare_after(TOKEN_KIND, name, serde_json::to_value(spec)?, false, None)?;
    Ok((record, raw))
}

pub fn revoke(node: &Node, id: &str) -> Result<ResourceRecord> {
    let head = resource::head(node, TOKEN_KIND, id)
        .ok_or_else(|| anyhow::anyhow!("API 访问令牌不存在"))?;
    if head.resource.deleted {
        bail!("API 访问令牌不存在");
    }
    let mut spec = token_spec(&head.resource)?;
    if spec.revoked_at_ms.is_some() {
        bail!("API 访问令牌已经撤销");
    }
    spec.revoked_at_ms = Some(now_ms());
    resource::prepare_after(
        TOKEN_KIND,
        id,
        serde_json::to_value(spec)?,
        false,
        Some(&head),
    )
}

pub fn token_spec(record: &ResourceRecord) -> Result<AccessTokenSpec> {
    if record.kind != TOKEN_KIND {
        bail!("平台资源不是 API 访问令牌");
    }
    let spec: AccessTokenSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn views(node: &Node) -> Vec<AccessTokenView> {
    let now = now_ms();
    resource::heads(node, Some(TOKEN_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = token_spec(&view.resource).ok()?;
            let id = view.resource.name.clone();
            let active = spec.active(now);
            let last_used_at_ms = node.store.credential_last_used(&id).ok().flatten();
            Some(AccessTokenView {
                id,
                version: view.resource.version,
                label: spec.label,
                prefix: spec.prefix,
                scopes: spec.scopes,
                created_at_ms: spec.created_at_ms,
                expires_at_ms: spec.expires_at_ms,
                revoked_at_ms: spec.revoked_at_ms,
                last_used_at_ms,
                active,
            })
        })
        .collect()
}

pub fn resolve(node: &Node, raw: &str) -> Option<AccessPrincipal> {
    if !raw.starts_with(TOKEN_PREFIX) || raw.len() != TOKEN_PREFIX.len() + 43 {
        return None;
    }
    let prefix = raw.get(..DISPLAY_PREFIX_LEN)?;
    let candidate: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let now = now_ms();
    for view in resource::heads(node, Some(TOKEN_KIND)) {
        if view.resource.deleted {
            continue;
        }
        let Ok(spec) = token_spec(&view.resource) else {
            continue;
        };
        if spec.prefix != prefix || !spec.active(now) {
            continue;
        }
        let Ok(expected) = hex::decode(&spec.sha256) else {
            continue;
        };
        if !constant_time_eq(&candidate, &expected) {
            continue;
        }
        let _ = node.store.touch_credential(&view.resource.name, now);
        return Some(AccessPrincipal {
            id: view.resource.name,
            label: spec.label,
            scopes: spec.scopes.into_iter().collect(),
        });
    }
    None
}

pub fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, raw) = value.trim().split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(raw.trim())
}

pub fn scope_for_resource(kind: &str, write: bool) -> Option<String> {
    let area = match kind {
        crate::r2::BUCKET_KIND => "r2",
        crate::s3::CREDENTIAL_KIND | TOKEN_KIND => return None,
        crate::queue::QUEUE_KIND => "queue",
        crate::analytics::DATASET_KIND => "analytics",
        crate::pipeline::PIPELINE_KIND => "pipeline",
        crate::workflow::WORKFLOW_KIND => "workflow",
        crate::flow::FLOW_KIND => "flow",
        crate::email::EMAIL_DOMAIN_KIND => "email",
        crate::binary::BINARY_KIND => "binary",
        crate::storage_policy::STORAGE_POLICY_KIND => "storage",
        crate::placement::NODE_POLICY_KIND => "node",
        crate::quota::POLICY_KIND => "quota",
        crate::preview::PREVIEW_KIND => "worker",
        _ => return None,
    };
    Some(format!("{area}:{}", if write { "write" } else { "read" }))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use rf_core::identity::{AnyKeypair, Keypair};

    #[test]
    fn token_hash_is_one_way_and_scope_match_is_exact() {
        let operator = AnyKeypair::Ed(Keypair::from_seed([51; 32]));
        let dir = std::env::temp_dir().join(format!(
            "rf-access-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let config: NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {dir:?}
            operator = "{operator}"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:17381"
            [peer_api]
            listen = "127.0.0.1:17382"
            "#,
            dir = dir.display(),
            operator = operator.signer_id(),
        ))
        .unwrap();
        let node = Node::open(config, Keypair::from_seed([52; 32])).unwrap();
        let (record, raw) = mint(&node, "自动化".into(), vec!["r2:read".into()], None).unwrap();
        assert!(!record.spec_json.contains(&raw));
        let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator);
        resource::ingest(&node, &envelope).unwrap();
        let principal = resolve(&node, &raw).unwrap();
        assert!(principal.allows("r2:read"));
        assert!(!principal.allows("r2:write"));
        assert!(resolve(&node, &(raw.clone() + "x")).is_none());
        assert!(scope_for_resource(crate::s3::CREDENTIAL_KIND, false).is_none());
        assert!(scope_for_resource(TOKEN_KIND, true).is_none());
        let revoked = revoke(&node, &record.name).unwrap();
        resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&revoked, &operator),
        )
        .unwrap();
        assert!(resolve(&node, &raw).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
