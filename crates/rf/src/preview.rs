//! Signed, expiring Worker previews.
//!
//! A preview is a generic platform resource containing one immutable Worker
//! manifest snapshot. It never advances the production manifest chain. Every
//! node independently materializes the same runtime alias and route; expiry is
//! checked against the signed timestamp, so cleanup needs no central scheduler.

use crate::node::{now_ms, Node};
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use rf_core::manifest::{valid_hostname, valid_name, WorkerManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREVIEW_KIND: &str = "worker_preview";
pub const PREVIEW_SCHEMA: u8 = 1;
pub const DEFAULT_VERSION_TTL_DAYS: u16 = 30;
pub const DEFAULT_PULL_REQUEST_TTL_DAYS: u16 = 14;
const MAX_TTL_DAYS: u16 = 90;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreviewSource {
    Version {
        version: u64,
    },
    PullRequest {
        number: u64,
        commit: String,
        branch: String,
    },
    Commit {
        commit: String,
        branch: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewSpec {
    pub schema: u8,
    pub worker: String,
    pub hostname: String,
    pub manifest: WorkerManifest,
    pub source: PreviewSource,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

impl PreviewSpec {
    pub fn validate(&self) -> Result<()> {
        if self.schema != PREVIEW_SCHEMA {
            bail!("不支持此版本的 Worker 预览格式");
        }
        if !valid_name(&self.worker) || self.manifest.name != self.worker {
            bail!("预览的 Worker 身份无效");
        }
        if !valid_hostname(&self.hostname) {
            bail!("预览域名无效");
        }
        self.manifest
            .validate()
            .map_err(|error| anyhow::anyhow!("预览清单无效：{error}"))?;
        if self.manifest.deleted {
            bail!("预览不能引用已删除的 Worker 清单");
        }
        if self.created_at_ms == 0
            || self.expires_at_ms <= self.created_at_ms
            || self.expires_at_ms.saturating_sub(self.created_at_ms)
                > u64::from(MAX_TTL_DAYS) * 86_400_000
        {
            bail!("预览有效期必须介于 1 毫秒和 {MAX_TTL_DAYS} 天之间");
        }
        match &self.source {
            PreviewSource::Version { version } if *version == self.manifest.version => {}
            PreviewSource::Version { .. } => bail!("预览版本与清单版本不一致"),
            PreviewSource::PullRequest {
                number,
                commit,
                branch,
            } => {
                if *number == 0 || *number > 1_000_000_000 {
                    bail!("Pull Request 编号无效");
                }
                validate_git_source(commit, branch)?;
            }
            PreviewSource::Commit { commit, branch } => validate_git_source(commit, branch)?,
        }
        Ok(())
    }

    pub fn active(&self, at_ms: u64) -> bool {
        at_ms < self.expires_at_ms
    }
}

fn validate_git_source(commit: &str, branch: &str) -> Result<()> {
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("预览提交必须是 40 位 Git SHA-1");
    }
    if branch.is_empty()
        || branch.len() > 255
        || branch.as_bytes().contains(&0)
        || branch.chars().any(char::is_control)
    {
        bail!("预览分支名称无效");
    }
    Ok(())
}

pub fn version_alias(worker: &str, version: u64) -> Result<String> {
    if !valid_name(worker) || version == 0 {
        bail!("Worker 名称或版本无效");
    }
    Ok(bounded_alias(&format!("v{version}"), worker))
}

pub fn pull_request_alias(worker: &str, number: u64) -> Result<String> {
    if !valid_name(worker) || number == 0 || number > 1_000_000_000 {
        bail!("Worker 名称或 Pull Request 编号无效");
    }
    Ok(bounded_alias(&format!("pr{number}"), worker))
}

pub fn commit_alias(worker: &str, commit: &str) -> Result<String> {
    if !valid_name(worker)
        || commit.len() != 40
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("Worker 名称或 Git 提交无效");
    }
    Ok(bounded_alias(&format!("git-{}", &commit[..12]), worker))
}

fn bounded_alias(prefix: &str, worker: &str) -> String {
    let raw = format!("{prefix}-{worker}");
    if raw.len() <= 63 {
        return raw;
    }
    let digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let available = 63usize.saturating_sub(prefix.len() + digest[..8].len() + 2);
    let mut end = available.min(worker.len());
    while !worker.is_char_boundary(end) {
        end -= 1;
    }
    format!("{prefix}-{}-{}", &worker[..end], &digest[..8])
}

pub fn prepare(
    node: &Node,
    manifest: WorkerManifest,
    source: PreviewSource,
    ttl_days: u16,
) -> Result<ResourceRecord> {
    if ttl_days == 0 || ttl_days > MAX_TTL_DAYS {
        bail!("预览保留天数必须在 1 至 {MAX_TTL_DAYS} 之间");
    }
    let alias = match &source {
        PreviewSource::Version { version } => version_alias(&manifest.name, *version)?,
        PreviewSource::PullRequest { number, .. } => pull_request_alias(&manifest.name, *number)?,
        PreviewSource::Commit { commit, .. } => commit_alias(&manifest.name, commit)?,
    };
    let domain = node
        .cfg
        .default_worker_domain()
        .context("创建预览前必须配置 ingress.default_domain")?;
    let now = now_ms();
    let spec = PreviewSpec {
        schema: PREVIEW_SCHEMA,
        worker: manifest.name.clone(),
        hostname: format!("{alias}.{domain}"),
        manifest,
        source,
        created_at_ms: now,
        expires_at_ms: now + u64::from(ttl_days) * 86_400_000,
    };
    spec.validate()?;
    resource::prepare(
        node,
        PREVIEW_KIND,
        alias,
        serde_json::to_value(spec)?,
        false,
    )
}

pub fn prepare_delete(node: &Node, alias: &str) -> Result<ResourceRecord> {
    let current = resource::head(node, PREVIEW_KIND, alias)
        .filter(|view| !view.resource.deleted)
        .context("未找到 Worker 预览")?;
    preview_spec(&current.resource)?;
    resource::prepare(node, PREVIEW_KIND, alias, serde_json::Value::Null, true)
}

pub fn preview_spec(record: &ResourceRecord) -> Result<PreviewSpec> {
    if record.kind != PREVIEW_KIND || record.deleted {
        bail!("平台资源不是可用的 Worker 预览");
    }
    let spec: PreviewSpec =
        serde_json::from_str(&record.spec_json).context("Worker 预览配置不是有效的 JSON")?;
    spec.validate()?;
    Ok(spec)
}

pub fn preview_records(node: &Node, worker: Option<&str>) -> Vec<(ResourceView, PreviewSpec)> {
    let mut previews = resource::heads(node, Some(PREVIEW_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| preview_spec(&view.resource).ok().map(|spec| (view, spec)))
        .filter(|(_, spec)| worker.is_none_or(|worker| spec.worker == worker))
        .collect::<Vec<_>>();
    previews.sort_by_key(|(_, spec)| std::cmp::Reverse(spec.created_at_ms));
    previews
}

pub fn active_previews(node: &Node) -> Vec<(ResourceView, PreviewSpec)> {
    let now = now_ms();
    preview_records(node, None)
        .into_iter()
        .filter(|(_, spec)| spec.active(now))
        .collect()
}

pub fn find_by_hostname(node: &Node, hostname: &str) -> Option<(ResourceView, PreviewSpec)> {
    active_previews(node)
        .into_iter()
        .find(|(_, spec)| spec.hostname == hostname)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use rf_core::envelope::Envelope;
    use rf_core::identity::{AnyKeypair, Keypair};
    use std::collections::BTreeMap;

    fn node(operator: &AnyKeypair) -> (Node, std::path::PathBuf) {
        let data_dir = std::env::temp_dir().join(format!(
            "rf-preview-{}-{}",
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
            [ingress]
            default_domain = "workers.example.com"
            "#,
            data_dir = data_dir.display(),
            operator = operator.signer_id(),
        ))
        .unwrap();
        (
            Node::open(cfg, Keypair::from_seed([72; 32])).unwrap(),
            data_dir,
        )
    }

    fn manifest(name: &str) -> WorkerManifest {
        WorkerManifest {
            name: name.into(),
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
        }
    }

    #[test]
    fn deterministic_aliases_are_bounded() {
        assert_eq!(version_alias("api", 7).unwrap(), "v7-api");
        assert_eq!(pull_request_alias("api", 42).unwrap(), "pr42-api");
        let long = "a".repeat(63);
        let alias = pull_request_alias(&long, 123456).unwrap();
        assert!(valid_name(&alias));
        assert!(alias.len() <= 63);
        assert_eq!(alias, pull_request_alias(&long, 123456).unwrap());
    }

    #[test]
    fn signed_preview_renews_then_tombstone_stops_it() {
        let operator = AnyKeypair::Ed(Keypair::from_seed([71; 32]));
        let (node, dir) = node(&operator);
        let first = prepare(
            &node,
            manifest("demo"),
            PreviewSource::Version { version: 1 },
            30,
        )
        .unwrap();
        let first_spec = preview_spec(&first).unwrap();
        assert_eq!(first.name, "v1-demo");
        assert_eq!(first_spec.hostname, "v1-demo.workers.example.com");
        resource::ingest(&node, &Envelope::seal_any(&first, &operator)).unwrap();
        assert_eq!(active_previews(&node).len(), 1);

        let renewed = prepare(
            &node,
            manifest("demo"),
            PreviewSource::Version { version: 1 },
            60,
        )
        .unwrap();
        assert_eq!(renewed.version, 2);
        resource::ingest(&node, &Envelope::seal_any(&renewed, &operator)).unwrap();
        let deleted = prepare_delete(&node, "v1-demo").unwrap();
        assert_eq!(deleted.version, 3);
        resource::ingest(&node, &Envelope::seal_any(&deleted, &operator)).unwrap();
        assert!(active_previews(&node).is_empty());

        drop(node);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expiry_is_enforced_without_a_cleanup_scheduler() {
        let operator = AnyKeypair::Ed(Keypair::from_seed([73; 32]));
        let (node, dir) = node(&operator);
        let now = now_ms();
        let spec = PreviewSpec {
            schema: PREVIEW_SCHEMA,
            worker: "demo".into(),
            hostname: "v1-demo.workers.example.com".into(),
            manifest: manifest("demo"),
            source: PreviewSource::Version { version: 1 },
            created_at_ms: now.saturating_sub(2),
            expires_at_ms: now.saturating_sub(1),
        };
        let record = resource::prepare_after(
            PREVIEW_KIND,
            "v1-demo",
            serde_json::to_value(spec).unwrap(),
            false,
            None,
        )
        .unwrap();
        resource::ingest(&node, &Envelope::seal_any(&record, &operator)).unwrap();
        assert_eq!(preview_records(&node, Some("demo")).len(), 1);
        assert!(active_previews(&node).is_empty());
        assert!(find_by_hostname(&node, "v1-demo.workers.example.com").is_none());

        drop(node);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
