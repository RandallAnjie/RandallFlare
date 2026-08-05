//! Operator-signed global defaults and content-addressed rclone sharding.
//!
//! A bucket opts into the `default` policy when it is created. The current
//! ordered shard set chooses the destination of each new immutable blob by
//! the first 32 bits of its SHA-256. Object metadata records the concrete
//! remote, so changing the shard set never strands or silently moves old data.

use crate::node::Node;
use crate::objectstore::StorageLocation;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use futures_util::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const STORAGE_POLICY_KIND: &str = "storage_policy";
pub const DEFAULT_POLICY_NAME: &str = "default";
pub const STORAGE_POLICY_SCHEMA: u8 = 1;
pub const MAX_SHARD_REMOTES: usize = 256;
pub const MAX_D1_BACKUP_POLICIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1BackupPolicy {
    pub database: String,
    pub bucket: String,
    #[serde(default = "default_d1_backup_prefix")]
    pub prefix: String,
    #[serde(default = "default_d1_backup_interval_hours")]
    pub interval_hours: u16,
    #[serde(default = "default_d1_backup_retention_days")]
    pub retention_days: u16,
    #[serde(default)]
    pub suspended: bool,
}

fn default_d1_backup_prefix() -> String {
    "d1-backups".into()
}

fn default_d1_backup_interval_hours() -> u16 {
    24
}

fn default_d1_backup_retention_days() -> u16 {
    30
}

impl D1BackupPolicy {
    fn validate(&self) -> Result<()> {
        if !rf_core::manifest::valid_name(&self.database)
            || !rf_core::manifest::valid_name(&self.bucket)
        {
            bail!("D1 备份策略中的数据库或 R2 bucket 名称无效");
        }
        crate::objectstore::validate_prefix(&self.prefix)?;
        if !(1..=720).contains(&self.interval_hours) {
            bail!("D1 自动备份间隔必须介于 1 和 720 小时之间");
        }
        if !(1..=3650).contains(&self.retention_days) {
            bail!("D1 备份保留期必须介于 1 和 3650 天之间");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NewBucketBackend {
    Local,
    RcloneSharded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicy {
    pub schema: u8,
    pub new_bucket_backend: NewBucketBackend,
    #[serde(default)]
    pub shard_remotes: Vec<String>,
    #[serde(default)]
    pub shard_prefix: String,
    #[serde(default)]
    pub d1_backups: Vec<D1BackupPolicy>,
}

impl Default for StoragePolicy {
    fn default() -> Self {
        Self {
            schema: STORAGE_POLICY_SCHEMA,
            new_bucket_backend: NewBucketBackend::Local,
            shard_remotes: Vec::new(),
            shard_prefix: String::new(),
            d1_backups: Vec::new(),
        }
    }
}

impl StoragePolicy {
    pub fn validate(&self) -> Result<()> {
        if self.schema != STORAGE_POLICY_SCHEMA {
            bail!("不支持此版本的存储策略");
        }
        if self.shard_remotes.len() > MAX_SHARD_REMOTES {
            bail!("rclone 分片 remote 最多 {MAX_SHARD_REMOTES} 个");
        }
        let mut unique = HashSet::new();
        for remote in &self.shard_remotes {
            if !crate::objectstore::valid_remote(remote) {
                bail!("rclone 分片 remote 名称无效：{remote}");
            }
            if !unique.insert(remote) {
                bail!("rclone 分片 remote 不能重复：{remote}");
            }
        }
        crate::objectstore::validate_prefix(&self.shard_prefix)?;
        if self.d1_backups.len() > MAX_D1_BACKUP_POLICIES {
            bail!("D1 自动备份策略最多 {MAX_D1_BACKUP_POLICIES} 条");
        }
        let mut backup_databases = HashSet::new();
        for backup in &self.d1_backups {
            backup.validate()?;
            if !backup_databases.insert(&backup.database) {
                bail!(
                    "每个 D1 数据库只能配置一条自动备份策略：{}",
                    backup.database
                );
            }
        }
        if self.new_bucket_backend == NewBucketBackend::RcloneSharded
            && self.shard_remotes.is_empty()
        {
            bail!("新 bucket 使用 rclone 分片时至少需要一个 remote");
        }
        Ok(())
    }
}

pub fn policy_spec(record: &ResourceRecord) -> Result<StoragePolicy> {
    if record.kind != STORAGE_POLICY_KIND || record.deleted || record.name != DEFAULT_POLICY_NAME {
        bail!("平台资源不是可用的默认存储策略");
    }
    let policy: StoragePolicy = serde_json::from_value(record.spec()?)?;
    policy.validate()?;
    Ok(policy)
}

pub fn current(node: &Node) -> Result<(Option<ResourceView>, StoragePolicy)> {
    let Some(view) = resource::head(node, STORAGE_POLICY_KIND, DEFAULT_POLICY_NAME) else {
        return Ok((None, StoragePolicy::default()));
    };
    if view.resource.deleted {
        return Ok((Some(view), StoragePolicy::default()));
    }
    let policy =
        policy_spec(&view.resource).context("签名存储策略无效；为安全起见拒绝使用 rclone 分片")?;
    Ok((Some(view), policy))
}

pub fn prepare_after(
    mut policy: StoragePolicy,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    policy.shard_remotes = policy
        .shard_remotes
        .into_iter()
        .map(|remote| remote.trim().to_string())
        .filter(|remote| !remote.is_empty())
        .collect();
    policy.shard_prefix = policy.shard_prefix.trim_matches('/').to_string();
    for backup in &mut policy.d1_backups {
        backup.database = backup.database.trim().to_ascii_lowercase();
        backup.bucket = backup.bucket.trim().to_ascii_lowercase();
        backup.prefix = backup.prefix.trim_matches('/').to_string();
    }
    policy
        .d1_backups
        .sort_by(|left, right| left.database.cmp(&right.database));
    policy.validate()?;
    resource::prepare_after(
        STORAGE_POLICY_KIND,
        DEFAULT_POLICY_NAME,
        serde_json::to_value(policy)?,
        false,
        head,
    )
}

pub fn validate_admission(node: &Node, record: &ResourceRecord) -> Result<()> {
    if record.kind != STORAGE_POLICY_KIND {
        return Ok(());
    }
    let referenced = crate::r2::bucket_records(node)
        .iter()
        .any(|(_, spec)| spec.storage_policy.as_deref() == Some(DEFAULT_POLICY_NAME));
    if record.deleted {
        if referenced {
            bail!("仍有 R2 bucket 使用默认分片策略，不能删除存储策略");
        }
        return Ok(());
    }
    let policy = policy_spec(record)?;
    if policy.shard_remotes.is_empty() && referenced {
        bail!("仍有 R2 bucket 使用默认分片策略，不能清空全部 remote");
    }
    Ok(())
}

/// Validate changes that require consulting live R2 metadata. This runs at
/// the authenticated resource-ingress boundary before the signed record is
/// accepted. Removing a remote that still owns pinned objects would make an
/// operator's later rclone decommission destructive, so fail closed until
/// those objects have been deleted or explicitly copied elsewhere.
pub async fn validate_transition(node: &Node, record: &ResourceRecord) -> Result<()> {
    validate_admission(node, record)?;
    if record.kind != STORAGE_POLICY_KIND || record.deleted {
        return Ok(());
    }
    let next = policy_spec(record)?;
    let databases = crate::d1::database_names(node);
    for backup in &next.d1_backups {
        if !databases.contains(&backup.database) {
            bail!("D1 自动备份策略引用了不存在的数据库：{}", backup.database);
        }
        if crate::r2::bucket_record(node, &backup.bucket).is_none() {
            bail!("D1 自动备份策略引用了不存在的 R2 bucket：{}", backup.bucket);
        }
    }
    let (_, current) = current(node)?;
    let removed = current
        .shard_remotes
        .iter()
        .filter(|remote| !next.shard_remotes.contains(remote))
        .cloned()
        .collect::<HashSet<_>>();
    if removed.is_empty() {
        return Ok(());
    }
    let references = crate::r2::shard_references(node)
        .await
        .context("无法确认待移除 remote 是否仍保存对象；拒绝修改存储策略")?;
    let mut in_use = references
        .into_iter()
        .filter(|(remote, references)| removed.contains(remote) && *references > 0)
        .collect::<Vec<_>>();
    in_use.sort_by(|left, right| left.0.cmp(&right.0));
    if !in_use.is_empty() {
        let detail = in_use
            .into_iter()
            .map(|(remote, references)| format!("{remote}（{references} 条对象/分片引用）"))
            .collect::<Vec<_>>()
            .join("、");
        bail!("以下 remote 仍保存被元数据固定的对象，不能从策略移除：{detail}");
    }
    Ok(())
}

pub fn shard_index(sha: &[u8; 32], remote_count: usize) -> Option<usize> {
    if remote_count == 0 {
        return None;
    }
    let value = u32::from_be_bytes(sha[..4].try_into().expect("SHA prefix"));
    Some(value as usize % remote_count)
}

pub fn resolve(node: &Node, policy_name: &str, sha: &[u8; 32]) -> Result<StorageLocation> {
    if policy_name != DEFAULT_POLICY_NAME {
        bail!("未知存储策略：{policy_name}");
    }
    let (_, policy) = current(node)?;
    let index = shard_index(sha, policy.shard_remotes.len())
        .context("存储策略没有可用的 rclone 分片 remote")?;
    Ok(StorageLocation::RcloneShard {
        remote: policy.shard_remotes[index].clone(),
        prefix: policy.shard_prefix,
    })
}

pub fn default_bucket_policy(node: &Node) -> Result<Option<String>> {
    let (_, policy) = current(node)?;
    Ok(
        (policy.new_bucket_backend == NewBucketBackend::RcloneSharded)
            .then(|| DEFAULT_POLICY_NAME.to_string()),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProbe {
    pub remote: String,
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn probe_remotes(node: &Node, policy: &StoragePolicy) -> Vec<RemoteProbe> {
    let mut probes: Vec<(usize, RemoteProbe)> =
        stream::iter(policy.shard_remotes.iter().cloned().enumerate().map(
            |(index, remote)| async move {
                let probe = match node.objects.probe(&remote, &policy.shard_prefix).await {
                    Ok(()) => RemoteProbe {
                        remote,
                        reachable: true,
                        error: None,
                    },
                    Err(error) => RemoteProbe {
                        remote,
                        reachable: false,
                        error: Some(bounded_error(&error)),
                    },
                };
                (index, probe)
            },
        ))
        // A broken remote must not make an operator wait through every rclone
        // timeout serially. Keep the fan-out bounded so a large policy cannot
        // exhaust file descriptors or child-process slots on the node.
        .buffer_unordered(8)
        .collect()
        .await;
    probes.sort_by_key(|(index, _)| *index);
    probes.into_iter().map(|(_, probe)| probe).collect()
}

fn bounded_error(error: &anyhow::Error) -> String {
    const MAX_CHARS: usize = 1_024;
    let rendered = format!("{error:#}");
    let mut chars = rendered.chars();
    let brief: String = chars.by_ref().take(MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{brief}…")
    } else {
        brief
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_shards_match_first_u32_modulo() {
        let mut sha = [0u8; 32];
        sha[..4].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(shard_index(&sha, 4), Some(1));
        assert_eq!(shard_index(&sha, 0), None);
        assert_eq!(shard_index(&sha, 1), Some(0));
    }

    #[test]
    fn policy_rejects_duplicates_and_empty_sharded_default() {
        let mut policy = StoragePolicy {
            schema: STORAGE_POLICY_SCHEMA,
            new_bucket_backend: NewBucketBackend::RcloneSharded,
            shard_remotes: vec!["drive-00".into()],
            shard_prefix: String::new(),
            d1_backups: Vec::new(),
        };
        policy.validate().unwrap();
        policy.shard_remotes.push("drive-00".into());
        assert!(policy.validate().is_err());
        policy.shard_remotes.clear();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn backup_policies_are_bounded_and_unique_per_database() {
        let backup = D1BackupPolicy {
            database: "appdb".into(),
            bucket: "backups".into(),
            prefix: "d1".into(),
            interval_hours: 24,
            retention_days: 30,
            suspended: false,
        };
        let mut policy = StoragePolicy {
            d1_backups: vec![backup.clone()],
            ..Default::default()
        };
        policy.validate().unwrap();
        policy.d1_backups.push(backup);
        assert!(policy.validate().is_err());
        policy.d1_backups[1].database = "other".into();
        policy.d1_backups[1].interval_hours = 0;
        assert!(policy.validate().is_err());
    }
}
