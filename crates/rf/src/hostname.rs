//! Operator-signed DNS ownership claims shared by every public service.
//!
//! A resource may declare a custom hostname before DNS is ready, but ingress
//! and ACME only see it after the matching claim has been verified. Default
//! hostnames derived from the node configuration never require a claim.

use crate::node::{now_ms, Node};
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use mail_auth::hickory_resolver::proto::rr::RData;
use mail_auth::MessageAuthenticator;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const HOSTNAME_CLAIM_KIND: &str = "hostname_claim";
pub const TXT_PREFIX: &str = "_randallflare-verify";
pub const VALUE_PREFIX: &str = "rf-hostname-verification=";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostnameClaimSpec {
    pub hostname: String,
    pub challenge: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub verified_at_ms: Option<u64>,
}

impl HostnameClaimSpec {
    pub fn validate(&self) -> Result<()> {
        if !rf_core::manifest::valid_hostname(&self.hostname) {
            bail!("自定义域名必须是有效的小写 DNS 主机名");
        }
        if self.challenge.len() < 24
            || self.challenge.len() > 192
            || !self
                .challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("域名所有权验证码无效");
        }
        if self.created_at_ms == 0 {
            bail!("域名所有权声明缺少创建时间");
        }
        if self
            .verified_at_ms
            .is_some_and(|verified| verified < self.created_at_ms)
        {
            bail!("域名验证时间早于声明创建时间");
        }
        Ok(())
    }

    pub fn txt_name(&self) -> String {
        format!("{TXT_PREFIX}.{}", self.hostname)
    }

    pub fn txt_value(&self) -> String {
        format!("{VALUE_PREFIX}{}", self.challenge)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostnameVerification {
    pub hostname: String,
    pub txt_name: String,
    pub txt_value: String,
    pub observed: Vec<String>,
    pub verified: bool,
    pub checked_at_ms: u64,
}

pub fn claim_name(hostname: &str) -> String {
    let digest = Sha256::digest(hostname.as_bytes());
    format!("host-{}", &hex::encode(digest)[..40])
}

pub fn generate_challenge() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn prepare_claim_after(
    hostname: &str,
    existing: Option<HostnameClaimSpec>,
    verified_at_ms: Option<u64>,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let mut spec = existing.unwrap_or_else(|| HostnameClaimSpec {
        hostname: hostname.clone(),
        challenge: generate_challenge(),
        created_at_ms: now_ms(),
        verified_at_ms: None,
    });
    if spec.hostname != hostname {
        bail!("域名所有权声明与资源名称不匹配");
    }
    spec.verified_at_ms = verified_at_ms;
    spec.validate()?;
    resource::prepare_after(
        HOSTNAME_CLAIM_KIND,
        claim_name(&hostname),
        json!(spec),
        deleted,
        head,
    )
}

pub fn claim_spec(record: &ResourceRecord) -> Result<HostnameClaimSpec> {
    if record.kind != HOSTNAME_CLAIM_KIND || record.deleted {
        bail!("平台资源不是有效的域名所有权声明");
    }
    let spec: HostnameClaimSpec =
        serde_json::from_str(&record.spec_json).context("域名所有权声明配置无效")?;
    spec.validate()?;
    if record.name != claim_name(&spec.hostname) {
        bail!("域名所有权声明名称与域名不匹配");
    }
    Ok(spec)
}

pub fn claim(node: &Node, hostname: &str) -> Option<(ResourceView, HostnameClaimSpec)> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let view = resource::head(node, HOSTNAME_CLAIM_KIND, &claim_name(&hostname))?;
    let spec = claim_spec(&view.resource).ok()?;
    (spec.hostname == hostname).then_some((view, spec))
}

pub fn claims(node: &Node) -> Vec<(ResourceView, HostnameClaimSpec)> {
    resource::heads(node, Some(HOSTNAME_CLAIM_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| claim_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn is_verified(node: &Node, hostname: &str) -> bool {
    node.verified_custom_hostnames().contains(hostname)
}

pub async fn query_verification(spec: &HostnameClaimSpec) -> Result<HostnameVerification> {
    spec.validate()?;
    let resolver = MessageAuthenticator::new_system_conf().context("无法读取系统 DNS 配置")?;
    let response = resolver
        .0
        .txt_lookup(spec.txt_name())
        .await
        .with_context(|| format!("查询 TXT 记录失败：{}", spec.txt_name()))?;
    let mut observed: Vec<String> = response
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect();
    observed.sort();
    observed.dedup();
    let txt_value = spec.txt_value();
    Ok(HostnameVerification {
        hostname: spec.hostname.clone(),
        txt_name: spec.txt_name(),
        verified: observed.iter().any(|value| value == &txt_value),
        txt_value,
        observed,
        checked_at_ms: now_ms(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_names_are_deterministic_and_specs_are_strict() {
        assert_eq!(claim_name("api.example.com"), claim_name("api.example.com"));
        assert_ne!(claim_name("api.example.com"), claim_name("www.example.com"));
        let record = prepare_claim_after("API.Example.COM.", None, None, false, None).unwrap();
        let spec = claim_spec(&record).unwrap();
        assert_eq!(spec.hostname, "api.example.com");
        assert_eq!(spec.challenge.len(), 32);
        assert_eq!(spec.txt_name(), "_randallflare-verify.api.example.com");
        assert!(spec.txt_value().starts_with("rf-hostname-verification="));
    }

    #[test]
    fn a_verified_successor_keeps_the_original_challenge() {
        let first = prepare_claim_after("api.example.com", None, None, false, None).unwrap();
        let first_spec = claim_spec(&first).unwrap();
        let head = ResourceView {
            resource: first,
            digest: hex::encode([7u8; 32]),
        };
        let second = prepare_claim_after(
            "api.example.com",
            Some(first_spec.clone()),
            Some(first_spec.created_at_ms + 1),
            false,
            Some(&head),
        )
        .unwrap();
        let second_spec = claim_spec(&second).unwrap();
        assert_eq!(second.version, 2);
        assert_eq!(second_spec.challenge, first_spec.challenge);
        assert!(second_spec.verified_at_ms.is_some());
    }
}
