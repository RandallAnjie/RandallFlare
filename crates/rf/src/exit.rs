//! Operator-signed split-routing rules and one-way device enrollment tokens.
//!
//! Devices are deliberately not cluster members: they never receive the
//! cluster secret, Worker manifests, or data-plane credentials. A device owns
//! one random bearer token whose SHA-256 is operator-signed. Any public node
//! can authenticate it and derive the same rule/exit view without an account
//! database or central control plane.

use crate::node::{now_ms, Node};
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

pub const EXIT_RULE_KIND: &str = "exit_rule";
pub const DEVICE_KIND: &str = "client_device";
pub const EXIT_RULE_SCHEMA: u8 = 1;
pub const DEVICE_SCHEMA: u8 = 1;
pub const DEVICE_TOKEN_PREFIX: &str = "rfd_";
const DEVICE_DISPLAY_PREFIX_LEN: usize = 12;
const MAX_RULE_CONFIG_BYTES: usize = 200_000;
const MAX_PROVIDER_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDERS: usize = 64;
const MAX_TOTAL_PROVIDER_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleFormat {
    Auto,
    Surge,
    Clash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExitTarget {
    Direct,
    Reject,
    Nearest,
    Node { node_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitRuleSpec {
    pub schema: u8,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    pub format: RuleFormat,
    pub config: String,
    /// Immutable snapshots for RULE-SET URLs and `geoip:CC` sources. Keeping
    /// them inside the signed record prevents wall-side devices from fetching
    /// mutable lists from GitHub and makes every node compile identical rules.
    #[serde(default)]
    pub providers: BTreeMap<String, String>,
    #[serde(default)]
    pub policy_exits: BTreeMap<String, ExitTarget>,
}

fn default_true() -> bool {
    true
}

impl ExitRuleSpec {
    pub fn validate(&self) -> Result<()> {
        if self.schema != EXIT_RULE_SCHEMA {
            bail!("不支持此版本的出口规则");
        }
        if self.description.len() > 1_000 || self.description.contains(['\r', '\0']) {
            bail!("出口规则说明不得超过 1000 个字符");
        }
        if self.config.len() > MAX_RULE_CONFIG_BYTES || self.config.contains('\0') {
            bail!("出口规则配置不得超过 200000 字节");
        }
        if self.providers.len() > MAX_PROVIDERS {
            bail!("出口规则最多包含 {MAX_PROVIDERS} 个签名规则集快照");
        }
        let mut provider_bytes = 0usize;
        for (source, content) in &self.providers {
            if !valid_provider_name(source) {
                bail!("规则集来源无效：{source}");
            }
            if content.len() > MAX_PROVIDER_BYTES || content.contains('\0') {
                bail!("单个规则集快照不得超过 2 MiB：{source}");
            }
            provider_bytes = provider_bytes.saturating_add(content.len());
        }
        if provider_bytes > MAX_TOTAL_PROVIDER_BYTES {
            bail!("规则集快照合计不得超过 8 MiB");
        }
        if self.policy_exits.len() > 256 {
            bail!("出口规则最多绑定 256 个策略");
        }
        for (policy, target) in &self.policy_exits {
            if policy.trim().is_empty() || policy.len() > 200 || policy.contains(['\r', '\n', '\0'])
            {
                bail!("出口策略名称无效");
            }
            if let ExitTarget::Node { node_id } = target {
                node_id
                    .parse::<rf_core::identity::PublicId>()
                    .map_err(|error| anyhow::anyhow!("出口节点身份无效：{node_id}：{error}"))?;
            }
        }
        for rule in compile(self)? {
            let policy = rule.policy.to_ascii_uppercase();
            if policy != "DIRECT"
                && policy != "REJECT"
                && !policy.starts_with("REJECT-")
                && !self.policy_exits.contains_key(&rule.policy)
            {
                bail!(
                    "出口策略 {0} 没有绑定 direct、reject、nearest 或具体节点",
                    rule.policy
                );
            }
        }
        Ok(())
    }
}

fn valid_provider_name(value: &str) -> bool {
    if let Some(code) = value.strip_prefix("geoip:") {
        return code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_alphabetic());
    }
    value.starts_with("https://")
        && value.len() <= 2_048
        && !value.contains(['\r', '\n', '\0', ' '])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSpec {
    pub schema: u8,
    pub label: String,
    pub token_prefix: String,
    pub token_sha256: String,
    #[serde(default)]
    pub allowed_rules: Vec<String>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub revoked_at_ms: Option<u64>,
    #[serde(default)]
    pub suspended: bool,
}

impl DeviceSpec {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DEVICE_SCHEMA {
            bail!("不支持此版本的客户端设备");
        }
        if self.label.trim().is_empty()
            || self.label.len() > 80
            || self.label.contains(['\r', '\n', '\0'])
        {
            bail!("设备名称必须为 1 至 80 个字符");
        }
        if self.token_prefix.len() != DEVICE_DISPLAY_PREFIX_LEN
            || !self.token_prefix.starts_with(DEVICE_TOKEN_PREFIX)
            || !self
                .token_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            bail!("设备令牌显示前缀无效");
        }
        if self.token_sha256.len() != 64
            || !self
                .token_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("设备令牌摘要无效");
        }
        if self.allowed_rules.is_empty() || self.allowed_rules.len() > 50 {
            bail!("一台设备必须选择 1 至 50 条出口规则");
        }
        let unique = self.allowed_rules.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.allowed_rules.len()
            || self
                .allowed_rules
                .iter()
                .any(|name| !rf_core::manifest::valid_name(name))
        {
            bail!("设备出口规则包含重复或无效名称");
        }
        if self.created_at_ms == 0
            || self
                .expires_at_ms
                .is_some_and(|expires| expires <= self.created_at_ms)
            || self
                .revoked_at_ms
                .is_some_and(|revoked| revoked < self.created_at_ms)
        {
            bail!("设备令牌时间范围无效");
        }
        Ok(())
    }

    pub fn active(&self, at_ms: u64) -> bool {
        !self.suspended
            && self.revoked_at_ms.is_none()
            && self.expires_at_ms.is_none_or(|expires| expires > at_ms)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub name: String,
    pub version: u64,
    pub digest: String,
    pub label: String,
    pub token_prefix: String,
    pub allowed_rules: Vec<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub revoked_at_ms: Option<u64>,
    pub suspended: bool,
    pub rules_ready: bool,
    pub active: bool,
    pub last_used_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DevicePrincipal {
    pub name: String,
    pub spec: DeviceSpec,
}

pub fn exit_rule_spec(record: &ResourceRecord) -> Result<ExitRuleSpec> {
    if record.kind != EXIT_RULE_KIND || record.deleted {
        bail!("平台资源不是可用的出口规则");
    }
    let spec: ExitRuleSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn device_spec(record: &ResourceRecord) -> Result<DeviceSpec> {
    if record.kind != DEVICE_KIND || record.deleted {
        bail!("平台资源不是可用的客户端设备");
    }
    let spec: DeviceSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn rule_records(node: &Node) -> Vec<(ResourceView, ExitRuleSpec)> {
    let mut rules = resource::heads(node, Some(EXIT_RULE_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = exit_rule_spec(&view.resource).ok()?;
            Some((view, spec))
        })
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        (left.1.priority, &left.0.resource.name).cmp(&(right.1.priority, &right.0.resource.name))
    });
    rules
}

pub fn device_views(node: &Node) -> Vec<DeviceView> {
    let now = now_ms();
    let mut views = resource::heads(node, Some(DEVICE_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = device_spec(&view.resource).ok()?;
            let name = view.resource.name.clone();
            let rules_ready = validate_device_rules(node, &spec).is_ok();
            let active = spec.active(now) && rules_ready;
            let last_used_at_ms = node
                .store
                .credential_last_used(&format!("device/{name}"))
                .ok()
                .flatten();
            Some(DeviceView {
                name,
                version: view.resource.version,
                digest: view.digest,
                label: spec.label,
                token_prefix: spec.token_prefix,
                allowed_rules: spec.allowed_rules,
                created_at_ms: spec.created_at_ms,
                expires_at_ms: spec.expires_at_ms,
                revoked_at_ms: spec.revoked_at_ms,
                suspended: spec.suspended,
                rules_ready,
                active,
                last_used_at_ms,
            })
        })
        .collect::<Vec<_>>();
    views.sort_by(|left, right| left.name.cmp(&right.name));
    views
}

pub fn mint_device(
    node: &Node,
    name: &str,
    label: String,
    allowed_rules: Vec<String>,
    expires_at_ms: Option<u64>,
) -> Result<(ResourceRecord, String)> {
    if resource::head(node, DEVICE_KIND, name).is_some() {
        bail!("设备 {name} 已存在");
    }
    let (record, raw) = mint_device_record(name, label, allowed_rules, expires_at_ms)?;
    let spec = device_spec(&record)?;
    validate_device_rules(node, &spec)?;
    Ok((record, raw))
}

/// Prepare a new one-way device credential without requiring a local node.
/// Admission on the receiving node still verifies all referenced signed rules.
pub fn mint_device_record(
    name: &str,
    label: String,
    allowed_rules: Vec<String>,
    expires_at_ms: Option<u64>,
) -> Result<(ResourceRecord, String)> {
    let raw = format!(
        "{DEVICE_TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    );
    let spec = DeviceSpec {
        schema: DEVICE_SCHEMA,
        label: label.trim().to_string(),
        token_prefix: raw[..DEVICE_DISPLAY_PREFIX_LEN].to_string(),
        token_sha256: hex::encode(Sha256::digest(raw.as_bytes())),
        allowed_rules,
        created_at_ms: now_ms(),
        expires_at_ms,
        revoked_at_ms: None,
        suspended: false,
    };
    spec.validate()?;
    let record =
        resource::prepare_after(DEVICE_KIND, name, serde_json::to_value(spec)?, false, None)?;
    Ok((record, raw))
}

pub fn update_device_after(
    node: &Node,
    name: &str,
    mut spec: DeviceSpec,
    head: &ResourceView,
) -> Result<ResourceRecord> {
    spec.label = spec.label.trim().to_string();
    spec.validate()?;
    validate_device_rules(node, &spec)?;
    resource::prepare_after(
        DEVICE_KIND,
        name,
        serde_json::to_value(spec)?,
        false,
        Some(head),
    )
}

fn validate_device_rules(node: &Node, spec: &DeviceSpec) -> Result<()> {
    for name in &spec.allowed_rules {
        if resource::head(node, EXIT_RULE_KIND, name)
            .is_none_or(|view| view.resource.deleted || exit_rule_spec(&view.resource).is_err())
        {
            bail!("设备引用的出口规则不存在：{name}");
        }
    }
    Ok(())
}

pub fn resolve_device(node: &Node, name: &str, raw: &str) -> Option<DevicePrincipal> {
    if !rf_core::manifest::valid_name(name)
        || !raw.starts_with(DEVICE_TOKEN_PREFIX)
        || raw.len() != DEVICE_TOKEN_PREFIX.len() + 43
    {
        return None;
    }
    let view = resource::head(node, DEVICE_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = device_spec(&view.resource).ok()?;
    validate_device_rules(node, &spec).ok()?;
    if spec.token_prefix != raw.get(..DEVICE_DISPLAY_PREFIX_LEN)? || !spec.active(now_ms()) {
        return None;
    }
    let candidate: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let expected = hex::decode(&spec.token_sha256).ok()?;
    if !constant_time_eq(&candidate, &expected) {
        return None;
    }
    let _ = node
        .store
        .touch_credential(&format!("device/{name}"), now_ms());
    Some(DevicePrincipal {
        name: name.to_string(),
        spec,
    })
}

pub fn validate_admission(node: &Node, record: &ResourceRecord) -> Result<()> {
    match record.kind.as_str() {
        EXIT_RULE_KIND => {
            if record.deleted {
                let referenced = device_views(node)
                    .iter()
                    .any(|device| device.allowed_rules.iter().any(|name| name == &record.name));
                if referenced {
                    bail!("仍有客户端设备引用此出口规则，不能删除");
                }
            } else {
                exit_rule_spec(record)?;
            }
        }
        DEVICE_KIND if !record.deleted => {
            let spec = device_spec(record)?;
            validate_device_rules(node, &spec)?;
        }
        _ => {}
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(IpCidr),
    MatchAll,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    pub matcher: RuleMatcher,
    pub policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').context("CIDR 缺少前缀长度")?;
        let address: IpAddr = address.parse().context("CIDR 地址无效")?;
        let prefix: u8 = prefix.parse().context("CIDR 前缀长度无效")?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("CIDR 前缀长度无效");
        }
        let network = mask_ip(address, prefix);
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        std::mem::discriminant(&self.network) == std::mem::discriminant(&address)
            && mask_ip(address, self.prefix) == self.network
    }
}

fn mask_ip(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(address) => {
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6((bits & mask).into())
        }
    }
}

pub fn compile(spec: &ExitRuleSpec) -> Result<Vec<CompiledRule>> {
    let clash = spec.format == RuleFormat::Clash
        || (spec.format == RuleFormat::Auto
            && (spec.config.contains("payload:")
                || spec.config.contains("\nrules:")
                || spec.config.trim_start().starts_with("rules:")));
    let mut rules = Vec::new();
    if clash {
        let lines = clash_rule_lines(&spec.config)?;
        for line in lines {
            parse_rule_line(&line, None, spec, &mut rules)?;
        }
    } else {
        for raw in spec.config.lines() {
            let Some(line) = normalized_line(raw, false) else {
                continue;
            };
            parse_rule_line(&line, None, spec, &mut rules)?;
        }
    }
    if rules.len() > 200_000 {
        bail!("展开后的出口规则不得超过 200000 条");
    }
    Ok(rules)
}

fn clash_rule_lines(config: &str) -> Result<Vec<String>> {
    let mut section = None;
    let mut output = Vec::new();
    for raw in config.lines() {
        let without_comment = strip_comment(raw);
        let trimmed = without_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        if section.is_none() {
            if matches!(trimmed, "rules:" | "payload:") {
                section = Some(raw.len() - raw.trim_start().len());
            }
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent <= section.unwrap_or_default()
            && !trimmed.starts_with('-')
            && trimmed.ends_with(':')
        {
            break;
        }
        let Some(item) = trimmed.strip_prefix('-') else {
            continue;
        };
        let item = item.trim().trim_matches(['\'', '"']).trim();
        if !item.is_empty() {
            output.push(item.to_string());
        }
    }
    if section.is_none() {
        bail!("Clash 配置缺少 rules: 或 payload: 段");
    }
    Ok(output)
}

fn normalized_line(raw: &str, clash: bool) -> Option<String> {
    let mut line = strip_comment(raw).trim().to_string();
    if line.is_empty() {
        return None;
    }
    if clash {
        let trimmed = line.trim();
        let item = trimmed.strip_prefix("- ")?;
        line = item.trim().trim_matches(['\'', '"']).to_string();
    }
    (!line.is_empty()).then_some(line)
}

fn strip_comment(value: &str) -> &str {
    let mut end = value.len();
    let bytes = value.as_bytes();
    for index in 0..bytes.len().saturating_sub(1) {
        if bytes[index] == b'/'
            && bytes[index + 1] == b'/'
            && (index == 0 || bytes[index - 1] != b':')
        {
            end = end.min(index);
            break;
        }
    }
    if let Some(index) = value[..end].find('#') {
        end = end.min(index);
    }
    &value[..end]
}

fn parse_rule_line(
    line: &str,
    inherited_policy: Option<&str>,
    spec: &ExitRuleSpec,
    output: &mut Vec<CompiledRule>,
) -> Result<()> {
    if !line.contains(',') {
        let policy = inherited_policy.context("裸规则只能出现在 RULE-SET 快照中")?;
        let matcher = if let Ok(cidr) = IpCidr::parse(line) {
            RuleMatcher::IpCidr(cidr)
        } else if let Some(suffix) = line.strip_prefix("+.").or_else(|| line.strip_prefix('.')) {
            RuleMatcher::DomainSuffix(normalize_host(suffix)?)
        } else {
            RuleMatcher::Domain(normalize_host(line)?)
        };
        output.push(CompiledRule {
            matcher,
            policy: policy.to_string(),
        });
        return Ok(());
    }
    let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
    let kind = parts
        .first()
        .copied()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let value = parts.get(1).copied().unwrap_or_default();
    let policy = parts
        .iter()
        .skip(2)
        .find(|part| !part.is_empty() && !part.eq_ignore_ascii_case("no-resolve"))
        .copied()
        .or(inherited_policy)
        .unwrap_or_default();
    if kind == "RULE-SET" {
        if policy.is_empty() {
            bail!("RULE-SET 缺少策略名称");
        }
        let content = spec
            .providers
            .get(value)
            .with_context(|| format!("RULE-SET 缺少签名快照：{value}"))?;
        let provider_lines = if content.lines().any(|line| line.trim() == "payload:") {
            clash_rule_lines(content)?
        } else {
            content
                .lines()
                .filter_map(|raw| {
                    let line = strip_comment(raw).trim();
                    (!line.is_empty()).then(|| line.to_string())
                })
                .collect()
        };
        for line in provider_lines {
            parse_rule_line(&line, Some(policy), spec, output)?;
        }
        return Ok(());
    }
    if kind == "GEOIP" {
        if policy.is_empty() {
            bail!("GEOIP 规则缺少策略名称");
        }
        let key = format!("geoip:{}", value.to_ascii_uppercase());
        let content = spec
            .providers
            .get(&key)
            .with_context(|| format!("GEOIP 缺少签名 CIDR 快照：{key}"))?;
        for raw in content.lines() {
            let cidr = strip_comment(raw).trim();
            if cidr.is_empty() {
                continue;
            }
            output.push(CompiledRule {
                matcher: RuleMatcher::IpCidr(IpCidr::parse(cidr)?),
                policy: policy.to_string(),
            });
        }
        return Ok(());
    }
    if matches!(kind.as_str(), "FINAL" | "MATCH") {
        let policy = parts.get(1).copied().unwrap_or_default();
        if policy.is_empty() {
            bail!("FINAL/MATCH 缺少策略名称");
        }
        output.push(CompiledRule {
            matcher: RuleMatcher::MatchAll,
            policy: policy.to_string(),
        });
        return Ok(());
    }
    if policy.is_empty() {
        bail!("出口规则缺少策略名称：{line}");
    }
    let matcher = match kind.as_str() {
        "DOMAIN" => RuleMatcher::Domain(normalize_host(value)?),
        "DOMAIN-SUFFIX" => RuleMatcher::DomainSuffix(normalize_host(value)?),
        "DOMAIN-KEYWORD" => {
            if value.is_empty() || value.len() > 253 {
                bail!("DOMAIN-KEYWORD 值无效");
            }
            RuleMatcher::DomainKeyword(value.to_ascii_lowercase())
        }
        "IP-CIDR" | "IP-CIDR6" => RuleMatcher::IpCidr(IpCidr::parse(value)?),
        // Unsupported process/UA/regex rules are ignored exactly like the
        // reference agent; they cannot accidentally become a catch-all.
        _ => return Ok(()),
    };
    output.push(CompiledRule {
        matcher,
        policy: policy.to_string(),
    });
    Ok(())
}

fn normalize_host(value: &str) -> Result<String> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        bail!("域名规则无效：{value}");
    }
    Ok(host)
}

pub fn extract_policies(spec: &ExitRuleSpec) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut policies = Vec::new();
    for rule in compile(spec)? {
        let upper = rule.policy.to_ascii_uppercase();
        if upper == "DIRECT" || upper == "REJECT" || upper.starts_with("REJECT-") {
            continue;
        }
        if seen.insert(rule.policy.clone()) {
            policies.push(rule.policy);
        }
    }
    Ok(policies)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Direct,
    Reject,
    Nearest,
    Node(String),
}

#[derive(Debug, Clone)]
struct RuleRef {
    index: usize,
    policy: String,
}

#[derive(Debug)]
struct IndexedMatcher {
    rule_count: usize,
    exact: HashMap<String, RuleRef>,
    suffix: HashMap<String, RuleRef>,
    keywords: Vec<(String, RuleRef)>,
    cidrs: Vec<(IpCidr, RuleRef)>,
    match_all: Option<RuleRef>,
}

impl IndexedMatcher {
    fn build(rules: Vec<CompiledRule>) -> Self {
        let rule_count = rules.len();
        let mut matcher = Self {
            rule_count,
            exact: HashMap::new(),
            suffix: HashMap::new(),
            keywords: Vec::new(),
            cidrs: Vec::new(),
            match_all: None,
        };
        for (index, rule) in rules.into_iter().enumerate() {
            let reference = RuleRef {
                index,
                policy: rule.policy,
            };
            match rule.matcher {
                RuleMatcher::Domain(domain) => {
                    matcher.exact.entry(domain).or_insert(reference);
                }
                RuleMatcher::DomainSuffix(suffix) => {
                    matcher.suffix.entry(suffix).or_insert(reference);
                }
                RuleMatcher::DomainKeyword(keyword) => {
                    matcher.keywords.push((keyword, reference));
                }
                RuleMatcher::IpCidr(cidr) => matcher.cidrs.push((cidr, reference)),
                RuleMatcher::MatchAll if matcher.match_all.is_none() => {
                    matcher.match_all = Some(reference);
                }
                RuleMatcher::MatchAll => {}
            }
        }
        matcher
    }

    fn policy(&self, host: &str, ip: Option<IpAddr>) -> Option<&str> {
        fn consider<'a>(best: &mut Option<&'a RuleRef>, candidate: Option<&'a RuleRef>) {
            if let Some(candidate) = candidate {
                if best.is_none_or(|current| candidate.index < current.index) {
                    *best = Some(candidate);
                }
            }
        }
        let mut best = self.match_all.as_ref();
        consider(&mut best, self.exact.get(host));
        let mut suffix = host;
        loop {
            consider(&mut best, self.suffix.get(suffix));
            let Some((_, parent)) = suffix.split_once('.') else {
                break;
            };
            suffix = parent;
        }
        for (keyword, reference) in &self.keywords {
            if host.contains(keyword) {
                consider(&mut best, Some(reference));
            }
        }
        if let Some(ip) = ip {
            for (cidr, reference) in &self.cidrs {
                if cidr.contains(ip) {
                    consider(&mut best, Some(reference));
                }
            }
        }
        best.map(|reference| reference.policy.as_str())
    }
}

#[derive(Default)]
struct MatcherCache {
    entries: HashMap<[u8; 32], Arc<IndexedMatcher>>,
    order: VecDeque<[u8; 32]>,
    total_rules: usize,
}

const MATCHER_CACHE_ENTRIES: usize = 32;
const MATCHER_CACHE_RULES: usize = 400_000;
static MATCHER_CACHE: OnceLock<Mutex<MatcherCache>> = OnceLock::new();

fn indexed_matcher(spec: &ExitRuleSpec) -> Result<Arc<IndexedMatcher>> {
    let key: [u8; 32] = Sha256::digest(serde_json::to_vec(spec)?).into();
    let cache = MATCHER_CACHE.get_or_init(|| Mutex::new(MatcherCache::default()));
    if let Some(matcher) = cache.lock().unwrap().entries.get(&key).cloned() {
        return Ok(matcher);
    }
    let matcher = Arc::new(IndexedMatcher::build(compile(spec)?));
    let mut cache = cache.lock().unwrap();
    if let Some(existing) = cache.entries.get(&key) {
        return Ok(existing.clone());
    }
    while cache.entries.len() >= MATCHER_CACHE_ENTRIES
        || cache.total_rules.saturating_add(matcher.rule_count) > MATCHER_CACHE_RULES
    {
        if let Some(oldest) = cache.order.pop_front() {
            if let Some(removed) = cache.entries.remove(&oldest) {
                cache.total_rules = cache.total_rules.saturating_sub(removed.rule_count);
            }
        } else {
            break;
        }
    }
    if matcher.rule_count > MATCHER_CACHE_RULES {
        return Ok(matcher);
    }
    cache.order.push_back(key);
    cache.total_rules = cache.total_rules.saturating_add(matcher.rule_count);
    cache.entries.insert(key, matcher.clone());
    Ok(matcher)
}

pub fn classify(spec: &ExitRuleSpec, host: &str, ip: Option<IpAddr>) -> Result<Option<Decision>> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let matcher = indexed_matcher(spec)?;
    let Some(policy) = matcher.policy(&host, ip) else {
        return Ok(None);
    };
    let decision = match spec.policy_exits.get(policy) {
        Some(ExitTarget::Direct) => Decision::Direct,
        Some(ExitTarget::Reject) => Decision::Reject,
        Some(ExitTarget::Nearest) => Decision::Nearest,
        Some(ExitTarget::Node { node_id }) => Decision::Node(node_id.clone()),
        None if policy.eq_ignore_ascii_case("REJECT")
            || policy.to_ascii_uppercase().starts_with("REJECT-") =>
        {
            Decision::Reject
        }
        None if policy.eq_ignore_ascii_case("DIRECT") => Decision::Direct,
        None => bail!("出口策略 {policy} 没有签名出口映射"),
    };
    Ok(Some(decision))
}

pub fn rules_for_device(node: &Node, device: &DeviceSpec) -> Vec<(ResourceView, ExitRuleSpec)> {
    let allowed = device.allowed_rules.iter().collect::<BTreeSet<_>>();
    rule_records(node)
        .into_iter()
        .filter(|(view, spec)| spec.enabled && allowed.contains(&view.resource.name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ExitRuleSpec {
        ExitRuleSpec {
            schema: EXIT_RULE_SCHEMA,
            description: "测试".into(),
            enabled: true,
            priority: 10,
            format: RuleFormat::Surge,
            config: "DOMAIN,api.example.com,AI\nDOMAIN-SUFFIX,blocked.test,REJECT\nIP-CIDR,1.1.1.0/24,DNS\nFINAL,DIRECT".into(),
            providers: BTreeMap::new(),
            policy_exits: BTreeMap::from([
                ("AI".into(), ExitTarget::Nearest),
                ("DNS".into(), ExitTarget::Node { node_id: "11".repeat(32) }),
            ]),
        }
    }

    #[test]
    fn surge_rules_preserve_order_and_map_policies() {
        let spec = fixture();
        spec.validate().unwrap();
        assert_eq!(
            classify(&spec, "api.example.com", None).unwrap(),
            Some(Decision::Nearest)
        );
        assert_eq!(
            classify(&spec, "x.blocked.test", None).unwrap(),
            Some(Decision::Reject)
        );
        assert!(matches!(
            classify(&spec, "one.one.one.one", Some("1.1.1.1".parse().unwrap())).unwrap(),
            Some(Decision::Node(_))
        ));
        assert_eq!(
            classify(&spec, "elsewhere.test", None).unwrap(),
            Some(Decision::Direct)
        );
    }

    #[test]
    fn signed_provider_snapshots_expand_in_place() {
        let mut spec = fixture();
        spec.config =
            "DOMAIN,first.test,DIRECT\nRULE-SET,https://rules.test/list,Proxy\nFINAL,REJECT".into();
        spec.providers.insert(
            "https://rules.test/list".into(),
            "+.example.net\n8.8.8.0/24".into(),
        );
        spec.policy_exits
            .insert("Proxy".into(), ExitTarget::Nearest);
        spec.validate().unwrap();
        assert_eq!(
            classify(&spec, "www.example.net", None).unwrap(),
            Some(Decision::Nearest)
        );
        assert_eq!(
            classify(&spec, "other.test", None).unwrap(),
            Some(Decision::Reject)
        );
    }

    #[test]
    fn full_clash_document_only_compiles_rules_and_provider_payload() {
        let mut spec = fixture();
        spec.format = RuleFormat::Clash;
        spec.config = r#"
proxies:
  - name: must-not-be-parsed
    type: socks5
rules:
  - 'DOMAIN,api.example.com,Proxy'
  - RULE-SET,https://rules.test/list,Proxy
  - MATCH,DIRECT
dns:
  enable: true
"#
        .into();
        spec.providers.insert(
            "https://rules.test/list".into(),
            "payload:\n  - '+.example.net'\n  - '8.8.8.0/24'\n".into(),
        );
        spec.policy_exits.clear();
        spec.policy_exits
            .insert("Proxy".into(), ExitTarget::Nearest);
        spec.validate().unwrap();
        assert_eq!(
            classify(&spec, "api.example.com", None).unwrap(),
            Some(Decision::Nearest)
        );
        assert_eq!(
            classify(&spec, "www.example.net", None).unwrap(),
            Some(Decision::Nearest)
        );
        assert_eq!(
            classify(&spec, "elsewhere.test", None).unwrap(),
            Some(Decision::Direct)
        );
    }

    #[test]
    fn unknown_proxy_policy_is_rejected_instead_of_bypassing_to_direct() {
        let mut spec = fixture();
        spec.config = "DOMAIN,private.example,MissingProxy".into();
        spec.policy_exits.clear();
        assert!(spec.validate().is_err());
        assert!(classify(&spec, "private.example", None).is_err());
    }

    #[test]
    fn cidr_masks_ipv4_and_ipv6_without_external_state() {
        let v4 = IpCidr::parse("10.1.2.0/24").unwrap();
        assert!(v4.contains("10.1.2.99".parse().unwrap()));
        assert!(!v4.contains("10.1.3.1".parse().unwrap()));
        let v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:4860::1".parse().unwrap()));
    }
}
