//! Decentralized inbound and outbound email foundations.
//!
//! Domain intent and routing are operator-signed resources. Mutable DNS
//! verification, delivery state, fenced leases, rate limits and audit events
//! live in a per-domain D1 quorum. RFC 822 source is stored in an ordinary R2
//! bucket, which means local and rclone-backed buckets share the exact same
//! durable mail path. DKIM private keys are deliberately node-local: signed
//! resources contain only the environment-variable name that email-capable
//! nodes may read.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use crate::r2::{self, PutOptions};
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use lettre::address::{Address, Envelope as SmtpEnvelope};
use lettre::transport::smtp::{
    client::{Tls, TlsParameters},
    extension::ClientId,
};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail_auth::hickory_resolver::proto::rr::RData;
use mail_auth::{
    common::{
        crypto::{RsaKey, Sha256 as DkimSha256},
        headers::HeaderWriter,
    },
    dkim::DkimSigner,
    dmarc::verify::DmarcParameters,
    spf::verify::SpfParameters,
    AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, MessageAuthenticator,
    SpfResult,
};
use mailin_embedded::{response, Handler, Response, Server, SslConfig};
use rustls_pki_types::{pem::PemObject, PrivateKeyDer};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;

pub const EMAIL_DOMAIN_KIND: &str = "email_domain";
pub const INTERNAL_EMAIL_PATH: &str = "/.rf/internal/email";
pub const INTERNAL_EVENT_HEADER: &str = "x-rf-internal-event";
pub const AUTH_RESULTS_HEADER: &str = "x-rf-email-authentication-results";
pub const SPF_RESULT_HEADER: &str = "x-rf-email-spf";
pub const DKIM_RESULT_HEADER: &str = "x-rf-email-dkim";
pub const DMARC_RESULT_HEADER: &str = "x-rf-email-dmarc";
pub const MAX_MESSAGE_BYTES: u64 = 63 * 1024 * 1024;
const DEFAULT_MESSAGE_BYTES: u64 = 25 * 1024 * 1024;
const DEFAULT_INBOUND_PER_MINUTE: u32 = 1_000;
const DEFAULT_OUTBOUND_PER_MINUTE: u32 = 1_000;
const DEFAULT_RETENTION_DAYS: u16 = 30;
const MAX_ROUTES: usize = 512;
const MAX_SEND_METADATA_BYTES: usize = 64 * 1024;
const OUTBOUND_LEASE_MS: u64 = 2 * 60 * 1_000;
const OUTBOUND_MAX_ATTEMPTS: u16 = 5;

fn default_message_bytes() -> u64 {
    DEFAULT_MESSAGE_BYTES
}

fn default_inbound_per_minute() -> u32 {
    DEFAULT_INBOUND_PER_MINUTE
}

fn default_outbound_per_minute() -> u32 {
    DEFAULT_OUTBOUND_PER_MINUTE
}

fn default_retention_days() -> u16 {
    DEFAULT_RETENTION_DAYS
}

fn default_dkim_selector() -> String {
    "rf".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailDomainSpec {
    #[serde(default)]
    pub description: String,
    /// The RFC 5321 domain accepted by this resource.
    pub domain: String,
    /// Public DNS proof. This is a random public challenge, not a credential.
    pub verification_challenge: String,
    /// Signed MX target. It must match the receiving node pool's EHLO name.
    pub mx_hostname: String,
    /// Existing R2 bucket used for immutable RFC 822 source.
    pub bucket: String,
    #[serde(default = "default_object_prefix")]
    pub object_prefix: String,
    #[serde(default)]
    pub routes: Vec<EmailRoute>,
    #[serde(default = "default_message_bytes")]
    pub max_message_bytes: u64,
    #[serde(default = "default_inbound_per_minute")]
    pub inbound_per_minute: u32,
    #[serde(default = "default_outbound_per_minute")]
    pub outbound_per_minute: u32,
    #[serde(default = "default_retention_days")]
    pub retention_days: u16,
    #[serde(default = "default_dkim_selector")]
    pub dkim_selector: String,
    /// DNS value beginning with `v=DKIM1;`. Public by design.
    #[serde(default)]
    pub dkim_public_key: String,
    /// Name of a node-local environment variable, never the private key.
    #[serde(default)]
    pub dkim_private_key_env: String,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub suspend_reason: String,
}

fn default_object_prefix() -> String {
    "mail".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmailRoute {
    pub id: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(flatten)]
    pub matcher: EmailMatcher,
    pub destination: EmailDestination,
}

impl<'de> Deserialize<'de> for EmailRoute {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("邮件路由必须是 JSON 对象"))?;
        let allowed = ["id", "priority", "enabled", "match", "value", "destination"];
        if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
            return Err(serde::de::Error::custom(format!(
                "邮件路由包含未知字段 {unknown}"
            )));
        }
        #[derive(Deserialize)]
        struct Wire {
            id: String,
            #[serde(default)]
            priority: i32,
            #[serde(default = "default_true")]
            enabled: bool,
            #[serde(flatten)]
            matcher: EmailMatcher,
            destination: EmailDestination,
        }
        let has_value = object.contains_key("value");
        let route: Wire = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        if matches!(route.matcher, EmailMatcher::CatchAll) && has_value {
            return Err(serde::de::Error::custom("catch_all 邮件路由不得包含 value"));
        }
        Ok(Self {
            id: route.id,
            priority: route.priority,
            enabled: route.enabled,
            matcher: route.matcher,
            destination: route.destination,
        })
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "match", rename_all = "snake_case")]
pub enum EmailMatcher {
    Exact { value: String },
    Prefix { value: String },
    CatchAll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmailDestination {
    Worker { worker: String },
    Forward { addresses: Vec<String> },
    Drop,
}

impl EmailDomainSpec {
    pub fn validate(&self) -> Result<()> {
        if self.description.len() > 2_000 || self.suspend_reason.len() > 2_000 {
            bail!("邮件域描述或暂停原因不得超过 2000 个字符");
        }
        if !valid_domain(&self.domain) || self.domain != self.domain.to_ascii_lowercase() {
            bail!("邮件域必须是有效的小写 DNS 域名");
        }
        if !valid_domain(&self.mx_hostname)
            || self.mx_hostname != self.mx_hostname.to_ascii_lowercase()
        {
            bail!("邮件 MX 主机名必须是有效的小写 DNS 域名");
        }
        if self.verification_challenge.len() < 16
            || self.verification_challenge.len() > 256
            || !self
                .verification_challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("邮件域验证挑战必须是 16 至 256 位 URL 安全文本");
        }
        if !rf_core::manifest::valid_name(&self.bucket) {
            bail!("邮件原文 R2 bucket 名称无效");
        }
        validate_prefix(&self.object_prefix)?;
        if self.routes.len() > MAX_ROUTES {
            bail!("每个邮件域最多配置 {MAX_ROUTES} 条路由");
        }
        let mut ids = HashSet::new();
        let mut exact = HashSet::new();
        for route in &self.routes {
            route.validate(&self.domain)?;
            if !ids.insert(route.id.as_str()) {
                bail!("邮件路由 ID 重复：{}", route.id);
            }
            if let EmailMatcher::Exact { value } = &route.matcher {
                if !exact.insert(value.to_ascii_lowercase()) {
                    bail!("邮件精确路由重复：{value}");
                }
            }
        }
        if !(1..=MAX_MESSAGE_BYTES).contains(&self.max_message_bytes) {
            bail!("邮件大小上限必须介于 1 字节和 63 MiB 之间");
        }
        if self.inbound_per_minute == 0 || self.outbound_per_minute == 0 {
            bail!("邮件收发速率上限必须大于零");
        }
        if !(1..=3650).contains(&self.retention_days) {
            bail!("邮件记录保留期必须介于 1 和 3650 天之间");
        }
        if !valid_selector(&self.dkim_selector) {
            bail!("DKIM selector 只能包含字母、数字、下划线和连字符");
        }
        if !self.dkim_public_key.is_empty()
            && (!self.dkim_public_key.starts_with("v=DKIM1;")
                || self.dkim_public_key.contains(['\r', '\n'])
                || self.dkim_public_key.len() > 16_384)
        {
            bail!("DKIM 公钥 DNS 值无效");
        }
        if !self.dkim_private_key_env.is_empty()
            && (!self.dkim_private_key_env.starts_with("RF_EMAIL_DKIM_")
                || self.dkim_private_key_env.len() > 128
                || !self
                    .dkim_private_key_env
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'))
        {
            bail!("DKIM 私钥环境变量须以 RF_EMAIL_DKIM_ 开头，并仅含大写字母、数字和下划线");
        }
        Ok(())
    }

    pub fn ownership_txt_name(&self) -> String {
        format!("_randallflare-verify.{}", self.domain)
    }

    pub fn ownership_txt_value(&self) -> String {
        format!("rf-email-verification={}", self.verification_challenge)
    }

    pub fn dkim_txt_name(&self) -> String {
        format!("{}._domainkey.{}", self.dkim_selector, self.domain)
    }
}

impl EmailRoute {
    fn validate(&self, domain: &str) -> Result<()> {
        if !rf_core::manifest::valid_name(&self.id) {
            bail!("邮件路由 ID 无效：{}", self.id);
        }
        match &self.matcher {
            EmailMatcher::Exact { value } => {
                let (local, address_domain) = split_address(value)?;
                if address_domain != domain || local.len() > 64 {
                    bail!("邮件精确路由必须是当前域内地址：{value}");
                }
            }
            EmailMatcher::Prefix { value } => {
                if value.is_empty()
                    || value.len() > 64
                    || !value.chars().all(valid_local_match_char)
                {
                    bail!("邮件前缀路由无效：{value}");
                }
            }
            EmailMatcher::CatchAll => {}
        }
        match &self.destination {
            EmailDestination::Worker { worker } => {
                if !rf_core::manifest::valid_name(worker) {
                    bail!("邮件路由 Worker 名称无效：{worker}");
                }
            }
            EmailDestination::Forward { addresses } => {
                if addresses.is_empty() || addresses.len() > 32 {
                    bail!("转发路由必须包含 1 至 32 个收件地址");
                }
                for address in addresses {
                    split_address(address)
                        .with_context(|| format!("邮件转发地址无效：{address}"))?;
                }
            }
            EmailDestination::Drop => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerification {
    pub domain: String,
    pub ownership_ok: bool,
    pub mx_ok: bool,
    pub dkim_ok: bool,
    pub spf_present: bool,
    pub verified: bool,
    pub ownership_observed: Vec<String>,
    pub mx_observed: Vec<String>,
    pub dkim_observed: Vec<String>,
    pub spf_observed: Vec<String>,
    pub checked_at_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    pub id: String,
    pub direction: String,
    pub mail_from: String,
    pub rcpt_to: String,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub object_key: String,
    pub size: u64,
    pub sha256: String,
    pub status: String,
    pub route_id: Option<String>,
    pub target: Option<String>,
    pub auth_results: Option<String>,
    pub spf: Option<String>,
    pub dkim: Option<String>,
    pub dmarc: Option<String>,
    pub attempts: u16,
    pub last_error: Option<String>,
    pub dsn_status: Option<String>,
    pub dsn_message_id: Option<String>,
    pub dsn_attempts: u16,
    pub dsn_last_error: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundEnvelope {
    pub helo_domain: String,
    pub client_ip: IpAddr,
    pub mail_from: String,
    pub recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedMessage {
    pub id: String,
    pub recipient: String,
    pub status: String,
    pub route_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub id: String,
    pub recipient: String,
    pub object_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailSendMetadata {
    pub mail_from: String,
    pub recipients: Vec<String>,
}

pub fn encode_send_request(metadata: &EmailSendMetadata, raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() as u64 > MAX_MESSAGE_BYTES {
        bail!("邮件原文不得超过 63 MiB");
    }
    let encoded = serde_json::to_vec(metadata)?;
    if encoded.len() > MAX_SEND_METADATA_BYTES {
        bail!("邮件信封元数据不得超过 64 KiB");
    }
    let mut body = Vec::with_capacity(4 + encoded.len() + raw.len());
    body.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    body.extend_from_slice(&encoded);
    body.extend_from_slice(raw);
    Ok(body)
}

pub fn decode_send_request(body: &[u8]) -> Result<(EmailSendMetadata, &[u8])> {
    if body.len() < 4 {
        bail!("邮件发送请求不完整");
    }
    let metadata_len = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
    if metadata_len > MAX_SEND_METADATA_BYTES || body.len() < 4 + metadata_len {
        bail!("邮件信封元数据长度无效");
    }
    let metadata = serde_json::from_slice(&body[4..4 + metadata_len])?;
    let raw = &body[4 + metadata_len..];
    if raw.len() as u64 > MAX_MESSAGE_BYTES {
        bail!("邮件原文不得超过 63 MiB");
    }
    Ok((metadata, raw))
}

#[derive(Debug, Clone)]
struct AuthSummary {
    header: String,
    spf: String,
    dkim: String,
    dmarc: String,
}

#[derive(Debug, Clone)]
struct OutboundClaim {
    message: EmailMessage,
    lease: String,
}

#[derive(Debug)]
struct DeliveryFailure {
    permanent: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerEmailOutcome {
    #[serde(default)]
    reject: Option<String>,
    #[serde(default)]
    forwards: Vec<WorkerForward>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerForward {
    recipient: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
}

enum InboundOutcome {
    Delivered,
    Rejected(String),
    Forwarded(usize),
}

enum DsnOutcome {
    Generated(String),
    Skipped(&'static str),
}

#[derive(Clone)]
struct SmtpHandler {
    node: Arc<Node>,
    runtime: tokio::runtime::Handle,
    mx_hostname: String,
    client_ip: IpAddr,
    helo_domain: String,
    mail_from: String,
    accepted: Vec<(String, String)>,
    data: Vec<u8>,
    max_bytes: usize,
    overflowed: bool,
}

impl SmtpHandler {
    fn new(node: Arc<Node>, runtime: tokio::runtime::Handle, mx_hostname: String) -> Self {
        Self {
            node,
            runtime,
            mx_hostname,
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            helo_domain: String::new(),
            mail_from: String::new(),
            accepted: Vec::new(),
            data: Vec::new(),
            max_bytes: DEFAULT_MESSAGE_BYTES as usize,
            overflowed: false,
        }
    }

    fn reset_message(&mut self) {
        self.mail_from.clear();
        self.accepted.clear();
        self.data.clear();
        self.max_bytes = DEFAULT_MESSAGE_BYTES as usize;
        self.overflowed = false;
    }

    fn find_recipient_domain(&self, address: &str) -> Option<(String, EmailDomainSpec)> {
        let (_, domain) = split_address(address).ok()?;
        email_domain_records(&self.node)
            .into_iter()
            .find(|(_, spec)| {
                !spec.suspended
                    && spec.domain == domain
                    && spec.mx_hostname == self.mx_hostname
                    && route_for(spec, address).is_some()
            })
            .map(|(view, spec)| (view.resource.name, spec))
    }
}

impl Handler for SmtpHandler {
    fn helo(&mut self, ip: IpAddr, domain: &str) -> Response {
        if !valid_domain(domain) {
            return response::BAD_HELLO;
        }
        self.client_ip = ip;
        self.helo_domain = domain.to_ascii_lowercase();
        response::OK
    }

    fn mail(&mut self, ip: IpAddr, domain: &str, from: &str) -> Response {
        self.reset_message();
        self.client_ip = ip;
        self.helo_domain = domain.to_ascii_lowercase();
        self.mail_from = if from.is_empty() {
            String::new()
        } else {
            let Ok(address) = normalize_address(from) else {
                return response::BAD_MAILBOX;
            };
            address
        };
        response::OK
    }

    fn rcpt(&mut self, to: &str) -> Response {
        let Ok(address) = normalize_address(to) else {
            return response::BAD_MAILBOX;
        };
        let Some((name, spec)) = self.find_recipient_domain(&address) else {
            return Response::custom(550, "5.1.1 收件地址不存在".into());
        };
        let verified = self
            .runtime
            .block_on(latest_verification(&self.node, &name))
            .ok()
            .flatten()
            .is_some_and(|status| status.verified);
        if !verified {
            return Response::custom(451, "4.3.0 收件域暂未就绪，请稍后重试".into());
        }
        self.max_bytes = self.max_bytes.min(spec.max_message_bytes as usize);
        self.accepted.push((name, address));
        response::OK
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> Response {
        self.data.clear();
        self.overflowed = false;
        if self.accepted.is_empty() {
            return response::NO_MAILBOX;
        }
        response::OK
    }

    fn data(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.overflowed {
            return Ok(());
        }
        if self.data.len().saturating_add(buf.len()) > self.max_bytes {
            self.overflowed = true;
            self.data.clear();
            return Ok(());
        }
        self.data.extend_from_slice(buf);
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        if self.overflowed {
            self.reset_message();
            return Response::custom(552, "5.3.4 邮件超过此域允许的大小".into());
        }
        let mut by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, recipient) in &self.accepted {
            by_domain
                .entry(name.clone())
                .or_default()
                .push(recipient.clone());
        }
        let envelope_base = InboundEnvelope {
            helo_domain: self.helo_domain.clone(),
            client_ip: self.client_ip,
            mail_from: self.mail_from.clone(),
            recipients: vec![],
        };
        let raw = self.data.clone();
        let result = self.runtime.block_on(async {
            let mut ids = Vec::new();
            for (name, recipients) in by_domain {
                let mut envelope = envelope_base.clone();
                envelope.recipients = recipients;
                let accepted = ingest_inbound(&self.node, &name, &envelope, &raw).await?;
                ids.extend(accepted.into_iter().map(|message| message.id));
            }
            Ok::<_, anyhow::Error>(ids)
        });
        self.reset_message();
        match result {
            Ok(ids) => Response::custom(
                250,
                format!("2.0.0 已由 RandallFlare 接收 {} 个投递", ids.len()),
            ),
            Err(error) => {
                tracing::warn!(client_ip = %self.client_ip, "接收 SMTP 邮件失败：{error:#}");
                Response::custom(451, "4.3.0 邮件暂存失败，请稍后重试".into())
            }
        }
    }
}

/// Bind and spawn the optional blocking SMTP server. Binding is performed
/// before the background thread starts so a bad address or occupied port
/// fails node startup instead of becoming a silent capability loss.
pub fn spawn_smtp_server(node: Arc<Node>) -> Result<Option<std::thread::JoinHandle<()>>> {
    if !node.cfg.email.enabled {
        return Ok(None);
    }
    let address = node
        .cfg
        .email
        .smtp_listen
        .context("email.smtp_listen 未配置")?;
    let mx_hostname = node
        .cfg
        .email
        .mx_hostname
        .clone()
        .context("email.mx_hostname 未配置")?;
    let listener =
        TcpListener::bind(address).with_context(|| format!("无法监听 SMTP 地址 {address}"))?;
    let cert_dir = node.cfg.data_dir.join("certs");
    let cert_path = cert_dir.join(format!("{mx_hostname}.crt"));
    let key_path = cert_dir.join(format!("{mx_hostname}.key"));
    let ssl = SslConfig::Reloading {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        chain_path: None,
    };
    if cert_path.is_file() && key_path.is_file() {
        tracing::info!(%mx_hostname, "SMTP STARTTLS 已启用并将自动热加载证书");
    } else {
        tracing::warn!(
            %mx_hostname,
            "SMTP 证书尚未物化，STARTTLS 暂不宣告；证书就绪后会自动启用"
        );
    }
    let runtime = tokio::runtime::Handle::current();
    let max_sessions = node.cfg.email.max_sessions;
    let handler = SmtpHandler::new(node, runtime, mx_hostname.clone());
    let thread = std::thread::Builder::new()
        .name("rf-smtp".into())
        .spawn(move || {
            let mut server = Server::new(handler);
            server
                .with_name(mx_hostname.clone())
                .with_num_threads(max_sessions)
                .with_tcp_listener(listener);
            if let Err(error) = server.with_ssl(ssl) {
                tracing::error!("SMTP TLS 初始化失败：{error}");
                return;
            }
            if let Err(error) = server.serve() {
                tracing::error!("SMTP 服务停止：{error}");
            }
        })
        .context("无法启动 SMTP 线程")?;
    Ok(Some(thread))
}

pub fn email_domain_record(node: &Node, name: &str) -> Option<(ResourceView, EmailDomainSpec)> {
    let view = resource::head(node, EMAIL_DOMAIN_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = email_domain_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn email_domain_records(node: &Node) -> Vec<(ResourceView, EmailDomainSpec)> {
    resource::heads(node, Some(EMAIL_DOMAIN_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            email_domain_spec(&view.resource)
                .ok()
                .map(|spec| (view, spec))
        })
        .collect()
}

pub fn email_domain_spec(record: &ResourceRecord) -> Result<EmailDomainSpec> {
    if record.kind != EMAIL_DOMAIN_KIND {
        bail!("平台资源不是邮件域");
    }
    let spec: EmailDomainSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn prepare_email_domain_after(
    name: &str,
    spec: EmailDomainSpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.validate()?;
    resource::prepare_after(
        EMAIL_DOMAIN_KIND,
        name,
        serde_json::to_value(spec)?,
        deleted,
        head,
    )
}

pub fn generate_verification_challenge() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>())
}

pub fn database_name(name: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("email/{name}").as_bytes()));
    format!("email-{}", &digest[..32])
}

pub fn route_for<'a>(spec: &'a EmailDomainSpec, recipient: &str) -> Option<&'a EmailRoute> {
    let (local, domain) = split_address(recipient).ok()?;
    if !domain.eq_ignore_ascii_case(&spec.domain) {
        return None;
    }
    let local = local.to_ascii_lowercase();
    let mut matches: Vec<_> = spec
        .routes
        .iter()
        .filter(|route| route.enabled)
        .filter(|route| match &route.matcher {
            EmailMatcher::Exact { value } => value.eq_ignore_ascii_case(recipient),
            EmailMatcher::Prefix { value } => local.starts_with(&value.to_ascii_lowercase()),
            EmailMatcher::CatchAll => true,
        })
        .collect();
    matches.sort_by_key(|route| {
        let specificity = match route.matcher {
            EmailMatcher::Exact { .. } => 0,
            EmailMatcher::Prefix { .. } => 1,
            EmailMatcher::CatchAll => 2,
        };
        (specificity, route.priority, route.id.as_str())
    });
    matches.into_iter().next()
}

pub async fn verify_domain(node: &Node, name: &str) -> Result<EmailVerification> {
    let (_, spec) = email_domain_record(node, name).context("邮件域不存在")?;
    ensure_schema(node, name).await?;
    let checked_at_ms = now_ms();
    let result = query_verification(&spec, checked_at_ms).await;
    let verification = match result {
        Ok(verification) => verification,
        Err(error) => EmailVerification {
            domain: spec.domain.clone(),
            ownership_ok: false,
            mx_ok: false,
            dkim_ok: false,
            spf_present: false,
            verified: false,
            ownership_observed: vec![],
            mx_observed: vec![],
            dkim_observed: vec![],
            spf_observed: vec![],
            checked_at_ms,
            error: Some(format!("{error:#}")),
        },
    };
    exec(
        node,
        name,
        r#"INSERT INTO email_verification
           (singleton,domain,ownership_ok,mx_ok,dkim_ok,spf_present,verified,
            ownership_json,mx_json,dkim_json,spf_json,checked_at_ms,error)
           VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
           ON CONFLICT(singleton) DO UPDATE SET
             domain=excluded.domain,ownership_ok=excluded.ownership_ok,mx_ok=excluded.mx_ok,
             dkim_ok=excluded.dkim_ok,spf_present=excluded.spf_present,verified=excluded.verified,
             ownership_json=excluded.ownership_json,mx_json=excluded.mx_json,
             dkim_json=excluded.dkim_json,spf_json=excluded.spf_json,
             checked_at_ms=excluded.checked_at_ms,error=excluded.error"#,
        json!([
            verification.domain,
            verification.ownership_ok,
            verification.mx_ok,
            verification.dkim_ok,
            verification.spf_present,
            verification.verified,
            serde_json::to_string(&verification.ownership_observed)?,
            serde_json::to_string(&verification.mx_observed)?,
            serde_json::to_string(&verification.dkim_observed)?,
            serde_json::to_string(&verification.spf_observed)?,
            verification.checked_at_ms,
            verification.error
        ]),
    )
    .await?;
    append_audit(
        node,
        name,
        "domain_verification",
        json!({
            "verified": verification.verified,
            "ownership_ok": verification.ownership_ok,
            "mx_ok": verification.mx_ok,
            "dkim_ok": verification.dkim_ok,
            "spf_present": verification.spf_present,
        }),
    )
    .await?;
    Ok(verification)
}

pub async fn latest_verification(node: &Node, name: &str) -> Result<Option<EmailVerification>> {
    ensure_schema(node, name).await?;
    let row = rows(
        exec(
            node,
            name,
            "SELECT domain,ownership_ok,mx_ok,dkim_ok,spf_present,verified,ownership_json,mx_json,dkim_json,spf_json,checked_at_ms,error FROM email_verification WHERE singleton=1",
            json!([]),
        )
        .await?,
    )
    .into_iter()
    .next();
    row.as_ref().map(row_to_verification).transpose()
}

pub async fn ingest_inbound(
    node: &Node,
    domain_name: &str,
    envelope: &InboundEnvelope,
    raw: &[u8],
) -> Result<Vec<IngestedMessage>> {
    ingest_inbound_inner(node, domain_name, envelope, raw, None).await
}

async fn ingest_inbound_inner(
    node: &Node,
    domain_name: &str,
    envelope: &InboundEnvelope,
    raw: &[u8],
    idempotency: Option<(&str, u64)>,
) -> Result<Vec<IngestedMessage>> {
    let (_, spec) = email_domain_record(node, domain_name).context("邮件域不存在")?;
    if spec.suspended {
        bail!("邮件域已暂停：{}", spec.suspend_reason);
    }
    if raw.len() as u64 > spec.max_message_bytes {
        bail!("邮件超过此域配置的大小上限");
    }
    if raw.is_empty() {
        bail!("邮件原文不能为空");
    }
    if envelope.recipients.is_empty() || envelope.recipients.len() > 1_000 {
        bail!("每封邮件必须包含 1 至 1000 个收件人");
    }
    ensure_schema(node, domain_name).await?;
    let verification = latest_verification(node, domain_name)
        .await?
        .context("邮件域尚未完成 DNS 验证")?;
    if !verification.verified {
        bail!("邮件域尚未通过所有必需的 DNS 验证");
    }
    if idempotency.is_none() {
        enforce_rate_limit(
            node,
            domain_name,
            "inbound",
            spec.inbound_per_minute,
            envelope.recipients.len() as u32,
        )
        .await?;
    }
    let auth = authenticate_message(&spec.mx_hostname, envelope, raw).await;
    let parsed = mail_parser::MessageParser::default().parse(raw);
    let subject = parsed
        .as_ref()
        .and_then(|message| message.subject())
        .map(str::to_string);
    let message_id = parsed
        .as_ref()
        .and_then(|message| message.message_id())
        .map(str::to_string);
    let timestamp = idempotency
        .map(|(_, timestamp)| timestamp)
        .unwrap_or_else(now_ms);
    let source_id = idempotency
        .map(|(key, _)| stable_id(&format!("inbound-source\0{key}")))
        .unwrap_or_else(new_id);
    let object_key = object_key(&spec, "inbound", timestamp, &source_id);
    let sha256 = hex::encode(Sha256::digest(raw));
    r2::put_object(
        node,
        &spec.bucket,
        &object_key,
        raw,
        PutOptions {
            content_type: Some("message/rfc822".into()),
            custom_metadata: serde_json::Map::from_iter([
                ("rf-email-domain".into(), Value::String(spec.domain.clone())),
                ("rf-email-direction".into(), Value::String("inbound".into())),
                ("rf-email-sha256".into(), Value::String(sha256.clone())),
            ]),
            ..Default::default()
        },
    )
    .await?;

    let mut ingested = Vec::new();
    for recipient in &envelope.recipients {
        let (_, recipient_domain) = split_address(recipient)?;
        if recipient_domain != spec.domain {
            continue;
        }
        let route = route_for(&spec, recipient);
        let (status, route_id, target) = match route {
            Some(route) => match &route.destination {
                EmailDestination::Worker { worker } => (
                    "pending",
                    Some(route.id.clone()),
                    Some(format!("worker:{worker}")),
                ),
                EmailDestination::Forward { addresses } => (
                    "pending",
                    Some(route.id.clone()),
                    Some(format!("forward:{}", addresses.join(","))),
                ),
                EmailDestination::Drop => ("dropped", Some(route.id.clone()), Some("drop".into())),
            },
            None => ("rejected", None, None),
        };
        let id = idempotency
            .map(|(key, _)| stable_id(&format!("inbound-recipient\0{key}\0{recipient}")))
            .unwrap_or_else(new_id);
        let inserted = exec(
            node,
            domain_name,
            r#"INSERT OR IGNORE INTO email_messages
               (id,direction,mail_from,rcpt_to,subject,message_id,object_key,size,sha256,
                status,route_id,target,auth_results,spf,dkim,dmarc,attempts,
                created_at_ms,updated_at_ms)
               VALUES(?1,'inbound',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,0,?16,?16)"#,
            json!([
                id,
                envelope.mail_from,
                recipient,
                subject,
                message_id,
                object_key,
                raw.len(),
                sha256,
                status,
                route_id,
                target,
                auth.as_ref().map(|value| &value.header),
                auth.as_ref().map(|value| &value.spf),
                auth.as_ref().map(|value| &value.dkim),
                auth.as_ref().map(|value| &value.dmarc),
                timestamp,
            ]),
        )
        .await?["rows_affected"]
            .as_u64()
            .unwrap_or(0);
        if inserted == 1 {
            append_audit(
                node,
                domain_name,
                "inbound_accepted",
                json!({ "message_id": id, "recipient": recipient, "status": status }),
            )
            .await?;
            ingested.push(IngestedMessage {
                id,
                recipient: recipient.clone(),
                status: status.into(),
                route_id,
            });
        } else {
            let existing = get_message(node, domain_name, &id)
                .await?
                .context("邮件幂等写入冲突后原记录不可见")?;
            ingested.push(IngestedMessage {
                id,
                recipient: existing.rcpt_to,
                status: existing.status,
                route_id: existing.route_id,
            });
        }
    }
    if ingested.is_empty() {
        bail!("邮件没有属于此域的有效收件人");
    }
    Ok(ingested)
}

/// Store one immutable source object and enqueue one independently retried
/// outbound delivery per recipient. Callers may run on ordinary nodes; only
/// email-capable nodes possessing the named DKIM environment variable claim
/// the resulting leases.
pub async fn queue_outbound(
    node: &Node,
    domain_name: &str,
    mail_from: &str,
    recipients: &[String],
    raw: &[u8],
) -> Result<Vec<QueuedMessage>> {
    queue_outbound_inner(node, domain_name, mail_from, recipients, raw, None).await
}

async fn queue_outbound_inner(
    node: &Node,
    domain_name: &str,
    mail_from: &str,
    recipients: &[String],
    raw: &[u8],
    idempotency_key: Option<&str>,
) -> Result<Vec<QueuedMessage>> {
    let (_, spec) = email_domain_record(node, domain_name).context("邮件域不存在")?;
    if spec.suspended {
        bail!("邮件域已暂停：{}", spec.suspend_reason);
    }
    if raw.is_empty() || raw.len() as u64 > spec.max_message_bytes {
        bail!("出站邮件原文为空或超过此域的大小上限");
    }
    let mail_from = normalize_address(mail_from)?;
    let (_, sender_domain) = split_address(&mail_from)?;
    if sender_domain != spec.domain {
        bail!("信封发件地址必须属于当前邮件域");
    }
    if recipients.is_empty() || recipients.len() > 1_000 {
        bail!("出站邮件必须包含 1 至 1000 个收件人");
    }
    let mut unique_recipients = Vec::new();
    let mut seen = HashSet::new();
    for recipient in recipients {
        split_address(recipient)?;
        let recipient = normalize_address(recipient)?;
        if seen.insert(recipient.clone()) {
            unique_recipients.push(recipient);
        }
    }
    if spec.dkim_public_key.is_empty() || spec.dkim_private_key_env.is_empty() {
        bail!("出站邮件要求配置 DKIM 公钥和节点私钥环境变量名");
    }
    ensure_schema(node, domain_name).await?;
    let verification = latest_verification(node, domain_name)
        .await?
        .context("邮件域尚未完成 DNS 验证")?;
    if !verification.verified {
        bail!("邮件域尚未通过所有必需的 DNS 验证");
    }
    let mut queued = Vec::with_capacity(unique_recipients.len());
    let mut planned = Vec::with_capacity(unique_recipients.len());
    for recipient in unique_recipients {
        let id = idempotency_key
            .map(|key| stable_id(&format!("{key}\0{recipient}")))
            .unwrap_or_else(new_id);
        if let Some(existing) = get_message(node, domain_name, &id).await? {
            if existing.direction != "outbound"
                || existing.mail_from != mail_from
                || existing.rcpt_to != recipient
            {
                bail!("邮件幂等键与已有投递冲突");
            }
            queued.push(QueuedMessage {
                id,
                recipient,
                object_key: existing.object_key,
            });
        } else {
            planned.push((id, recipient));
        }
    }
    if planned.is_empty() {
        return Ok(queued);
    }
    enforce_rate_limit(
        node,
        domain_name,
        "outbound",
        spec.outbound_per_minute,
        planned.len() as u32,
    )
    .await?;

    let parsed = mail_parser::MessageParser::default()
        .parse(raw)
        .context("出站邮件不是有效的 RFC 822 消息")?;
    if parsed.from().is_none() {
        bail!("出站邮件必须包含 From 头");
    }
    let subject = parsed.subject().map(str::to_string);
    let message_id = parsed.message_id().map(str::to_string);
    let timestamp = now_ms();
    let source_id = idempotency_key
        .map(|key| stable_id(&format!("source\0{key}")))
        .unwrap_or_else(new_id);
    let object_key = object_key(&spec, "outbound", timestamp, &source_id);
    let sha256 = hex::encode(Sha256::digest(raw));
    r2::put_object(
        node,
        &spec.bucket,
        &object_key,
        raw,
        PutOptions {
            content_type: Some("message/rfc822".into()),
            custom_metadata: serde_json::Map::from_iter([
                ("rf-email-domain".into(), Value::String(spec.domain.clone())),
                (
                    "rf-email-direction".into(),
                    Value::String("outbound".into()),
                ),
                ("rf-email-sha256".into(), Value::String(sha256.clone())),
            ]),
            ..Default::default()
        },
    )
    .await?;

    for (id, recipient) in planned {
        exec(
            node,
            domain_name,
            r#"INSERT INTO email_messages
               (id,direction,mail_from,rcpt_to,subject,message_id,object_key,size,sha256,
                status,target,attempts,next_attempt_ms,created_at_ms,updated_at_ms)
               VALUES(?1,'outbound',?2,?3,?4,?5,?6,?7,?8,'queued','smtp',0,?9,?9,?9)"#,
            json!([
                id,
                mail_from,
                recipient,
                subject,
                message_id,
                object_key,
                raw.len(),
                sha256,
                timestamp,
            ]),
        )
        .await?;
        append_audit(
            node,
            domain_name,
            "outbound_queued",
            json!({ "message_id": id, "recipient": recipient }),
        )
        .await?;
        queued.push(QueuedMessage {
            id,
            recipient,
            object_key: object_key.clone(),
        });
    }
    Ok(queued)
}

async fn recover_inbound_leases(node: &Node, name: &str) -> Result<()> {
    ensure_schema(node, name).await?;
    let now = now_ms();
    exec(
        node,
        name,
        r#"UPDATE email_messages SET
             status=CASE WHEN attempts>=?1 THEN 'failed' ELSE 'pending' END,
             next_attempt_ms=CASE WHEN attempts>=?1 THEN NULL ELSE ?2 END,
             last_error=CASE WHEN attempts>=?1 THEN '邮件事件节点失联，且已达到最大重试次数'
                             ELSE '邮件事件节点失联，租约已恢复' END,
             lease_token=NULL,lease_until_ms=NULL,leased_by=NULL,updated_at_ms=?2
           WHERE direction='inbound' AND status='running'
             AND lease_until_ms IS NOT NULL AND lease_until_ms<?2"#,
        json!([OUTBOUND_MAX_ATTEMPTS, now]),
    )
    .await?;
    Ok(())
}

async fn claim_inbound(node: &Node, name: &str) -> Result<Option<OutboundClaim>> {
    ensure_schema(node, name).await?;
    let now = now_ms();
    let lease = new_id();
    let result = exec(
        node,
        name,
        &format!(
            r#"UPDATE email_messages SET
                 status='running',attempts=attempts+1,lease_token=?1,
                 lease_until_ms=?2,leased_by=?3,updated_at_ms=?4
               WHERE id=(
                 SELECT id FROM email_messages
                 WHERE direction='inbound' AND status='pending'
                   AND attempts<?5 AND COALESCE(next_attempt_ms,0)<=?4
                 ORDER BY created_at_ms,id LIMIT 1
               )
               RETURNING {MESSAGE_FIELDS}"#
        ),
        json!([
            lease,
            now + OUTBOUND_LEASE_MS,
            node.id_hex(),
            now,
            OUTBOUND_MAX_ATTEMPTS,
        ]),
    )
    .await?;
    let Some(row) = rows(result).into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(OutboundClaim {
        message: row_to_message(&row)?,
        lease,
    }))
}

pub async fn process_inbound_once(
    node: &Node,
    domain_name: &str,
    spec: &EmailDomainSpec,
) -> Result<bool> {
    let Some(claim) = claim_inbound(node, domain_name).await? else {
        return Ok(false);
    };
    let result = process_inbound_claim(node, domain_name, spec, &claim).await;
    finish_inbound(node, domain_name, &claim, result).await?;
    Ok(true)
}

async fn process_inbound_claim(
    node: &Node,
    domain_name: &str,
    spec: &EmailDomainSpec,
    claim: &OutboundClaim,
) -> Result<InboundOutcome> {
    let route_id = claim
        .message
        .route_id
        .as_deref()
        .context("入站邮件缺少路由 ID")?;
    let route = spec
        .routes
        .iter()
        .find(|route| route.id == route_id && route.enabled)
        .context("入站邮件的签名路由已不存在或已禁用")?;
    let (_, raw) = r2::get_object(node, &spec.bucket, &claim.message.object_key)
        .await?
        .context("入站邮件原文对象不存在")?;
    match &route.destination {
        EmailDestination::Worker { worker } => {
            let outcome = dispatch_email_worker(node, worker, &claim.message, &raw).await?;
            if let Some(reason) = outcome.reject {
                if reason.is_empty() || reason.len() > 1_000 || reason.contains(['\r', '\n']) {
                    bail!("Worker 返回了无效的邮件拒收原因");
                }
                return Ok(InboundOutcome::Rejected(reason));
            }
            if outcome.forwards.is_empty() {
                return Ok(InboundOutcome::Delivered);
            }
            let mut queued = 0;
            for forward in outcome.forwards {
                let forwarded = add_forward_headers(spec, &claim.message, &raw, &forward.headers)?;
                queued += queue_forward(
                    node,
                    domain_name,
                    spec,
                    &claim.message,
                    &[forward.recipient],
                    &forwarded,
                )
                .await?;
            }
            Ok(InboundOutcome::Forwarded(queued))
        }
        EmailDestination::Forward { addresses } => {
            let forwarded = add_forward_headers(spec, &claim.message, &raw, &[])?;
            let queued = queue_forward(
                node,
                domain_name,
                spec,
                &claim.message,
                addresses,
                &forwarded,
            )
            .await?;
            Ok(InboundOutcome::Forwarded(queued))
        }
        EmailDestination::Drop => Ok(InboundOutcome::Delivered),
    }
}

async fn dispatch_email_worker(
    node: &Node,
    worker: &str,
    message: &EmailMessage,
    raw: &[u8],
) -> Result<WorkerEmailOutcome> {
    let port = node
        .worker_port(worker)
        .context("邮件处理 Worker 未在当前节点运行")?;
    let token = node
        .worker_event_token(worker)
        .context("邮件处理 Worker 内部事件令牌尚未就绪")?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15 * 60))
        .build()?;
    let mut request = client
        .post(format!("http://127.0.0.1:{port}{INTERNAL_EMAIL_PATH}"))
        .header(INTERNAL_EVENT_HEADER, token)
        .header("x-rf-email-message-id", &message.id)
        .header("x-rf-email-from", &message.mail_from)
        .header("x-rf-email-to", &message.rcpt_to)
        .header("content-type", "message/rfc822")
        .body(raw.to_vec());
    for (name, value) in [
        (AUTH_RESULTS_HEADER, message.auth_results.as_deref()),
        (SPF_RESULT_HEADER, message.spf.as_deref()),
        (DKIM_RESULT_HEADER, message.dkim.as_deref()),
        (DMARC_RESULT_HEADER, message.dmarc.as_deref()),
    ] {
        if let Some(value) = value {
            let unfolded = value.split_whitespace().collect::<Vec<_>>().join(" ");
            request = request.header(name, unfolded);
        }
    }
    let response = request.send().await?;
    let status = response.status();
    let body = response.bytes().await?;
    if body.len() > 256 * 1024 {
        bail!("邮件处理 Worker 响应超过 256 KiB");
    }
    if !status.is_success() {
        bail!(
            "邮件处理 Worker 返回 {status}：{}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(4_000)
                .collect::<String>()
        );
    }
    serde_json::from_slice(&body).context("邮件处理 Worker 返回了无效结果")
}

fn add_forward_headers(
    spec: &EmailDomainSpec,
    message: &EmailMessage,
    raw: &[u8],
    extra: &[(String, String)],
) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(raw);
    let prior_hops = text
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .filter(|line| {
            line.to_ascii_lowercase()
                .starts_with("x-randallflare-forwarded:")
        })
        .count();
    if prior_hops >= 5 {
        bail!("邮件转发已达到 5 跳循环保护上限");
    }
    if extra.len() > 128 {
        bail!("Worker 转发附加头不得超过 128 项");
    }
    let mut headers = format!(
        "X-RandallFlare-Forwarded: {}; hop={}\r\nX-RandallFlare-Original-To: {}\r\n",
        spec.domain,
        prior_hops + 1,
        message.rcpt_to
    );
    for (name, value) in extra {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.len() > 8_192
            || value.contains(['\r', '\n'])
        {
            bail!("Worker 转发附加邮件头无效");
        }
        if headers.len().saturating_add(name.len() + value.len() + 4) > 32 * 1024 {
            bail!("Worker 转发附加邮件头总计不得超过 32 KiB");
        }
        headers.push_str(name);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    let mut forwarded = Vec::with_capacity(headers.len() + raw.len());
    forwarded.extend_from_slice(headers.as_bytes());
    forwarded.extend_from_slice(raw);
    Ok(forwarded)
}

async fn queue_forward(
    node: &Node,
    domain_name: &str,
    spec: &EmailDomainSpec,
    source: &EmailMessage,
    recipients: &[String],
    raw: &[u8],
) -> Result<usize> {
    let sender_tag = source.id.chars().take(16).collect::<String>();
    let mail_from = format!("forward+{sender_tag}@{}", spec.domain);
    let mut digest = Sha256::new();
    digest.update(b"forward\0");
    digest.update(source.id.as_bytes());
    digest.update([0]);
    digest.update(raw);
    let key = hex::encode(digest.finalize());
    Ok(
        queue_outbound_inner(node, domain_name, &mail_from, recipients, raw, Some(&key))
            .await?
            .len(),
    )
}

async fn finish_inbound(
    node: &Node,
    name: &str,
    claim: &OutboundClaim,
    outcome: Result<InboundOutcome>,
) -> Result<()> {
    let now = now_ms();
    let (status, next_attempt, last_error, response) = match outcome {
        Ok(InboundOutcome::Delivered) => ("delivered", None, None, Some("Worker 已处理".into())),
        Ok(InboundOutcome::Rejected(reason)) => {
            ("rejected", None, Some(reason), Some("Worker 已拒收".into()))
        }
        Ok(InboundOutcome::Forwarded(count)) => (
            "forwarded",
            None,
            None,
            Some(format!("已建立 {count} 个可靠转发投递")),
        ),
        Err(error) if claim.message.attempts >= OUTBOUND_MAX_ATTEMPTS => {
            ("failed", None, Some(format!("{error:#}")), None)
        }
        Err(error) => (
            "pending",
            Some(now.saturating_add(outbound_retry_delay_ms(claim.message.attempts))),
            Some(format!("{error:#}")),
            None,
        ),
    };
    let result = exec(
        node,
        name,
        r#"UPDATE email_messages SET
             status=?1,next_attempt_ms=?2,last_error=?3,smtp_response=?4,
             delivered_at_ms=CASE WHEN ?1 IN ('delivered','forwarded') THEN ?5 ELSE NULL END,
             lease_token=NULL,lease_until_ms=NULL,leased_by=NULL,updated_at_ms=?5
           WHERE id=?6 AND status='running' AND lease_token=?7"#,
        json!([
            status,
            next_attempt,
            last_error,
            response,
            now,
            claim.message.id,
            claim.lease,
        ]),
    )
    .await?;
    if result["rows_affected"].as_u64().unwrap_or(0) != 1 {
        bail!("邮件事件租约已失效");
    }
    append_audit(
        node,
        name,
        match status {
            "delivered" => "inbound_delivered",
            "forwarded" => "inbound_forwarded",
            "rejected" => "inbound_rejected",
            "failed" => "inbound_failed",
            _ => "inbound_retry_scheduled",
        },
        json!({
            "message_id": claim.message.id,
            "recipient": claim.message.rcpt_to,
            "attempt": claim.message.attempts,
            "status": status,
        }),
    )
    .await?;
    Ok(())
}

/// Run the durable outbound worker pool. Capability selection happens per
/// domain: a node must opt into email, match the signed MX hostname, opt into
/// outbound delivery and possess the named private-key environment variable.
pub fn spawn_driver(node: Arc<Node>) {
    if !node.cfg.email.enabled {
        return;
    }
    tokio::spawn(async move {
        let mut last_retention_sweep = BTreeMap::<String, u64>::new();
        loop {
            let mx_hostname = node.cfg.email.mx_hostname.as_deref().unwrap_or_default();
            for (view, spec) in email_domain_records(&node) {
                if spec.suspended || spec.mx_hostname != mx_hostname {
                    continue;
                }
                let name = &view.resource.name;
                let now = now_ms();
                if now.saturating_sub(*last_retention_sweep.get(name).unwrap_or(&0))
                    >= 60 * 60 * 1_000
                {
                    if let Err(error) = sweep_retention(&node, name, &spec).await {
                        tracing::warn!(domain = %spec.domain, "清理过期邮件记录失败：{error:#}");
                    } else {
                        last_retention_sweep.insert(name.clone(), now);
                    }
                }
                if let Err(error) = recover_inbound_leases(&node, name).await {
                    tracing::warn!(domain = %spec.domain, "恢复入站邮件租约失败：{error:#}");
                    continue;
                }
                for _ in 0..8 {
                    match process_inbound_once(&node, name, &spec).await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(domain = %spec.domain, "处理入站邮件失败：{error:#}");
                            break;
                        }
                    }
                }
                for _ in 0..8 {
                    match process_dsn_once(&node, name, &spec).await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(domain = %spec.domain, "生成邮件 DSN 失败：{error:#}");
                            break;
                        }
                    }
                }
                if !node.cfg.email.outbound
                    || spec.dkim_private_key_env.is_empty()
                    || std::env::var_os(&spec.dkim_private_key_env).is_none()
                {
                    continue;
                }
                if let Err(error) = recover_outbound_leases(&node, name).await {
                    tracing::warn!(domain = %spec.domain, "恢复邮件投递租约失败：{error:#}");
                    continue;
                }
                for _ in 0..8 {
                    match process_outbound_once(&node, name, &spec).await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(domain = %spec.domain, "处理出站邮件失败：{error:#}");
                            break;
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });
}

/// Remove terminal delivery records after the signed retention window. Shared
/// RFC 822 objects are deleted only after no message row references them.
pub async fn sweep_retention(
    node: &Node,
    domain_name: &str,
    spec: &EmailDomainSpec,
) -> Result<u64> {
    ensure_schema(node, domain_name).await?;
    let cutoff = now_ms().saturating_sub(u64::from(spec.retention_days) * 86_400_000);
    let expired = rows(
        exec(
            node,
            domain_name,
            r#"SELECT DISTINCT object_key FROM email_messages
               WHERE created_at_ms<?1
                 AND status IN ('sent','failed','delivered','rejected','forwarded','dropped')
               LIMIT 1000"#,
            json!([cutoff]),
        )
        .await?,
    );
    let deleted = exec(
        node,
        domain_name,
        r#"DELETE FROM email_messages
           WHERE created_at_ms<?1
             AND status IN ('sent','failed','delivered','rejected','forwarded','dropped')"#,
        json!([cutoff]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    for row in expired {
        let key = string_field(&row, "object_key")?;
        let references = rows(
            exec(
                node,
                domain_name,
                "SELECT COUNT(*) AS count FROM email_messages WHERE object_key=?1",
                json!([key]),
            )
            .await?,
        )
        .first()
        .map(|row| u64_field(row, "count"))
        .unwrap_or(0);
        if references == 0 {
            r2::delete_object(node, &spec.bucket, key).await?;
        }
    }
    exec(
        node,
        domain_name,
        "DELETE FROM email_audit WHERE created_at_ms<?1",
        json!([cutoff]),
    )
    .await?;
    exec(
        node,
        domain_name,
        "DELETE FROM email_rate_buckets WHERE window_ms<?1",
        json!([now_ms().saturating_sub(2 * 60 * 60 * 1_000)]),
    )
    .await?;
    if deleted > 0 {
        append_audit(
            node,
            domain_name,
            "retention_sweep",
            json!({ "deleted_messages": deleted, "cutoff_ms": cutoff }),
        )
        .await?;
    }
    Ok(deleted)
}

pub async fn process_outbound_once(
    node: &Node,
    domain_name: &str,
    spec: &EmailDomainSpec,
) -> Result<bool> {
    let Some(claim) = claim_outbound(node, domain_name).await? else {
        return Ok(false);
    };
    let raw = match r2::get_object(node, &spec.bucket, &claim.message.object_key).await {
        Ok(Some((_metadata, raw))) => raw,
        Ok(None) => {
            finish_outbound(
                node,
                domain_name,
                &claim,
                Err(DeliveryFailure {
                    permanent: true,
                    detail: "邮件原文对象不存在".into(),
                }),
            )
            .await?;
            return Ok(true);
        }
        Err(error) => {
            finish_outbound(
                node,
                domain_name,
                &claim,
                Err(DeliveryFailure {
                    permanent: false,
                    detail: format!("读取邮件原文失败：{error:#}"),
                }),
            )
            .await?;
            return Ok(true);
        }
    };
    let signed = match sign_dkim(spec, &raw) {
        Ok(signed) => signed,
        Err(error) => {
            finish_outbound(
                node,
                domain_name,
                &claim,
                Err(DeliveryFailure {
                    permanent: false,
                    detail: format!("DKIM 签名失败：{error:#}"),
                }),
            )
            .await?;
            return Ok(true);
        }
    };
    let outcome = deliver_direct_smtp(
        &spec.mx_hostname,
        &claim.message.mail_from,
        &claim.message.rcpt_to,
        &signed,
    )
    .await;
    finish_outbound(node, domain_name, &claim, outcome).await?;
    Ok(true)
}

async fn recover_outbound_leases(node: &Node, name: &str) -> Result<()> {
    ensure_schema(node, name).await?;
    let now = now_ms();
    exec(
        node,
        name,
        r#"UPDATE email_messages SET
             status=CASE WHEN attempts>=?1 THEN 'failed' ELSE 'queued' END,
             next_attempt_ms=CASE WHEN attempts>=?1 THEN NULL ELSE ?2 END,
             last_error=CASE WHEN attempts>=?1 THEN '投递节点失联，且已达到最大重试次数'
                             ELSE '投递节点失联，租约已恢复' END,
             dsn_status=CASE WHEN attempts>=?1 THEN COALESCE(dsn_status,'pending')
                             ELSE dsn_status END,
             dsn_next_attempt_ms=CASE WHEN attempts>=?1 THEN ?2 ELSE dsn_next_attempt_ms END,
             lease_token=NULL,lease_until_ms=NULL,leased_by=NULL,updated_at_ms=?2
           WHERE direction='outbound' AND status='sending'
             AND lease_until_ms IS NOT NULL AND lease_until_ms<?2"#,
        json!([OUTBOUND_MAX_ATTEMPTS, now]),
    )
    .await?;
    Ok(())
}

async fn claim_outbound(node: &Node, name: &str) -> Result<Option<OutboundClaim>> {
    ensure_schema(node, name).await?;
    let now = now_ms();
    let lease = new_id();
    let result = exec(
        node,
        name,
        &format!(
            r#"UPDATE email_messages SET
                 status='sending',attempts=attempts+1,lease_token=?1,
                 lease_until_ms=?2,leased_by=?3,updated_at_ms=?4
               WHERE id=(
                 SELECT id FROM email_messages
                 WHERE direction='outbound' AND status='queued'
                   AND attempts<?5 AND COALESCE(next_attempt_ms,0)<=?4
                 ORDER BY created_at_ms,id LIMIT 1
               )
               RETURNING {MESSAGE_FIELDS}"#
        ),
        json!([
            lease,
            now + OUTBOUND_LEASE_MS,
            node.id_hex(),
            now,
            OUTBOUND_MAX_ATTEMPTS,
        ]),
    )
    .await?;
    let Some(row) = rows(result).into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(OutboundClaim {
        message: row_to_message(&row)?,
        lease,
    }))
}

async fn finish_outbound(
    node: &Node,
    name: &str,
    claim: &OutboundClaim,
    outcome: std::result::Result<String, DeliveryFailure>,
) -> Result<()> {
    let now = now_ms();
    let (status, next_attempt, last_error, response, delivered_at) = match outcome {
        Ok(response) => ("delivered", None, None, Some(response), Some(now)),
        Err(failure) if failure.permanent || claim.message.attempts >= OUTBOUND_MAX_ATTEMPTS => {
            ("failed", None, Some(failure.detail), None, None)
        }
        Err(failure) => {
            let delay_ms = outbound_retry_delay_ms(claim.message.attempts);
            (
                "queued",
                Some(now.saturating_add(delay_ms)),
                Some(failure.detail),
                None,
                None,
            )
        }
    };
    let result = exec(
        node,
        name,
        r#"UPDATE email_messages SET
             status=?1,next_attempt_ms=?2,last_error=?3,smtp_response=?4,
             delivered_at_ms=?5,lease_token=NULL,lease_until_ms=NULL,leased_by=NULL,
             dsn_status=CASE
               WHEN ?1='failed' THEN COALESCE(dsn_status,'pending')
               WHEN ?1='delivered' THEN 'not_needed'
               ELSE dsn_status END,
             dsn_next_attempt_ms=CASE WHEN ?1='failed' THEN ?6 ELSE dsn_next_attempt_ms END,
             updated_at_ms=?6
           WHERE id=?7 AND status='sending' AND lease_token=?8"#,
        json!([
            status,
            next_attempt,
            last_error,
            response,
            delivered_at,
            now,
            claim.message.id,
            claim.lease,
        ]),
    )
    .await?;
    if result["rows_affected"].as_u64().unwrap_or(0) != 1 {
        bail!("邮件投递租约已失效");
    }
    append_audit(
        node,
        name,
        if status == "delivered" {
            "outbound_delivered"
        } else if status == "failed" {
            "outbound_failed"
        } else {
            "outbound_retry_scheduled"
        },
        json!({
            "message_id": claim.message.id,
            "recipient": claim.message.rcpt_to,
            "attempt": claim.message.attempts,
            "status": status,
        }),
    )
    .await?;
    Ok(())
}

/// Turn one terminal outbound failure into a locally routed RFC 3464-style
/// delivery-status notification. A fenced D1 lease prevents noisy duplicate
/// work, while the deterministic inbound ID makes crash replay harmless even
/// if a node dies after archiving the DSN but before committing the lease.
pub async fn process_dsn_once(
    node: &Node,
    domain_name: &str,
    spec: &EmailDomainSpec,
) -> Result<bool> {
    ensure_schema(node, domain_name).await?;
    let now = now_ms();
    let lease = new_id();
    let result = exec(
        node,
        domain_name,
        &format!(
            r#"UPDATE email_messages SET
                 dsn_status='generating',dsn_attempts=dsn_attempts+1,
                 dsn_lease_token=?1,dsn_lease_until_ms=?2,updated_at_ms=?3
               WHERE id=(
                 SELECT id FROM email_messages
                 WHERE direction='outbound' AND status='failed' AND dsn_attempts<?4
                   AND (
                     (COALESCE(dsn_status,'pending')='pending'
                      AND COALESCE(dsn_next_attempt_ms,0)<=?3)
                     OR (dsn_status='generating' AND dsn_lease_until_ms<=?3)
                   )
                 ORDER BY updated_at_ms,id LIMIT 1
               )
               RETURNING {MESSAGE_FIELDS}"#
        ),
        json!([
            lease,
            now.saturating_add(OUTBOUND_LEASE_MS),
            now,
            OUTBOUND_MAX_ATTEMPTS,
        ]),
    )
    .await?;
    let Some(row) = rows(result).into_iter().next() else {
        return Ok(false);
    };
    let message = row_to_message(&row)?;
    let outcome = generate_delivery_status(node, domain_name, spec, &message).await;
    let (status, dsn_message_id, next_attempt, last_error, event) = match outcome {
        Ok(DsnOutcome::Generated(id)) => ("generated", Some(id), None, None, "dsn_generated"),
        Ok(DsnOutcome::Skipped(reason)) => (
            "skipped",
            None,
            None,
            Some(reason.to_string()),
            "dsn_skipped",
        ),
        Err(error) if message.dsn_attempts >= OUTBOUND_MAX_ATTEMPTS => (
            "failed",
            None,
            None,
            Some(format!("{error:#}")),
            "dsn_failed",
        ),
        Err(error) => (
            "pending",
            None,
            Some(now.saturating_add(outbound_retry_delay_ms(message.dsn_attempts))),
            Some(format!("{error:#}")),
            "dsn_retry_scheduled",
        ),
    };
    let updated = exec(
        node,
        domain_name,
        r#"UPDATE email_messages SET dsn_status=?1,dsn_message_id=?2,
             dsn_next_attempt_ms=?3,dsn_last_error=?4,
             dsn_lease_token=NULL,dsn_lease_until_ms=NULL,updated_at_ms=?5
           WHERE id=?6 AND dsn_status='generating' AND dsn_lease_token=?7"#,
        json!([
            status,
            dsn_message_id,
            next_attempt,
            last_error,
            now_ms(),
            message.id,
            lease,
        ]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if updated != 1 {
        bail!("邮件 DSN 生成租约已失效");
    }
    append_audit(
        node,
        domain_name,
        event,
        json!({
            "message_id": message.id,
            "recipient": message.rcpt_to,
            "dsn_message_id": dsn_message_id,
            "attempt": message.dsn_attempts,
            "status": status,
        }),
    )
    .await?;
    Ok(true)
}

async fn generate_delivery_status(
    node: &Node,
    domain_name: &str,
    spec: &EmailDomainSpec,
    message: &EmailMessage,
) -> Result<DsnOutcome> {
    if message.mail_from.is_empty() {
        return Ok(DsnOutcome::Skipped("空逆向路径不生成 DSN"));
    }
    let (_, original) = r2::get_object(node, &spec.bucket, &message.object_key)
        .await?
        .context("生成 DSN 时找不到原始邮件对象")?;
    if is_automatic_message(&original) {
        return Ok(DsnOutcome::Skipped(
            "自动提交邮件不再生成 DSN，以阻断退信环",
        ));
    }
    let sender = normalize_address(&message.mail_from)?;
    let (_, sender_domain) = split_address(&sender)?;
    if sender_domain != spec.domain {
        bail!("DSN 原始发件人不属于当前签名邮件域");
    }
    let boundary = format!("rf-dsn-{}", stable_id(&message.id));
    let diagnostic = header_safe(message.last_error.as_deref().unwrap_or("远端 MX 拒绝投递"));
    let original_message_id = header_safe(message.message_id.as_deref().unwrap_or("unknown"));
    let recipient_kind = if message.rcpt_to.is_ascii() {
        "rfc822"
    } else {
        "utf-8"
    };
    let (report_type, delivery_status_type) =
        if message.mail_from.is_ascii() && message.rcpt_to.is_ascii() && diagnostic.is_ascii() {
            ("delivery-status", "message/delivery-status")
        } else {
            ("global-delivery-status", "message/global-delivery-status")
        };
    let enhanced_status = enhanced_status(&diagnostic);
    let raw = format!(
        "From: Mail Delivery Subsystem <mailer-daemon@{domain}>\r\n\
         To: {sender}\r\n\
         Subject: Delivery Status Notification (Failure)\r\n\
         Message-ID: <dsn-{id}@{domain}>\r\n\
         Auto-Submitted: auto-replied\r\n\
         X-RandallFlare-DSN-Of: {id}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type={report_type}; boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         您的邮件未能投递到 {recipient}。\r\n\
         详细原因：{diagnostic}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: {delivery_status_type}\r\n\
         \r\n\
         Reporting-MTA: dns; {mx}\r\n\
         Original-Envelope-Id: {id}\r\n\
         Original-Message-ID: {original_message_id}\r\n\
         \r\n\
         Final-Recipient: {recipient_kind}; {recipient}\r\n\
         Action: failed\r\n\
         Status: {enhanced_status}\r\n\
         Diagnostic-Code: X-RandallFlare; {diagnostic}\r\n\
         \r\n\
         --{boundary}--\r\n",
        domain = spec.domain,
        sender = sender,
        id = message.id,
        recipient = message.rcpt_to,
        diagnostic = diagnostic,
        mx = spec.mx_hostname,
        original_message_id = original_message_id,
        recipient_kind = recipient_kind,
        report_type = report_type,
        delivery_status_type = delivery_status_type,
        enhanced_status = enhanced_status,
        boundary = boundary,
    )
    .into_bytes();
    let envelope = InboundEnvelope {
        helo_domain: spec.mx_hostname.clone(),
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        mail_from: String::new(),
        recipients: vec![sender],
    };
    let key = format!("dsn:{}", message.id);
    let generated = ingest_inbound_inner(
        node,
        domain_name,
        &envelope,
        &raw,
        Some((&key, message.created_at_ms)),
    )
    .await?;
    let id = generated
        .first()
        .map(|message| message.id.clone())
        .context("DSN 写入后没有生成收件人记录")?;
    Ok(DsnOutcome::Generated(id))
}

fn is_automatic_message(raw: &[u8]) -> bool {
    String::from_utf8_lossy(raw)
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("auto-submitted")
                    .then(|| value.trim())
            })
        })
        .is_some_and(|value| !value.eq_ignore_ascii_case("no"))
}

fn header_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if matches!(character, '\r' | '\n') || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(2_000)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn enhanced_status(diagnostic: &str) -> &str {
    diagnostic
        .split_ascii_whitespace()
        .find(|value| {
            let bytes = value.as_bytes();
            bytes.len() == 5
                && matches!(bytes[0], b'4' | b'5')
                && bytes[1] == b'.'
                && bytes[2].is_ascii_digit()
                && bytes[3] == b'.'
                && bytes[4].is_ascii_digit()
        })
        .unwrap_or("5.0.0")
}

fn sign_dkim(spec: &EmailDomainSpec, raw: &[u8]) -> Result<Vec<u8>> {
    let pem = std::env::var(&spec.dkim_private_key_env)
        .with_context(|| format!("节点未配置 {}", spec.dkim_private_key_env))?;
    let key_der = PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("DKIM 私钥不是受支持的 PKCS#1/PKCS#8 PEM"))?;
    let key = RsaKey::<DkimSha256>::from_key_der(key_der)
        .map_err(|_| anyhow::anyhow!("无法载入 DKIM RSA 私钥"))?;
    let signature = DkimSigner::from_key(key)
        .domain(spec.domain.clone())
        .selector(spec.dkim_selector.clone())
        .headers([
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
            "Content-Type",
            "Content-Transfer-Encoding",
        ])
        .expiration(7 * 24 * 60 * 60)
        .sign(raw)
        .map_err(|error| anyhow::anyhow!("DKIM 计算失败：{error}"))?;
    let header = signature.to_header();
    let mut signed = Vec::with_capacity(header.len() + raw.len());
    signed.extend_from_slice(header.as_bytes());
    signed.extend_from_slice(raw);
    Ok(signed)
}

async fn deliver_direct_smtp(
    mx_hostname: &str,
    mail_from: &str,
    recipient: &str,
    raw: &[u8],
) -> std::result::Result<String, DeliveryFailure> {
    let (_, recipient_domain) = split_address(recipient).map_err(|error| DeliveryFailure {
        permanent: true,
        detail: format!("收件地址无效：{error:#}"),
    })?;
    let resolver = MessageAuthenticator::new_system_conf().map_err(|error| DeliveryFailure {
        permanent: false,
        detail: format!("无法初始化 DNS 解析器：{error}"),
    })?;
    let mut exchanges = match resolver.0.mx_lookup(recipient_domain).await {
        Ok(response) => {
            let mut values: Vec<(u16, String)> = response
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::MX(mx) => Some((
                        mx.preference,
                        mx.exchange
                            .to_utf8()
                            .trim_end_matches('.')
                            .to_ascii_lowercase(),
                    )),
                    _ => None,
                })
                .collect();
            values.sort();
            values.dedup();
            if values.is_empty() || values.iter().all(|(_, exchange)| exchange.is_empty()) {
                return Err(DeliveryFailure {
                    permanent: true,
                    detail: "收件域发布了 Null MX，不接收邮件".into(),
                });
            }
            values
                .into_iter()
                .filter(|(_, exchange)| !exchange.is_empty())
                .collect()
        }
        Err(mail_auth::hickory_resolver::net::NetError::Dns(
            mail_auth::hickory_resolver::net::DnsError::NoRecordsFound(no_records),
        )) if no_records.response_code
            == mail_auth::hickory_resolver::proto::op::ResponseCode::NoError =>
        {
            vec![(0, recipient_domain.into())]
        }
        Err(mail_auth::hickory_resolver::net::NetError::Dns(
            mail_auth::hickory_resolver::net::DnsError::NoRecordsFound(_),
        )) => {
            return Err(DeliveryFailure {
                permanent: true,
                detail: "收件域不存在".into(),
            });
        }
        Err(error) => {
            return Err(DeliveryFailure {
                permanent: false,
                detail: format!("查询收件域 MX 失败：{error}"),
            });
        }
    };
    exchanges.sort();
    let envelope = SmtpEnvelope::new(
        Some(
            mail_from
                .parse::<Address>()
                .map_err(|error| DeliveryFailure {
                    permanent: true,
                    detail: format!("发件地址无效：{error}"),
                })?,
        ),
        vec![recipient
            .parse::<Address>()
            .map_err(|error| DeliveryFailure {
                permanent: true,
                detail: format!("收件地址无效：{error}"),
            })?],
    )
    .map_err(|error| DeliveryFailure {
        permanent: true,
        detail: format!("SMTP 信封无效：{error}"),
    })?;

    let mut errors = Vec::new();
    let mut all_permanent = true;
    let requires_smtp_utf8 = !mail_from.is_ascii() || !recipient.is_ascii();
    for (_, exchange) in exchanges {
        let tls = match TlsParameters::new(exchange.clone()) {
            Ok(parameters) => Tls::Opportunistic(parameters),
            Err(error) => {
                errors.push(format!("{exchange}: TLS 配置失败：{error}"));
                all_permanent = false;
                continue;
            }
        };
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(exchange.clone())
            .port(25)
            .hello_name(ClientId::Domain(mx_hostname.into()))
            .tls(tls)
            .timeout(Some(std::time::Duration::from_secs(60)))
            .build();
        match transport.send_raw(&envelope, raw).await {
            Ok(response) => return Ok(format!("{exchange}: {response:?}")),
            Err(error) => {
                let detail = error.to_string();
                let smtp_utf8_rejected = requires_smtp_utf8
                    && detail
                        .to_ascii_lowercase()
                        .contains("does not support smtputf8");
                all_permanent &= error.is_permanent() || smtp_utf8_rejected;
                errors.push(format!("{exchange}: {detail}"));
            }
        }
    }
    Err(DeliveryFailure {
        permanent: all_permanent,
        detail: if errors.is_empty() {
            "收件域没有可用 MX".into()
        } else {
            errors.join("；")
        },
    })
}

pub async fn list_messages(node: &Node, name: &str, limit: usize) -> Result<Vec<EmailMessage>> {
    ensure_schema(node, name).await?;
    let limit = limit.clamp(1, 500);
    rows(
        exec(
            node,
            name,
            &format!(
                "SELECT {MESSAGE_FIELDS} FROM email_messages ORDER BY created_at_ms DESC,id DESC LIMIT ?1"
            ),
            json!([limit]),
        )
        .await?,
    )
    .iter()
    .map(row_to_message)
    .collect()
}

pub async fn get_message(node: &Node, name: &str, id: &str) -> Result<Option<EmailMessage>> {
    ensure_schema(node, name).await?;
    rows(
        exec(
            node,
            name,
            &format!("SELECT {MESSAGE_FIELDS} FROM email_messages WHERE id=?1"),
            json!([id]),
        )
        .await?,
    )
    .first()
    .map(row_to_message)
    .transpose()
}

async fn query_verification(
    spec: &EmailDomainSpec,
    checked_at_ms: u64,
) -> Result<EmailVerification> {
    let resolver = MessageAuthenticator::new_system_conf().context("无法读取系统 DNS 配置")?;
    let ownership_observed = txt_lookup(&resolver, &spec.ownership_txt_name()).await?;
    let dkim_observed = txt_lookup(&resolver, &spec.dkim_txt_name()).await?;
    let spf_observed = txt_lookup(&resolver, &spec.domain).await?;
    let mx_response = resolver
        .0
        .mx_lookup(spec.domain.as_str())
        .await
        .context("查询 MX 记录失败")?;
    let mut mx_observed: Vec<String> = mx_response
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::MX(mx) => Some(
                mx.exchange
                    .to_utf8()
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
            ),
            _ => None,
        })
        .collect();
    mx_observed.sort();
    mx_observed.dedup();
    let ownership_ok = ownership_observed
        .iter()
        .any(|value| value == &spec.ownership_txt_value());
    let mx_ok = mx_observed.iter().any(|value| value == &spec.mx_hostname);
    let dkim_ok = spec.dkim_public_key.is_empty()
        || dkim_observed
            .iter()
            .any(|value| normalize_txt(value) == normalize_txt(&spec.dkim_public_key));
    let spf_present = spf_observed
        .iter()
        .any(|value| value.to_ascii_lowercase().starts_with("v=spf1"));
    Ok(EmailVerification {
        domain: spec.domain.clone(),
        ownership_ok,
        mx_ok,
        dkim_ok,
        spf_present,
        verified: ownership_ok && mx_ok && dkim_ok,
        ownership_observed,
        mx_observed,
        dkim_observed,
        spf_observed,
        checked_at_ms,
        error: None,
    })
}

async fn txt_lookup(authenticator: &MessageAuthenticator, name: &str) -> Result<Vec<String>> {
    let response = authenticator
        .0
        .txt_lookup(name)
        .await
        .with_context(|| format!("查询 TXT 记录失败：{name}"))?;
    let mut values: Vec<String> = response
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
    values.sort();
    values.dedup();
    Ok(values)
}

async fn authenticate_message(
    mx_hostname: &str,
    envelope: &InboundEnvelope,
    raw: &[u8],
) -> Option<AuthSummary> {
    let message = AuthenticatedMessage::parse(raw)?;
    let authenticator = MessageAuthenticator::new_system_conf().ok()?;
    let dkim = authenticator.verify_dkim(&message).await;
    let spf = authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            envelope.client_ip,
            &envelope.helo_domain,
            mx_hostname,
            &envelope.mail_from,
        ))
        .await;
    let mail_from_domain = envelope
        .mail_from
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or(&envelope.helo_domain);
    let dmarc = authenticator
        .verify_dmarc(DmarcParameters::new(
            &message,
            &dkim,
            mail_from_domain,
            &spf,
        ))
        .await;
    let header_from = message.from.first().map(String::as_str).unwrap_or("");
    let header = AuthenticationResults::new(mx_hostname)
        .with_dkim_results(&dkim, header_from)
        .with_spf_mailfrom_result(
            &spf,
            envelope.client_ip,
            &envelope.mail_from,
            &envelope.helo_domain,
        )
        .with_dmarc_result(&dmarc)
        .to_string();
    let dkim_status = if dkim
        .iter()
        .any(|output| matches!(output.result(), DkimResult::Pass))
    {
        "pass"
    } else if dkim.is_empty() {
        "none"
    } else {
        "fail"
    };
    let dmarc_status = if matches!(dmarc.dkim_result(), DmarcResult::Pass)
        || matches!(dmarc.spf_result(), DmarcResult::Pass)
    {
        "pass"
    } else if matches!(dmarc.dkim_result(), DmarcResult::None)
        && matches!(dmarc.spf_result(), DmarcResult::None)
    {
        "none"
    } else {
        "fail"
    };
    Some(AuthSummary {
        header,
        spf: match spf.result() {
            SpfResult::Pass => "pass",
            SpfResult::Fail | SpfResult::SoftFail => "fail",
            SpfResult::TempError => "temperror",
            SpfResult::PermError => "permerror",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
        }
        .into(),
        dkim: dkim_status.into(),
        dmarc: dmarc_status.into(),
    })
}

async fn enforce_rate_limit(
    node: &Node,
    name: &str,
    scope: &str,
    limit: u32,
    increment: u32,
) -> Result<()> {
    let window_ms = now_ms() / 60_000 * 60_000;
    exec(
        node,
        name,
        r#"INSERT INTO email_rate_buckets(scope,window_ms,count)
           VALUES(?1,?2,?3)
           ON CONFLICT(scope,window_ms) DO UPDATE SET count=count+excluded.count"#,
        json!([scope, window_ms, increment]),
    )
    .await?;
    let count = rows(
        exec(
            node,
            name,
            "SELECT count FROM email_rate_buckets WHERE scope=?1 AND window_ms=?2",
            json!([scope, window_ms]),
        )
        .await?,
    )
    .first()
    .map(|row| u64_field(row, "count"))
    .unwrap_or(0);
    if count > u64::from(limit) {
        bail!("邮件域已超过每分钟 {limit} 封的 {scope} 速率限制");
    }
    Ok(())
}

async fn append_audit(node: &Node, name: &str, kind: &str, detail: Value) -> Result<()> {
    exec(
        node,
        name,
        "INSERT INTO email_audit(id,kind,detail_json,created_at_ms) VALUES(?1,?2,?3,?4)",
        json!([new_id(), kind, serde_json::to_string(&detail)?, now_ms()]),
    )
    .await?;
    Ok(())
}

async fn ensure_schema(node: &Node, name: &str) -> Result<()> {
    let database = database_name(name);
    d1::ensure_database(node, &database)?;
    if node.email_schema_ready(&database) {
        return Ok(());
    }
    for sql in [
        r#"CREATE TABLE IF NOT EXISTS email_verification (
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             domain TEXT NOT NULL,
             ownership_ok INTEGER NOT NULL,
             mx_ok INTEGER NOT NULL,
             dkim_ok INTEGER NOT NULL,
             spf_present INTEGER NOT NULL,
             verified INTEGER NOT NULL,
             ownership_json TEXT NOT NULL,
             mx_json TEXT NOT NULL,
             dkim_json TEXT NOT NULL,
             spf_json TEXT NOT NULL,
             checked_at_ms INTEGER NOT NULL,
             error TEXT
           )"#,
        r#"CREATE TABLE IF NOT EXISTS email_messages (
             id TEXT PRIMARY KEY,
             direction TEXT NOT NULL,
             mail_from TEXT NOT NULL,
             rcpt_to TEXT NOT NULL,
             subject TEXT,
             message_id TEXT,
             object_key TEXT NOT NULL,
             size INTEGER NOT NULL,
             sha256 TEXT NOT NULL,
             status TEXT NOT NULL,
             route_id TEXT,
             target TEXT,
             auth_results TEXT,
             spf TEXT,
             dkim TEXT,
             dmarc TEXT,
             attempts INTEGER NOT NULL DEFAULT 0,
             next_attempt_ms INTEGER,
             lease_token TEXT,
             lease_until_ms INTEGER,
             leased_by TEXT,
             last_error TEXT,
             smtp_response TEXT,
             delivered_at_ms INTEGER,
             dsn_status TEXT,
             dsn_message_id TEXT,
             dsn_attempts INTEGER NOT NULL DEFAULT 0,
             dsn_next_attempt_ms INTEGER,
             dsn_last_error TEXT,
             dsn_lease_token TEXT,
             dsn_lease_until_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL
           )"#,
        "CREATE INDEX IF NOT EXISTS email_messages_ready ON email_messages(direction,status,next_attempt_ms,created_at_ms)",
        "CREATE INDEX IF NOT EXISTS email_messages_created ON email_messages(created_at_ms DESC,id DESC)",
        "CREATE INDEX IF NOT EXISTS email_messages_recipient ON email_messages(rcpt_to,created_at_ms DESC)",
        r#"CREATE TABLE IF NOT EXISTS email_rate_buckets (
             scope TEXT NOT NULL,
             window_ms INTEGER NOT NULL,
             count INTEGER NOT NULL,
             PRIMARY KEY(scope,window_ms)
           )"#,
        r#"CREATE TABLE IF NOT EXISTS email_audit (
             id TEXT PRIMARY KEY,
             kind TEXT NOT NULL,
             detail_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL
           )"#,
        "CREATE INDEX IF NOT EXISTS email_audit_created ON email_audit(created_at_ms DESC,id DESC)",
    ] {
        exec_database(node, &database, sql, json!([])).await?;
    }
    for (column, definition) in [
        ("dsn_status", "TEXT"),
        ("dsn_message_id", "TEXT"),
        ("dsn_attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("dsn_next_attempt_ms", "INTEGER"),
        ("dsn_last_error", "TEXT"),
        ("dsn_lease_token", "TEXT"),
        ("dsn_lease_until_ms", "INTEGER"),
    ] {
        ensure_column(node, &database, "email_messages", column, definition).await?;
    }
    exec_database(
        node,
        &database,
        "CREATE INDEX IF NOT EXISTS email_messages_dsn_ready ON email_messages(direction,status,dsn_status,dsn_next_attempt_ms,updated_at_ms)",
        json!([]),
    )
    .await?;
    node.mark_email_schema_ready(database);
    Ok(())
}

async fn ensure_column(
    node: &Node,
    database: &str,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let info = exec_database(
        node,
        database,
        &format!("PRAGMA table_info({table})"),
        json!([]),
    )
    .await?;
    if rows(info)
        .iter()
        .any(|row| row.get("name").and_then(Value::as_str) == Some(column))
    {
        return Ok(());
    }
    exec_database(
        node,
        database,
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        json!([]),
    )
    .await?;
    Ok(())
}

async fn exec(node: &Node, name: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &database_name(name), sql, params).await
}

async fn exec_database(node: &Node, database: &str, sql: &str, params: Value) -> Result<Value> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let listen = node.cfg.peer_api.listen;
    let base = if listen.is_ipv6() {
        format!("[::1]:{}", listen.port())
    } else {
        format!("127.0.0.1:{}", listen.port())
    };
    client.d1_exec(&base, database, sql, params).await
}

const MESSAGE_FIELDS: &str = "id,direction,mail_from,rcpt_to,subject,message_id,object_key,size,sha256,status,route_id,target,auth_results,spf,dkim,dmarc,attempts,last_error,dsn_status,dsn_message_id,dsn_attempts,dsn_last_error,created_at_ms,updated_at_ms";

fn rows(result: Value) -> Vec<Value> {
    result["rows"].as_array().cloned().unwrap_or_default()
}

fn row_to_message(row: &Value) -> Result<EmailMessage> {
    Ok(EmailMessage {
        id: string_field(row, "id")?.into(),
        direction: string_field(row, "direction")?.into(),
        mail_from: string_field(row, "mail_from")?.into(),
        rcpt_to: string_field(row, "rcpt_to")?.into(),
        subject: optional_string_field(row, "subject"),
        message_id: optional_string_field(row, "message_id"),
        object_key: string_field(row, "object_key")?.into(),
        size: u64_field(row, "size"),
        sha256: string_field(row, "sha256")?.into(),
        status: string_field(row, "status")?.into(),
        route_id: optional_string_field(row, "route_id"),
        target: optional_string_field(row, "target"),
        auth_results: optional_string_field(row, "auth_results"),
        spf: optional_string_field(row, "spf"),
        dkim: optional_string_field(row, "dkim"),
        dmarc: optional_string_field(row, "dmarc"),
        attempts: u64_field(row, "attempts") as u16,
        last_error: optional_string_field(row, "last_error"),
        dsn_status: optional_string_field(row, "dsn_status"),
        dsn_message_id: optional_string_field(row, "dsn_message_id"),
        dsn_attempts: u64_field(row, "dsn_attempts") as u16,
        dsn_last_error: optional_string_field(row, "dsn_last_error"),
        created_at_ms: u64_field(row, "created_at_ms"),
        updated_at_ms: u64_field(row, "updated_at_ms"),
    })
}

fn row_to_verification(row: &Value) -> Result<EmailVerification> {
    Ok(EmailVerification {
        domain: string_field(row, "domain")?.into(),
        ownership_ok: bool_field(row, "ownership_ok"),
        mx_ok: bool_field(row, "mx_ok"),
        dkim_ok: bool_field(row, "dkim_ok"),
        spf_present: bool_field(row, "spf_present"),
        verified: bool_field(row, "verified"),
        ownership_observed: json_vec_field(row, "ownership_json")?,
        mx_observed: json_vec_field(row, "mx_json")?,
        dkim_observed: json_vec_field(row, "dkim_json")?,
        spf_observed: json_vec_field(row, "spf_json")?,
        checked_at_ms: u64_field(row, "checked_at_ms"),
        error: optional_string_field(row, "error"),
    })
}

fn string_field<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("邮件数据库行缺少 {field}"))
}

fn optional_string_field(row: &Value, field: &str) -> Option<String> {
    row.get(field).and_then(Value::as_str).map(str::to_string)
}

fn u64_field(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn bool_field(row: &Value, field: &str) -> bool {
    row.get(field)
        .and_then(Value::as_bool)
        .or_else(|| {
            row.get(field)
                .and_then(Value::as_u64)
                .map(|value| value != 0)
        })
        .unwrap_or(false)
}

fn json_vec_field(row: &Value, field: &str) -> Result<Vec<String>> {
    serde_json::from_str(string_field(row, field)?).with_context(|| format!("{field} JSON 无效"))
}

fn split_address(address: &str) -> Result<(&str, &str)> {
    if address.len() > 320 || address.contains(['\r', '\n', ' ', '<', '>']) {
        bail!("邮件地址格式无效");
    }
    let (local, domain) = address.rsplit_once('@').context("邮件地址缺少 @")?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.chars().all(valid_local_match_char)
        || !valid_domain(&domain.to_ascii_lowercase())
    {
        bail!("邮件地址格式无效");
    }
    Ok((local, domain))
}

fn normalize_address(address: &str) -> Result<String> {
    let (local, domain) = split_address(address)?;
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

fn valid_local_match_char(character: char) -> bool {
    if !character.is_ascii() {
        return !character.is_control() && !character.is_whitespace();
    }
    let byte = character as u8;
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
                | b'.'
        )
}

fn valid_domain(domain: &str) -> bool {
    rf_core::manifest::valid_hostname(domain) && domain.contains('.') && domain.len() <= 253
}

fn valid_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector.len() <= 63
        && selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty()
        || prefix.len() > 512
        || prefix.starts_with('/')
        || prefix.ends_with('/')
        || prefix.contains("..")
        || prefix.contains(['\\', '\r', '\n'])
    {
        bail!("邮件 R2 对象前缀无效");
    }
    Ok(())
}

fn normalize_txt(value: &str) -> String {
    value.split_whitespace().collect::<String>()
}

fn object_key(spec: &EmailDomainSpec, direction: &str, timestamp: u64, id: &str) -> String {
    let datetime = time::OffsetDateTime::from_unix_timestamp((timestamp / 1_000) as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{}/{}/{}/{:02}/{:02}/{}.eml",
        spec.object_prefix,
        direction,
        datetime.year(),
        datetime.month() as u8,
        datetime.day(),
        id
    )
}

fn outbound_retry_delay_ms(attempt: u16) -> u64 {
    let exponent = u32::from(attempt.saturating_sub(1)).min(4);
    30_000_u64.saturating_mul(4_u64.pow(exponent))
}

fn new_id() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

fn stable_id(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> EmailDomainSpec {
        EmailDomainSpec {
            description: "测试域".into(),
            domain: "mail.example.com".into(),
            verification_challenge: "abcdefghijklmnop".into(),
            mx_hostname: "mx.example.com".into(),
            bucket: "mail-raw".into(),
            object_prefix: "mail".into(),
            routes: vec![
                EmailRoute {
                    id: "admin".into(),
                    priority: 0,
                    enabled: true,
                    matcher: EmailMatcher::Exact {
                        value: "admin@mail.example.com".into(),
                    },
                    destination: EmailDestination::Worker {
                        worker: "mail-worker".into(),
                    },
                },
                EmailRoute {
                    id: "support".into(),
                    priority: 10,
                    enabled: true,
                    matcher: EmailMatcher::Prefix {
                        value: "support+".into(),
                    },
                    destination: EmailDestination::Forward {
                        addresses: vec!["help@example.net".into()],
                    },
                },
                EmailRoute {
                    id: "fallback".into(),
                    priority: 100,
                    enabled: true,
                    matcher: EmailMatcher::CatchAll,
                    destination: EmailDestination::Drop,
                },
            ],
            max_message_bytes: DEFAULT_MESSAGE_BYTES,
            inbound_per_minute: 100,
            outbound_per_minute: 100,
            retention_days: 30,
            dkim_selector: "rf".into(),
            dkim_public_key: "v=DKIM1; k=rsa; p=abc".into(),
            dkim_private_key_env: "RF_EMAIL_DKIM_MAIL_EXAMPLE_COM".into(),
            suspended: false,
            suspend_reason: String::new(),
        }
    }

    #[test]
    fn validates_domain_without_private_key_material() {
        let spec = spec();
        spec.validate().unwrap();
        let encoded = serde_json::to_string(&spec).unwrap();
        let decoded: EmailDomainSpec = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, spec);
        assert!(encoded.contains("RF_EMAIL_DKIM_MAIL_EXAMPLE_COM"));
        assert!(!encoded.contains("PRIVATE KEY"));
        assert_eq!(
            spec.ownership_txt_name(),
            "_randallflare-verify.mail.example.com"
        );
    }

    #[test]
    fn route_wire_format_rejects_unknown_fields_without_breaking_flattened_matcher() {
        let route: EmailRoute = serde_json::from_value(json!({
            "id": "fallback",
            "priority": 100,
            "enabled": true,
            "match": "catch_all",
            "destination": { "type": "drop" }
        }))
        .unwrap();
        assert!(matches!(route.matcher, EmailMatcher::CatchAll));
        assert!(serde_json::from_value::<EmailRoute>(json!({
            "id": "bad",
            "match": "catch_all",
            "unexpected": true,
            "destination": { "type": "drop" }
        }))
        .is_err());
    }

    #[test]
    fn route_order_is_exact_then_prefix_then_catch_all() {
        let spec = spec();
        assert_eq!(
            route_for(&spec, "admin@mail.example.com").unwrap().id,
            "admin"
        );
        assert_eq!(
            route_for(&spec, "support+42@mail.example.com").unwrap().id,
            "support"
        );
        assert_eq!(
            route_for(&spec, "someone@mail.example.com").unwrap().id,
            "fallback"
        );
    }

    #[test]
    fn rejects_secret_value_and_duplicate_exact_routes() {
        let mut spec = spec();
        spec.dkim_private_key_env = "-----BEGIN PRIVATE KEY-----".into();
        assert!(spec.validate().is_err());
        spec.dkim_private_key_env = "RF_EMAIL_DKIM_MAIL_EXAMPLE_COM".into();
        spec.routes.push(EmailRoute {
            id: "duplicate".into(),
            priority: 1,
            enabled: true,
            matcher: EmailMatcher::Exact {
                value: "ADMIN@mail.example.com".into(),
            },
            destination: EmailDestination::Drop,
        });
        assert!(spec.validate().is_err());
    }

    #[test]
    fn outbound_retry_schedule_is_bounded_exponential() {
        assert_eq!(outbound_retry_delay_ms(1), 30_000);
        assert_eq!(outbound_retry_delay_ms(2), 120_000);
        assert_eq!(outbound_retry_delay_ms(3), 480_000);
        assert_eq!(outbound_retry_delay_ms(4), 1_920_000);
        assert_eq!(outbound_retry_delay_ms(5), 7_680_000);
        assert_eq!(outbound_retry_delay_ms(99), 7_680_000);
        assert_eq!(stable_id("same"), stable_id("same"));
        assert_ne!(stable_id("same"), stable_id("other"));
    }

    #[test]
    fn smtp_utf8_addresses_preserve_local_part_and_normalize_domain() {
        assert_eq!(
            normalize_address("张三@MAIL.EXAMPLE.COM").unwrap(),
            "张三@mail.example.com"
        );
        assert!("张三@mail.example.com".parse::<Address>().is_ok());
        assert!(split_address("bad..local@mail.example.com").is_err());
        assert!(split_address(" bad@mail.example.com").is_err());
    }

    #[test]
    fn automatic_submission_detection_blocks_dsn_loops() {
        assert!(is_automatic_message(
            b"From: daemon@example.com\r\nAuto-Submitted: auto-replied\r\n\r\nbody"
        ));
        assert!(!is_automatic_message(
            b"From: sender@example.com\r\nAuto-Submitted: no\r\n\r\nbody"
        ));
        assert_eq!(
            header_safe("550 failed\r\nInjected: bad"),
            "550 failed Injected: bad"
        );
        assert_eq!(enhanced_status("550 5.1.1 user unknown"), "5.1.1");
        assert_eq!(enhanced_status("connection refused"), "5.0.0");
    }

    #[test]
    fn r2_object_key_uses_real_utc_calendar_components() {
        let key = object_key(&spec(), "inbound", 1_735_689_600_000, "message");
        assert_eq!(key, "mail/inbound/2025/01/01/message.eml");
    }
}
