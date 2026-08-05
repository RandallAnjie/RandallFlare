//! Node-local GitHub App integration.
//!
//! App credentials deliberately never enter a signed resource or the cluster
//! KV. A node reads them from environment variables, mints a short-lived App
//! JWT, exchanges it for an installation token and drops/zeroizes all secret
//! material after the build. GitHub remains an optional source/status sink,
//! never RandallFlare's control plane.

use crate::build::{BuildJob, BuildState};
use crate::node::Node;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, Response};
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

const API: &str = "https://api.github.com";
const USER_AGENT: &str = "RandallFlare-node";
const COMMENT_MARKER: &str = "<!-- randallflare-workers-pr-bot -->";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubContext {
    pub repository: String,
    #[serde(default)]
    pub installation_id: Option<u64>,
    #[serde(default)]
    pub pull_request: Option<u64>,
    #[serde(default)]
    pub check_run_id: Option<u64>,
    #[serde(default)]
    pub comment_id: Option<u64>,
}

pub fn app_configured(node: &Node) -> bool {
    app_configured_build(&node.cfg.build)
}

pub fn app_configured_build(build: &crate::config::BuildConfig) -> bool {
    [
        &build.github_app_id_env,
        &build.github_app_private_key_env,
        &build.github_app_webhook_secret_env,
    ]
    .iter()
    .all(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

pub fn webhook_secret(node: &Node) -> Result<Zeroizing<String>> {
    secret_env(
        &node.cfg.build.github_app_webhook_secret_env,
        "GitHub App Webhook 密钥",
    )
}

pub fn verify_webhook(secret: &[u8], signature: &str, body: &[u8]) -> bool {
    let Some(hex_signature) = signature.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_signature) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

pub async fn installation_token(
    node: &Node,
    repository: &str,
    installation_hint: Option<u64>,
) -> Result<Zeroizing<String>> {
    let app_id = secret_env(&node.cfg.build.github_app_id_env, "GitHub App ID")?;
    if !app_id.chars().all(|c| c.is_ascii_digit()) || app_id.len() > 32 {
        bail!("GitHub App ID 格式无效");
    }
    let encoded_key = secret_env(
        &node.cfg.build.github_app_private_key_env,
        "GitHub App 私钥",
    )?;
    let pem = Zeroizing::new(
        general_purpose::STANDARD
            .decode(encoded_key.as_bytes())
            .context("GitHub App 私钥必须是 base64 编码的 PEM")?,
    );
    let jwt = mint_app_jwt(&app_id, &pem)?;

    let client = github_client()?;
    let slug = repository_slug(repository)?;
    let response = app_request(
        &client,
        Method::GET,
        &format!("/repos/{slug}/installation"),
        &jwt,
        None,
    )
    .await?;
    let value = checked_json(response, "查找 GitHub App 安装").await?;
    let installation_id = value
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("GitHub 安装响应缺少 id"))?;
    if installation_id == 0 {
        bail!("GitHub 安装 ID 无效");
    }
    if installation_hint.is_some_and(|hint| hint != installation_id) {
        bail!("Webhook 的 GitHub 安装 ID 与仓库实际安装不一致");
    }
    let response = app_request(
        &client,
        Method::POST,
        &format!("/app/installations/{installation_id}/access_tokens"),
        &jwt,
        Some(json!({})),
    )
    .await?;
    let value = checked_json(response, "签发 GitHub 安装令牌").await?;
    let token = value
        .get("token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("GitHub 安装响应缺少 token"))?;
    Ok(Zeroizing::new(token.to_string()))
}

fn mint_app_jwt(app_id: &str, pem: &[u8]) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(pem)
        .context("GitHub App PEM 不是 UTF-8")?
        .trim();
    let (kind, body) = if let Some(body) = pem_body(text, "RSA PRIVATE KEY") {
        ("pkcs1", body)
    } else if let Some(body) = pem_body(text, "PRIVATE KEY") {
        ("pkcs8", body)
    } else {
        bail!("GitHub App 私钥必须是 PKCS#1 或 PKCS#8 PEM");
    };
    let der = Zeroizing::new(
        general_purpose::STANDARD
            .decode(body.as_bytes())
            .context("GitHub App PEM 内容无效")?,
    );
    let key = if kind == "pkcs1" {
        RsaKeyPair::from_der(&der)
    } else {
        RsaKeyPair::from_pkcs8(&der)
    }
    .map_err(|_| anyhow::anyhow!("GitHub App RSA 私钥无法解析"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let header = general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "iat": now.saturating_sub(60),
        "exp": now.saturating_add(540),
        "iss": app_id,
    }))?);
    let signing_input = format!("{header}.{claims}");
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| anyhow::anyhow!("GitHub App JWT 签名失败"))?;
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&signature);
    signature.zeroize();
    Ok(Zeroizing::new(format!("{signing_input}.{encoded}")))
}

fn pem_body(text: &str, label: &str) -> Option<Zeroizing<String>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text.strip_prefix(&begin)?.strip_suffix(&end)?;
    Some(Zeroizing::new(
        body.chars().filter(|c| !c.is_ascii_whitespace()).collect(),
    ))
}

async fn app_request(
    client: &Client,
    method: Method,
    path: &str,
    jwt: &str,
    body: Option<Value>,
) -> Result<Response> {
    let mut request = client
        .request(method, format!("{API}{path}"))
        .header("accept", "application/vnd.github+json")
        .header("authorization", format!("Bearer {jwt}"))
        .header("user-agent", USER_AGENT)
        .header("x-github-api-version", "2022-11-28");
    if let Some(body) = body {
        request = request.json(&body);
    }
    request.send().await.context("连接 GitHub API")
}

async fn token_request(
    client: &Client,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Result<Response> {
    let mut request = client
        .request(method, format!("{API}{path}"))
        .header("accept", "application/vnd.github+json")
        .header("authorization", format!("Bearer {token}"))
        .header("user-agent", USER_AGENT)
        .header("x-github-api-version", "2022-11-28");
    if let Some(body) = body {
        request = request.json(&body);
    }
    request.send().await.context("连接 GitHub API")
}

async fn checked_json(response: Response, action: &str) -> Result<Value> {
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("读取{action}响应"))?;
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&bytes);
        bail!(
            "{action}失败（HTTP {status}）：{}",
            detail.chars().take(240).collect::<String>()
        );
    }
    serde_json::from_slice(&bytes).with_context(|| format!("解析{action}响应"))
}

pub async fn sync_pull_request(node: &Node, token: &str, job: &mut BuildJob) -> Result<()> {
    let Some(mut context) = job.github.clone() else {
        return Ok(());
    };
    let Some(number) = context.pull_request else {
        return Ok(());
    };
    let slug = repository_slug(&context.repository)?;
    let client = github_client()?;
    let details_url = job.preview_url.clone();
    let output = json!({
        "title": status_title(job.state),
        "summary": status_summary(job),
    });
    if let Some(id) = context.check_run_id {
        let mut body = json!({ "output": output });
        if let Some(conclusion) = conclusion(job.state) {
            body["status"] = Value::String("completed".into());
            body["conclusion"] = Value::String(conclusion.into());
        } else {
            body["status"] = Value::String("in_progress".into());
        }
        if let Some(url) = details_url.as_deref() {
            body["details_url"] = Value::String(url.to_string());
        }
        let response = token_request(
            &client,
            Method::PATCH,
            &format!("/repos/{slug}/check-runs/{id}"),
            token,
            Some(body),
        )
        .await?;
        checked_empty(response, "更新 GitHub Check Run").await?;
    } else if let Some(head_sha) = job.requested_commit.as_deref().or(job.commit.as_deref()) {
        let mut body = json!({
            "name": "RandallFlare Worker 预览",
            "head_sha": head_sha,
            "status": "in_progress",
            "output": output,
        });
        if let Some(conclusion) = conclusion(job.state) {
            body["status"] = Value::String("completed".into());
            body["conclusion"] = Value::String(conclusion.into());
        }
        if let Some(url) = details_url.as_deref() {
            body["details_url"] = Value::String(url.to_string());
        }
        let value = checked_json(
            token_request(
                &client,
                Method::POST,
                &format!("/repos/{slug}/check-runs"),
                token,
                Some(body),
            )
            .await?,
            "创建 GitHub Check Run",
        )
        .await?;
        context.check_run_id = value.get("id").and_then(Value::as_u64);
        job.github = Some(context.clone());
    }

    let comment = render_comment(job);
    if context.comment_id.is_none() {
        let response = token_request(
            &client,
            Method::GET,
            &format!("/repos/{slug}/issues/{number}/comments?per_page=100"),
            token,
            None,
        )
        .await?;
        let comments = checked_json(response, "读取 GitHub PR 评论").await?;
        let expected_app_id = context_app_id(node)?;
        context.comment_id = comments.as_array().and_then(|items| {
            items.iter().find_map(|item| {
                item.get("body")
                    .and_then(Value::as_str)
                    .filter(|body| body.contains(COMMENT_MARKER))
                    .filter(|_| {
                        item.pointer("/performed_via_github_app/id")
                            .and_then(Value::as_u64)
                            == Some(expected_app_id)
                    })
                    .and_then(|_| item.get("id").and_then(Value::as_u64))
            })
        });
        job.github = Some(context.clone());
    }
    if let Some(id) = context.comment_id {
        let response = token_request(
            &client,
            Method::PATCH,
            &format!("/repos/{slug}/issues/comments/{id}"),
            token,
            Some(json!({ "body": comment })),
        )
        .await?;
        checked_empty(response, "更新 GitHub PR 评论").await?;
    } else {
        let value = checked_json(
            token_request(
                &client,
                Method::POST,
                &format!("/repos/{slug}/issues/{number}/comments"),
                token,
                Some(json!({ "body": comment })),
            )
            .await?,
            "创建 GitHub PR 评论",
        )
        .await?;
        context.comment_id = value.get("id").and_then(Value::as_u64);
        job.github = Some(context.clone());
    }
    job.github = Some(context);
    Ok(())
}

async fn checked_empty(response: Response, action: &str) -> Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let detail = response.text().await.unwrap_or_default();
    bail!(
        "{action}失败（HTTP {status}）：{}",
        detail.chars().take(240).collect::<String>()
    )
}

fn status_title(state: BuildState) -> &'static str {
    match state {
        BuildState::Queued => "等待构建节点",
        BuildState::Cloning => "正在检出源码",
        BuildState::Building => "正在构建",
        BuildState::Packaging => "正在封装产物",
        BuildState::AwaitingApproval => "等待管理员签名批准",
        BuildState::Deployed => "预览已经发布",
        BuildState::Failed => "构建失败",
    }
}

fn status_summary(job: &BuildJob) -> String {
    let mut text = format!("Worker `{}`：{}。", job.worker, status_title(job.state));
    if let Some(url) = job.preview_url.as_deref() {
        text.push_str(&format!("\n\n预览：{url}"));
    }
    if job.state == BuildState::Failed {
        if let Some(error) = job.error.as_deref() {
            text.push_str(&format!(
                "\n\n{}",
                escape_markdown(error).chars().take(500).collect::<String>()
            ));
        }
    }
    text
}

fn render_comment(job: &BuildJob) -> String {
    let icon = match job.state {
        BuildState::Deployed => "✅",
        BuildState::Failed => "❌",
        BuildState::AwaitingApproval => "🔐",
        _ => "🟡",
    };
    let mut lines = vec![
        COMMENT_MARKER.to_string(),
        String::new(),
        "### RandallFlare Worker 预览".into(),
        String::new(),
        format!("{icon} **{}**", status_title(job.state)),
        String::new(),
        "| 项目 | 内容 |".into(),
        "|---|---|".into(),
        format!("| Worker | `{}` |", job.worker),
    ];
    if let Some(commit) = job.requested_commit.as_deref().or(job.commit.as_deref()) {
        lines.push(format!("| 提交 | `{}` |", &commit[..commit.len().min(12)]));
    }
    if let Some(version) = job.version {
        lines.push(format!("| 版本 | `v{version}` |"));
    }
    if let Some(url) = job.preview_url.as_deref() {
        lines.push(format!("| 预览 | {url} |"));
    }
    if job.state == BuildState::Failed {
        if let Some(error) = job.error.as_deref() {
            lines.extend([
                String::new(),
                "<details><summary>失败原因</summary>".into(),
                String::new(),
                escape_markdown(error).chars().take(1000).collect(),
                String::new(),
                "</details>".into(),
            ]);
        }
    }
    lines.extend([
        String::new(),
        "_此状态由构建节点直接回写；GitHub 不保存 RandallFlare 管理员审批码。_".into(),
    ]);
    lines.join("\n")
}

fn escape_markdown(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('`', "\\`")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn repository_slug(repository: &str) -> Result<String> {
    let repository = repository.trim().trim_end_matches('/');
    let path = repository
        .strip_prefix("https://github.com/")
        .or_else(|| repository.strip_prefix("ssh://git@github.com/"))
        .ok_or_else(|| anyhow::anyhow!("不是 GitHub HTTPS/SSH 仓库"))?
        .trim_end_matches(".git");
    let mut parts = path.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if owner.is_empty()
        || repo.is_empty()
        || parts.next().is_some()
        || !owner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || !repo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("GitHub 仓库名称无效");
    }
    Ok(format!("{owner}/{repo}"))
}

fn conclusion(state: BuildState) -> Option<&'static str> {
    match state {
        BuildState::Deployed => Some("success"),
        BuildState::Failed => Some("failure"),
        _ => None,
    }
}

fn secret_env(name: &str, label: &str) -> Result<Zeroizing<String>> {
    let value = std::env::var(name).with_context(|| format!("此节点尚未设置 {label}（{name}）"))?;
    if value.is_empty() || value.as_bytes().contains(&0) {
        bail!("{label}为空或格式无效");
    }
    Ok(Zeroizing::new(value))
}

fn github_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()
        .context("初始化 GitHub API 客户端")
}

fn context_app_id(node: &Node) -> Result<u64> {
    let value = secret_env(&node.cfg.build.github_app_id_env, "GitHub App ID")?;
    value.parse().context("GitHub App ID 格式无效")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_verification_is_exact() {
        let secret = b"local-test-secret";
        let body = br#"{"action":"opened"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_webhook(secret, &signature, body));
        assert!(!verify_webhook(secret, &signature, b"{}"));
        assert!(!verify_webhook(secret, "sha1=bad", body));
    }

    #[test]
    fn repository_slug_accepts_canonical_https_and_ssh() {
        assert_eq!(
            repository_slug("https://github.com/example/demo.git").unwrap(),
            "example/demo"
        );
        assert_eq!(
            repository_slug("ssh://git@github.com/example/demo.git").unwrap(),
            "example/demo"
        );
        assert!(repository_slug("ssh://git@example.com/example/demo.git").is_err());
    }

    #[test]
    fn comment_never_contains_approval_or_raw_markdown() {
        let job = BuildJob {
            id: "job".into(),
            worker: "demo".into(),
            repository: "https://github.com/example/demo.git".into(),
            branch: "main".into(),
            node_id: "node".into(),
            approve_node: "127.0.0.1:7382".into(),
            trigger: "github-pr:test".into(),
            state: BuildState::Failed,
            created_at_ms: 1,
            updated_at_ms: 2,
            commit: None,
            requested_commit: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            requested_ref: Some("refs/pull/1/head".into()),
            version: None,
            preview: None,
            preview_url: None,
            github: None,
            approval: Some(crate::management::CreatedApproval {
                id: "secret-id".into(),
                code: "ABCDE-12345".into(),
                kind: crate::management::ApprovalKind::Manifest,
                summary: "secret summary".into(),
                expires_at_ms: 9,
            }),
            error: Some("bad | [`<script>`]".into()),
            log: Vec::new(),
        };
        let body = render_comment(&job);
        assert!(!body.contains("ABCDE-12345"));
        assert!(body.contains("\\|"));
        assert!(body.contains("&lt;script&gt;"));
    }
}
