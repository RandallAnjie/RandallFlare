//! RandallFlare management console.
//!
//! Local mode keeps the original loopback token + optional in-process
//! operator key. Public-node mode is mounted as the default ingress and uses
//! operator-signed, stateless [`crate::management::ConsoleGrant`] cookies.
//! Every node verifies those grants independently; no central identity
//! service, cluster secret, or operator private key reaches the browser.

use crate::deploy;
use crate::management::{ApprovalState, ConsoleGrant};
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rand::RngCore;
use rf_core::identity::AnyKeypair;
use rf_core::manifest::{valid_name, AssetFile, ManifestError, Module, WorkerManifest};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroize;

const INDEX_HTML: &str = include_str!("console/index.html");
const APP_JS: &str = include_str!("console/app.js");
const STYLES_CSS: &str = include_str!("console/styles.css");
const TOKEN_HEADER: &str = "x-rf-console-token";
const CSRF_HEADER: &str = "x-rf-csrf";
const SESSION_COOKIE: &str = "rf_console_session";
const MAX_CONSOLE_VALUE: usize = 1024 * 1024;
const MAX_CONSOLE_UPLOAD: usize = 64 * 1024 * 1024;
const MAX_CONSOLE_FILES: usize = 2048;
const MAX_EDITOR_CHANGES: usize = 256;
const MAX_EDITOR_FILE: usize = 25 * 1024 * 1024;
const MAX_EDITOR_READ: usize = 5 * 1024 * 1024;

#[derive(Clone)]
enum ConsoleMode {
    Local {
        operator: Option<Arc<AnyKeypair>>,
        token: Arc<str>,
    },
    Public {
        node: Arc<Node>,
        secure_cookies: bool,
    },
}

#[derive(Clone)]
pub struct ConsoleState {
    node: Arc<str>,
    client: PeerClient,
    secret: [u8; 32],
    mode: ConsoleMode,
    started: Instant,
}

impl ConsoleState {
    pub fn new(node: String, secret: [u8; 32], operator: Option<AnyKeypair>) -> Self {
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        Self {
            node: node.into(),
            client: PeerClient::new(secret),
            secret,
            mode: ConsoleMode::Local {
                operator: operator.map(Arc::new),
                token: hex::encode(token).into(),
            },
            started: Instant::now(),
        }
    }

    pub fn public(node: Arc<Node>, secure_cookies: bool) -> Result<Self> {
        let peer = format!("127.0.0.1:{}", node.cfg.peer_api.listen.port());
        let secret = node.cfg.cluster_secret_bytes()?;
        Ok(Self {
            node: peer.into(),
            client: PeerClient::new(secret),
            secret,
            mode: ConsoleMode::Public {
                node,
                secure_cookies,
            },
            started: Instant::now(),
        })
    }

    fn operator(&self) -> ApiResult<&AnyKeypair> {
        match &self.mode {
            ConsoleMode::Local {
                operator: Some(operator),
                ..
            } => Ok(operator),
            ConsoleMode::Local { operator: None, .. } => Err(ApiError::forbidden(
                "尚未配置管理员密钥；控制台当前为只读模式",
            )),
            ConsoleMode::Public { .. } => Err(ApiError::forbidden(
                "公共控制台提交的部署清单需要管理员批准",
            )),
        }
    }

    fn require_mutation(&self) -> ApiResult<()> {
        match &self.mode {
            ConsoleMode::Local { operator, .. } if operator.is_none() => Err(ApiError::forbidden(
                "尚未配置管理员密钥；控制台当前为只读模式",
            )),
            _ => Ok(()),
        }
    }

    fn operator_id(&self) -> Option<rf_core::identity::SignerId> {
        match &self.mode {
            ConsoleMode::Local {
                operator: Some(operator),
                ..
            } => Some(operator.signer_id()),
            ConsoleMode::Local { operator: None, .. } => None,
            ConsoleMode::Public { node, .. } => Some(node.cfg.operator),
        }
    }

    fn public_node(&self) -> ApiResult<&Arc<Node>> {
        match &self.mode {
            ConsoleMode::Public { node, .. } => Ok(node),
            ConsoleMode::Local { .. } => Err(ApiError::bad_request("此接口仅供公共节点控制台使用")),
        }
    }

    fn is_public(&self) -> bool {
        matches!(self.mode, ConsoleMode::Public { .. })
    }

    fn is_read_only(&self) -> bool {
        matches!(self.mode, ConsoleMode::Local { operator: None, .. })
    }

    fn allows_secret_writes(&self) -> bool {
        matches!(
            self.mode,
            ConsoleMode::Local { .. }
                | ConsoleMode::Public {
                    secure_cookies: true,
                    ..
                }
        )
    }

    fn origin_scheme(&self) -> &'static str {
        match &self.mode {
            ConsoleMode::Public {
                secure_cookies: true,
                ..
            } => "https",
            ConsoleMode::Local { .. } | ConsoleMode::Public { .. } => "http",
        }
    }

    #[cfg(test)]
    fn local_token(&self) -> &str {
        match &self.mode {
            ConsoleMode::Local { token, .. } => token,
            ConsoleMode::Public { .. } => panic!("public console has no local token"),
        }
    }
}

#[derive(Debug, Clone)]
struct ConsolePrincipal {
    session_id: [u8; 32],
    csrf: String,
}

pub async fn serve(
    listen: SocketAddr,
    node: String,
    secret: [u8; 32],
    operator: Option<AnyKeypair>,
) -> Result<()> {
    validate_listen(listen)?;
    let state = ConsoleState::new(node, secret, operator);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("在 {listen} 监听控制台"))?;
    let addr = listener.local_addr()?;
    println!("RandallFlare 管理控制台：http://{addr}");
    println!(
        "模式：{}",
        if !state.is_read_only() {
            "管理员"
        } else {
            "只读（未配置管理员密钥）"
        }
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn validate_listen(listen: SocketAddr) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("控制台只能监听回环地址；如需远程访问，请使用 SSH 隧道");
    }
    Ok(())
}

pub fn router(state: ConsoleState) -> Router {
    let api = Router::new()
        .route("/api/session", get(session))
        .route("/api/overview", get(overview))
        .route("/api/workers/deploy", post(worker_deploy))
        .route(
            "/api/workers/{name}",
            get(worker_get).patch(worker_update).delete(worker_delete),
        )
        .route("/api/workers/{name}/log", get(worker_log))
        .route("/api/workers/{name}/runtime-log", get(worker_runtime_log))
        .route("/api/workers/{name}/build", post(worker_build))
        .route("/api/workers/{name}/files", post(worker_files_update))
        .route("/api/workers/{name}/files/{*path}", get(worker_file_get))
        .route("/api/workers/{name}/cron-runs", get(worker_cron_runs))
        .route("/api/workers/{name}/cron-fire", post(worker_cron_fire))
        .route(
            "/api/workers/{name}/cron-runs/{id}",
            delete(worker_cron_delete_dlq),
        )
        .route(
            "/api/workers/{name}/cron-runs/{id}/replay",
            post(worker_cron_replay),
        )
        .route("/api/workers/{name}/secrets", get(worker_secret_list))
        .route(
            "/api/workers/{name}/secrets/{binding}",
            put(worker_secret_put).delete(worker_secret_delete),
        )
        .route(
            "/api/workers/{name}/rollback/{version}",
            post(worker_rollback),
        )
        .route("/api/sources", get(source_list).post(source_connect))
        .route("/api/sources/{name}", delete(source_disconnect))
        .route("/api/builds", get(build_list))
        .route("/api/builds/{id}", get(build_get))
        .route("/api/approvals/{id}", get(approval_status))
        .route("/api/kv", get(kv_list))
        .route("/api/kv/value", get(kv_get).put(kv_put).delete(kv_delete))
        .route("/api/d1/create", post(d1_create))
        .route("/api/d1/exec", post(d1_exec))
        .route("/api/r2/buckets", get(r2_bucket_list).post(r2_bucket_apply))
        .route("/api/r2/buckets/{name}", delete(r2_bucket_delete))
        .route("/api/r2/objects/{bucket}", get(r2_object_list))
        .route(
            "/api/r2/object/{bucket}/{*key}",
            get(r2_object_get)
                .put(r2_object_put)
                .delete(r2_object_delete),
        )
        .route("/api/queues", get(queue_list).post(queue_apply))
        .route("/api/queues/{name}", delete(queue_delete))
        .route("/api/queues/{name}/messages", post(queue_send))
        .route("/api/queues/{name}/dead", get(queue_dead_letters))
        .route("/api/queues/{name}/dead/{id}/redrive", post(queue_redrive))
        .route("/api/analytics", get(analytics_list).post(analytics_apply))
        .route("/api/analytics/{name}", delete(analytics_delete))
        .route(
            "/api/analytics/{name}/events",
            get(analytics_recent).post(analytics_write),
        )
        .route("/api/analytics/{name}/stats", get(analytics_stats))
        .route("/api/analytics/{name}/group", get(analytics_group))
        .route("/api/pipelines", get(pipeline_list).post(pipeline_apply))
        .route("/api/pipelines/{name}", delete(pipeline_delete))
        .route("/api/pipelines/{name}/tokens", post(pipeline_token_mint))
        .route(
            "/api/pipelines/{name}/tokens/{id}",
            delete(pipeline_token_revoke),
        )
        .route("/api/pipelines/{name}/events", post(pipeline_ingest))
        .route("/api/pipelines/{name}/status", get(pipeline_status))
        .route("/api/pipelines/{name}/batches", get(pipeline_batches))
        .route("/api/pipelines/{name}/flush", post(pipeline_flush))
        .route("/api/workflows", get(workflow_list).post(workflow_apply))
        .route("/api/workflows/{name}", delete(workflow_delete))
        .route(
            "/api/workflows/{name}/instances",
            get(workflow_instances).post(workflow_trigger),
        )
        .route(
            "/api/workflows/{name}/instances/{id}",
            get(workflow_instance),
        )
        .route(
            "/api/workflows/{name}/instances/{id}/signal",
            post(workflow_signal),
        )
        .route(
            "/api/workflows/{name}/instances/{id}/{action}",
            post(workflow_action),
        )
        .route("/api/flows", get(flow_list).post(flow_apply))
        .route("/api/flows/{name}", delete(flow_delete))
        .route("/api/flows/{name}/tokens", post(flow_token_mint))
        .route("/api/flows/{name}/tokens/{id}", delete(flow_token_revoke))
        .route("/api/flows/{name}/runs", get(flow_runs).post(flow_trigger))
        .route("/api/flows/{name}/runs/{id}", get(flow_run))
        .route("/api/flows/{name}/runs/{id}/{action}", post(flow_action))
        .route("/api/email", get(email_list).post(email_apply))
        .route("/api/email/{name}", delete(email_delete))
        .route(
            "/api/email/{name}/verification",
            get(email_verification).post(email_verify),
        )
        .route(
            "/api/email/{name}/messages",
            get(email_messages).post(email_send),
        )
        .route("/api/email/{name}/messages/{id}", get(email_message))
        .route(
            "/api/email/{name}/messages/{id}/raw",
            get(email_message_raw),
        )
        .route("/api/auth/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_console_auth,
        ));
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .route("/api/auth/challenge", post(auth_challenge))
        .route("/api/auth/challenge/{id}", get(auth_poll))
        .route("/api/webhooks/github/{name}", post(github_webhook))
        .merge(api)
        .fallback(not_found)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_CONSOLE_UPLOAD * 2))
        .layer(middleware::from_fn(security_headers))
}

async fn require_console_auth(
    State(state): State<ConsoleState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let principal = match &state.mode {
        ConsoleMode::Local { token, .. } => {
            let supplied = request
                .headers()
                .get(TOKEN_HEADER)
                .and_then(|value| value.to_str().ok());
            if supplied != Some(token.as_ref()) {
                return ApiError::unauthorized("控制台会话令牌缺失或无效").into_response();
            }
            ConsolePrincipal {
                session_id: [0; 32],
                csrf: String::new(),
            }
        }
        ConsoleMode::Public { node, .. } => {
            let Some(encoded) = cookie_value(request.headers(), SESSION_COOKIE) else {
                return ApiError::unauthorized("需要操作员授权").into_response();
            };
            let grant = match decode_grant(encoded, &node.cfg.operator, &node.cfg.cluster_id) {
                Ok(grant) => grant,
                Err(error) => return ApiError::unauthorized(error.to_string()).into_response(),
            };
            if is_mutating(request.method()) {
                let csrf = request
                    .headers()
                    .get(CSRF_HEADER)
                    .and_then(|value| value.to_str().ok());
                if csrf != Some(grant.csrf_hex().as_str()) {
                    return ApiError::forbidden("CSRF 令牌缺失或无效").into_response();
                }
                if !same_origin(&request, state.origin_scheme()) {
                    log_origin_rejection(&request, state.origin_scheme(), "management");
                    return ApiError::forbidden("已拒绝跨源管理请求").into_response();
                }
            }
            ConsolePrincipal {
                session_id: grant.session_id,
                csrf: grant.csrf_hex(),
            }
        }
    };
    request.extensions_mut().insert(principal);
    next.run(request).await
}

async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

async fn index(State(state): State<ConsoleState>) -> Html<String> {
    let (mode, token) = match &state.mode {
        ConsoleMode::Local { token, .. } => ("local", token.as_ref()),
        ConsoleMode::Public { .. } => ("public", ""),
    };
    Html(
        INDEX_HTML
            .replace("__RF_TOKEN__", token)
            .replace("__RF_MODE__", mode),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn styles_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLES_CSS,
    )
}

async fn not_found() -> ApiError {
    ApiError::not_found("未找到对应的控制台路由")
}

fn is_mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn cookie_value<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn request_authority(request: &Request<axum::body::Body>) -> Option<&str> {
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
}

fn same_origin(request: &Request<axum::body::Body>, expected_scheme: &str) -> bool {
    let Some(authority) = request_authority(request) else {
        return false;
    };
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Ok(origin) = origin.parse::<Uri>() else {
        return false;
    };
    origin.scheme_str() == Some(expected_scheme)
        && origin
            .authority()
            .is_some_and(|origin| origin.as_str().eq_ignore_ascii_case(authority))
        && origin.path() == "/"
        && origin.query().is_none()
}

fn log_origin_rejection(
    request: &Request<axum::body::Body>,
    expected_scheme: &str,
    endpoint: &str,
) {
    let authority = request_authority(request).unwrap_or("<missing>");
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>");
    tracing::warn!(
        endpoint,
        authority,
        origin,
        expected_scheme,
        "console: rejected cross-origin request"
    );
}

fn encode_grant(envelope: &rf_core::envelope::Envelope) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope.to_bytes())
}

fn decode_grant(
    encoded: &str,
    operator: &rf_core::identity::SignerId,
    cluster_id: &str,
) -> Result<ConsoleGrant> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("控制台会话格式有误")?;
    let envelope = rf_core::envelope::Envelope::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("控制台会话格式有误：{error}"))?;
    let grant: ConsoleGrant = envelope
        .open(Some(operator))
        .map_err(|error| anyhow::anyhow!("控制台会话无效：{error}"))?;
    grant.validate(cluster_id, now_ms())?;
    Ok(grant)
}

fn session_cookie(envelope: &rf_core::envelope::Envelope, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
        encode_grant(envelope),
        crate::management::CONSOLE_SESSION_TTL_MS / 1000,
    )
}

fn expired_session_cookie(secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
}

async fn auth_challenge(
    State(state): State<ConsoleState>,
    request: Request<axum::body::Body>,
) -> ApiResult<Json<Value>> {
    if !same_origin(&request, state.origin_scheme()) {
        log_origin_rejection(&request, state.origin_scheme(), "auth_challenge");
        return Err(ApiError::forbidden("已拒绝跨源身份验证请求"));
    }
    let node = state.public_node()?;
    let approval = node
        .management
        .create_login(&node.cfg.cluster_id, &node.cfg.label)?;
    Ok(Json(json!({
        "id": approval.id,
        "code": approval.code,
        "summary": approval.summary,
        "expires_at_ms": approval.expires_at_ms,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
        "operator": node.cfg.operator.to_string(),
    })))
}

async fn auth_poll(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let node = state.public_node()?;
    let poll = node.management.poll_login(&id)?;
    match poll.state {
        ApprovalState::Pending => Ok(Json(json!({ "state": "pending" })).into_response()),
        ApprovalState::Failed => Err(ApiError::forbidden(
            poll.error.unwrap_or_else(|| "授权失败".into()),
        )),
        ApprovalState::Completed => {
            let envelope = poll
                .envelope
                .ok_or_else(|| ApiError::upstream("已批准的登录缺少签名信封"))?;
            let grant: ConsoleGrant = envelope
                .open(Some(&node.cfg.operator))
                .map_err(|error| ApiError::forbidden(error.to_string()))?;
            grant
                .validate(&node.cfg.cluster_id, now_ms())
                .map_err(|error| ApiError::forbidden(error.to_string()))?;
            let secure = matches!(
                state.mode,
                ConsoleMode::Public {
                    secure_cookies: true,
                    ..
                }
            );
            let mut response = Json(json!({
                "state": "completed",
                "expires_at_ms": grant.expires_at_ms,
            }))
            .into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&session_cookie(&envelope, secure))
                    .map_err(|_| ApiError::upstream("无法创建控制台会话 Cookie"))?,
            );
            Ok(response)
        }
    }
}

async fn logout(State(state): State<ConsoleState>) -> ApiResult<Response> {
    let secure = matches!(
        state.mode,
        ConsoleMode::Public {
            secure_cookies: true,
            ..
        }
    );
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&expired_session_cookie(secure))
            .map_err(|_| ApiError::upstream("无法清除控制台会话 Cookie"))?,
    );
    Ok(response)
}

async fn session(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
) -> Json<Value> {
    let (operator, auth_mode, secure_transport) = match &state.mode {
        ConsoleMode::Local { operator, .. } => (
            operator.as_ref().map(|key| key.signer_id().to_string()),
            "local_token",
            true,
        ),
        ConsoleMode::Public {
            node,
            secure_cookies,
        } => (
            Some(node.cfg.operator.to_string()),
            "operator_grant",
            *secure_cookies,
        ),
    };
    Json(json!({
        "product": "RandallFlare",
        "version": env!("CARGO_PKG_VERSION"),
        "node": state.node.as_ref(),
        "operator": operator,
        "read_only": state.is_read_only(),
        "auth_mode": auth_mode,
        "csrf": principal.csrf,
        "secure_transport": secure_transport,
        "uptime_seconds": state.started.elapsed().as_secs(),
    }))
}

async fn overview(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let mut value = state.client.status(&state.node).await?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ApiError::upstream("节点返回了无效的状态数据"))?;
    object.insert(
        "console".into(),
        json!({
            "connected_to": state.node.as_ref(),
            "operator": state.operator_id().map(|operator| operator.to_string()),
            "read_only": state.is_read_only(),
            "auth_mode": if state.is_public() { "operator_grant" } else { "local_token" },
            "uptime_seconds": state.started.elapsed().as_secs(),
        }),
    );
    Ok(Json(value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployRequest {
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    files: Vec<UploadedFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadedFile {
    path: String,
    data_base64: String,
}

async fn worker_deploy(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<DeployRequest>,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let operator = state.operator()?.clone();
            let requested = request
                .path
                .ok_or_else(|| ApiError::bad_request("从本地控制台部署时必须提供 Worker 路径"))?;
            let path = requested.canonicalize().map_err(|error| {
                ApiError::bad_request(format!(
                    "无法解析 Worker 目录 {}：{error}",
                    requested.display()
                ))
            })?;
            if !path.is_dir() {
                return Err(ApiError::bad_request("Worker 路径不是目录"));
            }
            let bundle = deploy::read_bundle(&path)?;
            let name = bundle.spec.name.clone();
            let version = deploy::deploy(&bundle, &state.client, &state.node, &operator).await?;
            Ok(Json(
                json!({ "ok": true, "name": name, "version": version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            if request.files.is_empty() || request.files.len() > MAX_CONSOLE_FILES {
                return Err(ApiError::bad_request(format!(
                    "上传内容必须包含 1 至 {MAX_CONSOLE_FILES} 个文件"
                )));
            }
            use base64::Engine as _;
            let mut total = 0usize;
            let mut files = Vec::with_capacity(request.files.len());
            for file in request.files {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&file.data_base64)
                    .map_err(|_| ApiError::bad_request("上传文件不是有效的 Base64 数据"))?;
                total = total.saturating_add(bytes.len());
                if total > MAX_CONSOLE_UPLOAD {
                    return Err(ApiError::bad_request("Worker 上传内容超过 64 MiB"));
                }
                files.push((file.path, bytes));
            }
            let bundle = deploy::read_bundle_files(files)?;
            let manifest = deploy::prepare_manifest(&bundle, &state.client, &state.node).await?;
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "部署 Worker {} v{}（{} 个模块，{} 项静态资源）",
                    manifest.name,
                    manifest.version,
                    manifest.modules.len(),
                    manifest.assets.len()
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSettingsRequest {
    #[serde(default)]
    hostnames: Option<Vec<String>>,
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    kv_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    r2_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    d1_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    queue_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    analytics_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pipeline_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    workflow_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    email_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    service_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    crons: Option<Vec<String>>,
    #[serde(default)]
    compatibility_date: Option<String>,
    #[serde(default)]
    compatibility_flags: Option<Vec<String>>,
}

fn manifest_error_zh(error: ManifestError) -> String {
    match error {
        ManifestError::Envelope(_) => "部署清单封装无效".into(),
        ManifestError::NotOperator => "部署清单并非由集群管理员签署".into(),
        ManifestError::BadName => "Worker 名称须由小写字母、数字或连字符组成".into(),
        ManifestError::MainNotInModules => "入口模块不在构建产物的模块列表中".into(),
        ManifestError::BadCron(value) => format!("Cron 表达式无效：{value}"),
        ManifestError::BadHostname(value) => format!("域名格式无效：{value}"),
        ManifestError::BadPath(value) => format!("Worker 包含不安全的文件路径：{value}"),
        ManifestError::DuplicatePath(value) => format!("Worker 包含重复的文件路径：{value}"),
        ManifestError::ChainBroken => "部署清单的版本哈希链已断裂".into(),
    }
}

async fn current_manifest(
    state: &ConsoleState,
    name: &str,
) -> ApiResult<(WorkerManifest, [u8; 32])> {
    if !valid_name(name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let envelopes = state.client.worker_log(&state.node, name).await?;
    let operator = state
        .operator_id()
        .ok_or_else(|| ApiError::upstream("无法确定部署清单的签名者"))?;
    let chain = rf_core::manifest::verify_chain(&envelopes, &operator)
        .map_err(|error| ApiError::upstream(manifest_error_zh(error)))?;
    let manifest = chain
        .last()
        .filter(|manifest| !manifest.deleted)
        .cloned()
        .ok_or_else(|| ApiError::not_found("Worker 不存在或已删除"))?;
    let digest = envelopes
        .last()
        .map(rf_core::envelope::Envelope::digest)
        .ok_or_else(|| ApiError::not_found("未找到 Worker 部署清单"))?;
    Ok((manifest, digest))
}

async fn worker_get(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let env = worker_console_environment(&manifest);
    let durable_objects = deploy::durable_objects(&manifest);
    let r2_bindings = deploy::r2_bindings(&manifest);
    let d1_bindings = deploy::d1_bindings(&manifest);
    let queue_bindings = deploy::queue_bindings(&manifest);
    let analytics_bindings = deploy::analytics_bindings(&manifest);
    let pipeline_bindings = deploy::pipeline_bindings(&manifest);
    let workflow_bindings = deploy::workflow_bindings(&manifest);
    let email_bindings = deploy::email_bindings(&manifest);
    let service_bindings = deploy::service_bindings(&manifest);
    let secret_names: Vec<String> = crate::worker_secret::encrypted_secrets_checked(&manifest)?
        .into_keys()
        .collect();
    let source = match &state.mode {
        ConsoleMode::Public { node, .. } => crate::build::source_head(node, &name)
            .filter(|record| !record.source.deleted)
            .map(|record| serde_json::to_value(record).unwrap_or(Value::Null)),
        ConsoleMode::Local { .. } => None,
    };
    let (default_hostname, effective_hostnames) = match &state.mode {
        ConsoleMode::Public { node, .. } => (
            node.default_worker_hostname(&manifest.name),
            node.effective_worker_hostnames(&manifest),
        ),
        ConsoleMode::Local { .. } => (None, manifest.hostnames.clone()),
    };
    let tls = match &state.mode {
        ConsoleMode::Public { node, .. } => worker_tls_view(node, &effective_hostnames),
        ConsoleMode::Local { .. } => json!({
            "enabled": false,
            "acme_enabled": false,
            "acme_ready": false,
            "include_worker_hostnames": false,
            "zone": null,
            "dns_target": null,
            "certificates": effective_hostnames.iter().map(|hostname| json!({
                "hostname": hostname,
                "status": "unknown",
                "source": "unknown",
                "coverage": "unknown",
                "covered_by": null,
                "issued_ms": null,
                "expires_ms": null,
                "days_remaining": null,
                "auto_managed": false,
            })).collect::<Vec<_>>(),
        }),
    };
    Ok(Json(json!({
        "worker": {
            "name": manifest.name,
            "version": manifest.version,
            "digest": hex::encode(digest),
            "main": manifest.main,
            "modules": manifest.modules,
            "assets": manifest.assets,
            "hostnames": effective_hostnames,
            "custom_hostnames": manifest.hostnames,
            "default_hostname": default_hostname,
            "env": env,
            "kv_bindings": manifest.kv_bindings,
            "r2_bindings": r2_bindings,
            "d1_bindings": d1_bindings,
            "queue_bindings": queue_bindings,
            "analytics_bindings": analytics_bindings,
            "pipeline_bindings": pipeline_bindings,
            "workflow_bindings": workflow_bindings,
            "email_bindings": email_bindings,
            "service_bindings": service_bindings,
            "secret_names": secret_names,
            "crons": manifest.crons,
            "compatibility_date": manifest.compatibility_date,
            "compatibility_flags": deploy::compatibility_flags(&manifest),
            "durable_objects": durable_objects,
        },
        "source": source,
        "tls": tls,
    })))
}

fn worker_console_environment(manifest: &WorkerManifest) -> BTreeMap<String, String> {
    let mut env = manifest.env.clone();
    env.remove(deploy::DO_METADATA_ENV);
    env.remove(deploy::R2_METADATA_ENV);
    env.remove(deploy::D1_METADATA_ENV);
    env.remove(deploy::QUEUE_METADATA_ENV);
    env.remove(deploy::ANALYTICS_METADATA_ENV);
    env.remove(deploy::PIPELINE_METADATA_ENV);
    env.remove(deploy::WORKFLOW_METADATA_ENV);
    env.remove(deploy::EMAIL_METADATA_ENV);
    env.remove(deploy::SERVICE_METADATA_ENV);
    env.remove(deploy::SECRET_METADATA_ENV);
    env.remove(deploy::COMPATIBILITY_FLAGS_METADATA_ENV);
    env
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerFileType {
    Module,
    Asset,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerFileChange {
    Put {
        path: String,
        content_base64: String,
        #[serde(default)]
        file_type: Option<WorkerFileType>,
    },
    Delete {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerFilesRequest {
    changes: Vec<WorkerFileChange>,
    #[serde(default)]
    main: Option<String>,
}

#[derive(Clone)]
enum EditableWorkerFile {
    Module(Module),
    Asset(AssetFile),
}

impl EditableWorkerFile {
    fn set_path(&mut self, path: String) {
        match self {
            Self::Module(module) => {
                module.kind = deploy::module_kind(std::path::Path::new(&path));
                module.path = path;
            }
            Self::Asset(asset) => asset.path = path,
        }
    }
}

async fn worker_file_get(
    State(state): State<ConsoleState>,
    Path((name, path)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (manifest, _) = current_manifest(&state, &name).await?;
    let (sha256, size, file_type, module_kind) =
        if let Some(module) = manifest.modules.iter().find(|module| module.path == path) {
            (
                module.sha256,
                module.size,
                "module",
                Some(format!("{:?}", module.kind)),
            )
        } else if let Some(asset) = manifest.assets.iter().find(|asset| asset.path == path) {
            (asset.sha256, asset.size, "asset", None)
        } else {
            return Err(ApiError::not_found("当前 Worker 版本中没有这个文件"));
        };
    if size > MAX_EDITOR_READ as u64 {
        return Ok(Json(json!({
            "path": path,
            "file_type": file_type,
            "module_kind": module_kind,
            "size": size,
            "sha256": hex::encode(sha256),
            "editable": false,
            "reason": "文件超过 5 MiB，请通过目录上传或 Git 构建替换",
        })));
    }
    let bytes = state.client.fetch_blob(&state.node, &sha256).await?;
    if crate::blob::sha256_hex(&bytes) != hex::encode(sha256) {
        return Err(ApiError::upstream("节点返回的文件内容摘要不匹配"));
    }
    use base64::Engine as _;
    let text = String::from_utf8(bytes.clone())
        .ok()
        .filter(|value| !value.contains('\0'));
    Ok(Json(json!({
        "path": path,
        "file_type": file_type,
        "module_kind": module_kind,
        "size": size,
        "sha256": hex::encode(sha256),
        "editable": true,
        "text": text,
        "content_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
    })))
}

async fn worker_files_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<WorkerFilesRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if request.changes.is_empty() && request.main.is_none() {
        return Err(ApiError::bad_request("没有需要发布的文件或入口修改"));
    }
    if request.changes.len() > MAX_EDITOR_CHANGES {
        return Err(ApiError::bad_request("一次最多修改 256 个文件"));
    }
    let (mut manifest, digest) = current_manifest(&state, &name).await?;
    let mut files = BTreeMap::new();
    for module in manifest.modules.drain(..) {
        files.insert(module.path.clone(), EditableWorkerFile::Module(module));
    }
    for asset in manifest.assets.drain(..) {
        if files
            .insert(asset.path.clone(), EditableWorkerFile::Asset(asset))
            .is_some()
        {
            return Err(ApiError::upstream("当前 Worker 清单包含重复文件路径"));
        }
    }

    let mut uploaded_bytes = 0usize;
    use base64::Engine as _;
    for change in request.changes {
        match change {
            WorkerFileChange::Put {
                path,
                content_base64,
                file_type,
            } => {
                validate_editor_path(&path)?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(content_base64)
                    .map_err(|_| ApiError::bad_request("文件内容不是有效的 Base64"))?;
                if bytes.len() > MAX_EDITOR_FILE {
                    return Err(ApiError::bad_request("单个编辑文件不能超过 25 MiB"));
                }
                uploaded_bytes = uploaded_bytes.saturating_add(bytes.len());
                if uploaded_bytes > MAX_CONSOLE_UPLOAD {
                    return Err(ApiError::bad_request("单次文件修改不能超过 64 MiB"));
                }
                let resolved_type = file_type.or_else(|| {
                    files.get(&path).map(|file| match file {
                        EditableWorkerFile::Module(_) => WorkerFileType::Module,
                        EditableWorkerFile::Asset(_) => WorkerFileType::Asset,
                    })
                });
                let resolved_type = resolved_type.ok_or_else(|| {
                    ApiError::bad_request("创建新文件时必须指定 module 或 asset 类型")
                })?;
                if matches!(resolved_type, WorkerFileType::Module)
                    && deploy::reserved_module_path(&path)
                {
                    return Err(ApiError::bad_request("__rf_ 模块路径由 RandallFlare 保留"));
                }
                let sha_hex = state.client.put_blob(&state.node, bytes.clone()).await?;
                let sha256 = decode_console_sha(&sha_hex)?;
                if crate::blob::sha256_hex(&bytes) != sha_hex.trim().to_ascii_lowercase() {
                    return Err(ApiError::upstream("节点返回的内容摘要与上传文件不匹配"));
                }
                let file = match resolved_type {
                    WorkerFileType::Module => EditableWorkerFile::Module(Module {
                        path: path.clone(),
                        sha256,
                        kind: deploy::module_kind(std::path::Path::new(&path)),
                        size: bytes.len() as u64,
                    }),
                    WorkerFileType::Asset => EditableWorkerFile::Asset(AssetFile {
                        path: path.clone(),
                        sha256,
                        size: bytes.len() as u64,
                    }),
                };
                files.insert(path, file);
            }
            WorkerFileChange::Delete { path } => {
                validate_editor_path(&path)?;
                if files.remove(&path).is_none() {
                    return Err(ApiError::not_found(format!("文件 {path} 不存在")));
                }
            }
            WorkerFileChange::Rename { from, to } => {
                validate_editor_path(&from)?;
                validate_editor_path(&to)?;
                if files.contains_key(&to) {
                    return Err(ApiError::bad_request(format!("目标文件 {to} 已存在")));
                }
                let mut file = files
                    .remove(&from)
                    .ok_or_else(|| ApiError::not_found(format!("文件 {from} 不存在")))?;
                file.set_path(to.clone());
                if manifest.main == from {
                    if !matches!(file, EditableWorkerFile::Module(_)) {
                        return Err(ApiError::bad_request("入口模块不能重命名为静态资源"));
                    }
                    manifest.main = to.clone();
                }
                files.insert(to, file);
            }
        }
    }
    if files.len() > 5_000 {
        return Err(ApiError::bad_request("一个 Worker 最多包含 5000 个文件"));
    }
    if let Some(main) = request.main {
        manifest.main = main.trim().to_string();
    }
    manifest.modules = files
        .values()
        .filter_map(|file| match file {
            EditableWorkerFile::Module(module) => Some(module.clone()),
            EditableWorkerFile::Asset(_) => None,
        })
        .collect();
    manifest.assets = files
        .values()
        .filter_map(|file| match file {
            EditableWorkerFile::Module(_) => None,
            EditableWorkerFile::Asset(asset) => Some(asset.clone()),
        })
        .collect();
    if manifest
        .modules
        .iter()
        .any(|module| deploy::reserved_module_path(&module.path))
    {
        return Err(ApiError::bad_request("__rf_ 模块路径由 RandallFlare 保留"));
    }
    if manifest.main.is_empty() && manifest.assets.is_empty() {
        return Err(ApiError::bad_request(
            "Worker 必须设置入口模块，或至少保留一个静态资源",
        ));
    }
    manifest.version = manifest
        .version
        .checked_add(1)
        .ok_or_else(|| ApiError::bad_request("Worker 版本号已耗尽"))?;
    manifest.prev = Some(digest);
    manifest.validate().map_err(|error| {
        ApiError::bad_request(format!("Worker 文件无效：{}", manifest_error_zh(error)))
    })?;
    submit_file_manifest(&state, &principal, manifest, files.len()).await
}

async fn submit_file_manifest(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    manifest: WorkerManifest,
    file_count: usize,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&manifest, state.operator()?);
            state.client.post_manifest(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": manifest.name,
                "version": manifest.version,
                "files": file_count,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "发布 Worker {} 的文件修改为 v{}（{} 个文件）",
                    manifest.name, manifest.version, file_count
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "files": file_count,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

fn validate_editor_path(path: &str) -> ApiResult<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.starts_with('/')
        || path.contains('\\')
        || path.as_bytes().iter().any(|byte| byte.is_ascii_control())
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(ApiError::bad_request("文件路径不是安全的相对路径"));
    }
    Ok(())
}

fn decode_console_sha(value: &str) -> ApiResult<[u8; 32]> {
    hex::decode(value.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::upstream("节点返回了无效的内容摘要"))
}

fn worker_tls_view(node: &Node, hostnames: &[String]) -> Value {
    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    const RENEWAL_MS: u64 = 30 * DAY_MS;

    let https_enabled = node.cfg.ingress.https.is_some();
    let acme = node.cfg.acme.as_ref();
    let zone = acme
        .and_then(|cfg| cfg.zone.clone())
        .or_else(|| node.cfg.dns.as_ref().map(|cfg| cfg.zone.clone()));
    let configured: Vec<String> = acme
        .map(|cfg| {
            cfg.hostnames
                .iter()
                .map(|hostname| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let include_worker_hostnames = acme
        .map(|cfg| cfg.include_worker_hostnames)
        .unwrap_or(false);
    let token_env = acme
        .and_then(|cfg| cfg.api_token_env.clone())
        .or_else(|| node.cfg.dns.as_ref().map(|cfg| cfg.api_token_env.clone()))
        .unwrap_or_else(|| "CF_API_TOKEN".into());
    let acme_ready = acme.is_some()
        && zone.is_some()
        && std::env::var(&token_env)
            .ok()
            .is_some_and(|token| !token.is_empty());
    let cert_dir = node.cfg.data_dir.join("certs");
    let now = now_ms();

    let certificates = hostnames
        .iter()
        .map(|hostname| {
            let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
            let wildcard = hostname
                .split_once('.')
                .map(|(_, suffix)| format!("*.{suffix}"));
            let candidates = std::iter::once((hostname.clone(), "exact"))
                .chain(wildcard.clone().map(|name| (name, "wildcard")));

            let mut record = None;
            let mut manual = None;
            for (candidate, coverage) in candidates {
                if record.is_none() {
                    record = node
                        .kv_get(crate::acme::NS, &crate::acme::cert_kv_key(&candidate))
                        .and_then(|raw| {
                            serde_json::from_slice::<crate::acme::CertRecord>(&raw).ok()
                        })
                        .map(|record| (candidate.clone(), coverage, record));
                }
                if manual.is_none() {
                    let stem = crate::acme::file_stem(&candidate);
                    if cert_dir.join(format!("{stem}.crt")).is_file()
                        && cert_dir.join(format!("{stem}.key")).is_file()
                    {
                        manual = Some((candidate, coverage));
                    }
                }
            }

            let zone_match = zone.as_deref().is_some_and(|zone| {
                let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
                hostname == zone || hostname.ends_with(&format!(".{zone}"))
            });
            let configured_name = configured
                .iter()
                .find(|name| **name == hostname || wildcard.as_ref() == Some(*name))
                .cloned();
            let auto_managed = acme.is_some()
                && (configured_name.is_some() || (include_worker_hostnames && zone_match));

            let (status, source, coverage, covered_by, issued_ms, expires_ms, days_remaining) =
                if !https_enabled {
                    ("https_disabled", "none", "none", None, None, None, None)
                } else if let Some((covered_by, coverage, record)) = record {
                    let remaining = record.expires_ms.saturating_sub(now);
                    let status = if record.expires_ms <= now {
                        "expired"
                    } else if remaining < RENEWAL_MS {
                        "renewing"
                    } else {
                        "active"
                    };
                    (
                        status,
                        "acme",
                        coverage,
                        Some(covered_by),
                        Some(record.issued_ms),
                        Some(record.expires_ms),
                        Some(remaining / DAY_MS),
                    )
                } else if let Some((covered_by, coverage)) = manual {
                    (
                        "installed",
                        "manual",
                        coverage,
                        Some(covered_by),
                        None,
                        None,
                        None,
                    )
                } else if auto_managed && acme_ready {
                    (
                        "provisioning",
                        "acme",
                        if configured_name
                            .as_deref()
                            .is_some_and(|name| name.starts_with("*."))
                        {
                            "wildcard"
                        } else {
                            "exact"
                        },
                        configured_name.or_else(|| Some(hostname.clone())),
                        None,
                        None,
                        None,
                    )
                } else if auto_managed {
                    (
                        "acme_unavailable",
                        "acme",
                        if configured_name
                            .as_deref()
                            .is_some_and(|name| name.starts_with("*."))
                        {
                            "wildcard"
                        } else {
                            "exact"
                        },
                        configured_name.or_else(|| Some(hostname.clone())),
                        None,
                        None,
                        None,
                    )
                } else {
                    ("missing", "none", "none", None, None, None, None)
                };

            json!({
                "hostname": hostname,
                "status": status,
                "source": source,
                "coverage": coverage,
                "covered_by": covered_by,
                "issued_ms": issued_ms,
                "expires_ms": expires_ms,
                "days_remaining": days_remaining,
                "auto_managed": auto_managed,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "enabled": https_enabled,
        "http_enabled": node.cfg.ingress.http.is_some(),
        "acme_enabled": acme.is_some(),
        "acme_ready": acme_ready,
        "include_worker_hostnames": include_worker_hostnames,
        "zone": zone,
        "dns_target": node.cfg.dns.as_ref().map(|cfg| cfg.hostname.clone()),
        "certificates": certificates,
    })
}

fn valid_compatibility_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u16>().ok();
    let month = value[5..7].parse::<u8>().ok();
    let day = value[8..10].parse::<u8>().ok();
    let (Some(year @ 2021..=9999), Some(month @ 1..=12), Some(day)) = (year, month, day) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
}

fn validate_settings_map(values: &BTreeMap<String, String>, label: &str) -> ApiResult<()> {
    if values.len() > 256 {
        return Err(ApiError::bad_request(format!("{label}最多允许 256 项")));
    }
    let mut total = 0usize;
    for (key, value) in values {
        if key.is_empty()
            || key.len() > 256
            || key.as_bytes().iter().any(|byte| byte.is_ascii_control())
        {
            return Err(ApiError::bad_request(format!("{label}中包含无效名称")));
        }
        if value.len() > MAX_CONSOLE_VALUE {
            return Err(ApiError::bad_request(format!(
                "{label}中的单项值超过 1 MiB"
            )));
        }
        total = total.saturating_add(key.len()).saturating_add(value.len());
    }
    if total > MAX_CONSOLE_VALUE {
        return Err(ApiError::bad_request(format!("{label}总大小超过 1 MiB")));
    }
    Ok(())
}

fn apply_worker_settings(
    mut manifest: WorkerManifest,
    digest: [u8; 32],
    request: WorkerSettingsRequest,
) -> ApiResult<WorkerManifest> {
    let WorkerSettingsRequest {
        hostnames,
        env,
        kv_bindings,
        r2_bindings,
        d1_bindings,
        queue_bindings,
        analytics_bindings,
        pipeline_bindings,
        workflow_bindings,
        email_bindings,
        service_bindings,
        crons,
        compatibility_date,
        compatibility_flags,
    } = request;
    if hostnames.is_none()
        && env.is_none()
        && kv_bindings.is_none()
        && r2_bindings.is_none()
        && d1_bindings.is_none()
        && queue_bindings.is_none()
        && analytics_bindings.is_none()
        && pipeline_bindings.is_none()
        && workflow_bindings.is_none()
        && email_bindings.is_none()
        && service_bindings.is_none()
        && crons.is_none()
        && compatibility_date.is_none()
        && compatibility_flags.is_none()
    {
        return Err(ApiError::bad_request("没有需要更新的 Worker 配置"));
    }
    if let Some(hostnames) = hostnames {
        if hostnames.len() > 256 {
            return Err(ApiError::bad_request("一个 Worker 最多绑定 256 个域名"));
        }
        let mut normalized: Vec<String> = hostnames
            .into_iter()
            .map(|hostname| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|hostname| !hostname.is_empty())
            .collect();
        normalized.sort();
        normalized.dedup();
        manifest.hostnames = normalized;
    }
    if let Some(mut env) = env {
        if env.keys().any(|key| key.starts_with("__RF_")) {
            return Err(ApiError::bad_request(
                "不能修改 RandallFlare 保留的环境变量",
            ));
        }
        validate_settings_map(&env, "环境变量")?;
        if let Some(durable_objects) = manifest.env.get(deploy::DO_METADATA_ENV).cloned() {
            env.insert(deploy::DO_METADATA_ENV.into(), durable_objects);
        }
        if let Some(r2) = manifest.env.get(deploy::R2_METADATA_ENV).cloned() {
            env.insert(deploy::R2_METADATA_ENV.into(), r2);
        }
        if let Some(d1) = manifest.env.get(deploy::D1_METADATA_ENV).cloned() {
            env.insert(deploy::D1_METADATA_ENV.into(), d1);
        }
        if let Some(queues) = manifest.env.get(deploy::QUEUE_METADATA_ENV).cloned() {
            env.insert(deploy::QUEUE_METADATA_ENV.into(), queues);
        }
        if let Some(analytics) = manifest.env.get(deploy::ANALYTICS_METADATA_ENV).cloned() {
            env.insert(deploy::ANALYTICS_METADATA_ENV.into(), analytics);
        }
        if let Some(pipelines) = manifest.env.get(deploy::PIPELINE_METADATA_ENV).cloned() {
            env.insert(deploy::PIPELINE_METADATA_ENV.into(), pipelines);
        }
        if let Some(workflows) = manifest.env.get(deploy::WORKFLOW_METADATA_ENV).cloned() {
            env.insert(deploy::WORKFLOW_METADATA_ENV.into(), workflows);
        }
        if let Some(email) = manifest.env.get(deploy::EMAIL_METADATA_ENV).cloned() {
            env.insert(deploy::EMAIL_METADATA_ENV.into(), email);
        }
        if let Some(services) = manifest.env.get(deploy::SERVICE_METADATA_ENV).cloned() {
            env.insert(deploy::SERVICE_METADATA_ENV.into(), services);
        }
        if let Some(secrets) = manifest.env.get(deploy::SECRET_METADATA_ENV).cloned() {
            env.insert(deploy::SECRET_METADATA_ENV.into(), secrets);
        }
        if let Some(flags) = manifest
            .env
            .get(deploy::COMPATIBILITY_FLAGS_METADATA_ENV)
            .cloned()
        {
            env.insert(deploy::COMPATIBILITY_FLAGS_METADATA_ENV.into(), flags);
        }
        manifest.env = env;
    }
    if let Some(kv_bindings) = kv_bindings {
        validate_settings_map(&kv_bindings, "KV 绑定")?;
        manifest.kv_bindings = kv_bindings;
    }
    if let Some(r2_bindings) = r2_bindings {
        validate_settings_map(&r2_bindings, "R2 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, bucket) in &r2_bindings {
            if !identifier(binding) || !valid_name(bucket) {
                return Err(ApiError::bad_request(format!(
                    "R2 绑定 {binding} 或 bucket 名称无效"
                )));
            }
        }
        if r2_bindings.is_empty() {
            manifest.env.remove(deploy::R2_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::R2_METADATA_ENV.into(),
                serde_json::to_string(&r2_bindings)?,
            );
        }
    }
    if let Some(d1_bindings) = d1_bindings {
        validate_settings_map(&d1_bindings, "D1 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, database) in &d1_bindings {
            if !identifier(binding)
                || !valid_name(database)
                || database.starts_with("r2-")
                || database.starts_with("rfdo-")
            {
                return Err(ApiError::bad_request(format!(
                    "D1 绑定 {binding} 或数据库名称无效"
                )));
            }
        }
        if d1_bindings.is_empty() {
            manifest.env.remove(deploy::D1_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::D1_METADATA_ENV.into(),
                serde_json::to_string(&d1_bindings)?,
            );
        }
    }
    if let Some(queue_bindings) = queue_bindings {
        validate_settings_map(&queue_bindings, "Queue 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, queue) in &queue_bindings {
            if !identifier(binding) || !valid_name(queue) {
                return Err(ApiError::bad_request(format!(
                    "Queue 绑定 {binding} 或队列名称无效"
                )));
            }
        }
        if queue_bindings.is_empty() {
            manifest.env.remove(deploy::QUEUE_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::QUEUE_METADATA_ENV.into(),
                serde_json::to_string(&queue_bindings)?,
            );
        }
    }
    if let Some(analytics_bindings) = analytics_bindings {
        validate_settings_map(&analytics_bindings, "Analytics 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, dataset) in &analytics_bindings {
            if !identifier(binding) || !valid_name(dataset) {
                return Err(ApiError::bad_request(format!(
                    "Analytics 绑定 {binding} 或数据集名称无效"
                )));
            }
        }
        if analytics_bindings.is_empty() {
            manifest.env.remove(deploy::ANALYTICS_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::ANALYTICS_METADATA_ENV.into(),
                serde_json::to_string(&analytics_bindings)?,
            );
        }
    }
    if let Some(pipeline_bindings) = pipeline_bindings {
        validate_settings_map(&pipeline_bindings, "Pipeline 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, pipeline) in &pipeline_bindings {
            if !identifier(binding) || !valid_name(pipeline) {
                return Err(ApiError::bad_request(format!(
                    "Pipeline 绑定 {binding} 或 Pipeline 名称无效"
                )));
            }
        }
        if pipeline_bindings.is_empty() {
            manifest.env.remove(deploy::PIPELINE_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::PIPELINE_METADATA_ENV.into(),
                serde_json::to_string(&pipeline_bindings)?,
            );
        }
    }
    if let Some(workflow_bindings) = workflow_bindings {
        validate_settings_map(&workflow_bindings, "Workflow 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, workflow) in &workflow_bindings {
            if !identifier(binding) || !valid_name(workflow) {
                return Err(ApiError::bad_request(format!(
                    "Workflow 绑定 {binding} 或 Workflow 名称无效"
                )));
            }
        }
        if workflow_bindings.is_empty() {
            manifest.env.remove(deploy::WORKFLOW_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::WORKFLOW_METADATA_ENV.into(),
                serde_json::to_string(&workflow_bindings)?,
            );
        }
    }
    if let Some(email_bindings) = email_bindings {
        validate_settings_map(&email_bindings, "Email 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, domain) in &email_bindings {
            if !identifier(binding) || !valid_name(domain) {
                return Err(ApiError::bad_request(format!(
                    "Email 绑定 {binding} 或邮件域资源名称无效"
                )));
            }
        }
        if email_bindings.is_empty() {
            manifest.env.remove(deploy::EMAIL_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::EMAIL_METADATA_ENV.into(),
                serde_json::to_string(&email_bindings)?,
            );
        }
    }
    if let Some(service_bindings) = service_bindings {
        validate_settings_map(&service_bindings, "Service 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, target) in &service_bindings {
            if !identifier(binding) || !valid_name(target) || target == &manifest.name {
                return Err(ApiError::bad_request(format!(
                    "Service 绑定 {binding} 或目标 Worker 名称无效，且不能绑定自身"
                )));
            }
        }
        if service_bindings.is_empty() {
            manifest.env.remove(deploy::SERVICE_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::SERVICE_METADATA_ENV.into(),
                serde_json::to_string(&service_bindings)?,
            );
        }
    }
    if let Some(crons) = crons {
        if crons.len() > 256 {
            return Err(ApiError::bad_request(
                "一个 Worker 最多配置 256 个定时触发器",
            ));
        }
        manifest.crons = crons
            .into_iter()
            .map(|cron| cron.trim().to_string())
            .filter(|cron| !cron.is_empty())
            .collect();
    }
    if let Some(compatibility_date) = compatibility_date {
        let compatibility_date = compatibility_date.trim().to_string();
        if !valid_compatibility_date(&compatibility_date) {
            return Err(ApiError::bad_request("兼容日期必须采用 YYYY-MM-DD 格式"));
        }
        manifest.compatibility_date = compatibility_date;
    }
    if let Some(compatibility_flags) = compatibility_flags {
        deploy::validate_compatibility_flags(&compatibility_flags)
            .map_err(|error| ApiError::bad_request(format!("兼容性标志无效：{error:#}")))?;
        if compatibility_flags.is_empty() {
            manifest
                .env
                .remove(deploy::COMPATIBILITY_FLAGS_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::COMPATIBILITY_FLAGS_METADATA_ENV.into(),
                serde_json::to_string(&compatibility_flags)?,
            );
        }
    }
    let encrypted_secrets = crate::worker_secret::encrypted_secrets_checked(&manifest)?;
    let mut binding_names = std::collections::BTreeSet::new();
    for name in manifest
        .env
        .keys()
        .filter(|name| !name.starts_with("__RF_"))
        .chain(manifest.kv_bindings.keys())
        .chain(deploy::durable_objects(&manifest).keys())
        .chain(deploy::r2_bindings(&manifest).keys())
        .chain(deploy::d1_bindings(&manifest).keys())
        .chain(deploy::queue_bindings(&manifest).keys())
        .chain(deploy::analytics_bindings(&manifest).keys())
        .chain(deploy::pipeline_bindings(&manifest).keys())
        .chain(deploy::workflow_bindings(&manifest).keys())
        .chain(deploy::email_bindings(&manifest).keys())
        .chain(deploy::service_bindings(&manifest).keys())
        .chain(encrypted_secrets.keys())
    {
        if !binding_names.insert(name.clone()) {
            return Err(ApiError::bad_request(format!("绑定名称 {name} 被重复使用")));
        }
    }
    manifest.version = manifest.version.saturating_add(1);
    manifest.prev = Some(digest);
    manifest.validate().map_err(|error| {
        ApiError::bad_request(format!("Worker 配置无效：{}", manifest_error_zh(error)))
    })?;
    Ok(manifest)
}

async fn worker_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<WorkerSettingsRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let manifest = apply_worker_settings(manifest, digest, request)?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&manifest, state.operator()?);
            state.client.post_manifest(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": manifest.name,
                "version": manifest.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "更新 Worker {} 的配置并发布 v{}",
                    manifest.name, manifest.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSecretPutRequest {
    value: String,
}

async fn worker_secret_list(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let (manifest, _) = current_manifest(&state, &name).await?;
    let secrets = crate::worker_secret::encrypted_secrets_checked(&manifest)?;
    Ok(Json(json!({
        "worker": manifest.name,
        "secrets": secrets.into_keys().collect::<Vec<_>>(),
    })))
}

async fn worker_secret_put(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, binding)): Path<(String, String)>,
    Json(mut request): Json<WorkerSecretPutRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.allows_secret_writes() {
        return Err(ApiError::forbidden(
            "公共控制台只能通过 HTTPS 写入 Worker Secret",
        ));
    }
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let manifest_result = mutate_worker_secret(
        manifest,
        digest,
        &binding,
        Some(&request.value),
        &state.secret,
    );
    request.value.zeroize();
    let manifest = manifest_result?;
    submit_secret_manifest(&state, &principal, manifest, &binding, "写入或替换").await
}

async fn worker_secret_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, binding)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let manifest = mutate_worker_secret(manifest, digest, &binding, None, &state.secret)?;
    submit_secret_manifest(&state, &principal, manifest, &binding, "删除").await
}

fn mutate_worker_secret(
    manifest: WorkerManifest,
    digest: [u8; 32],
    binding: &str,
    value: Option<&str>,
    cluster_secret: &[u8; 32],
) -> ApiResult<WorkerManifest> {
    let result = if let Some(value) = value {
        crate::worker_secret::put_manifest_secret(manifest, digest, cluster_secret, binding, value)
    } else {
        crate::worker_secret::delete_manifest_secret(manifest, digest, binding)
    };
    result.map_err(|error| ApiError::bad_request(format!("Secret 配置无效：{error:#}")))
}

async fn submit_secret_manifest(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    manifest: WorkerManifest,
    binding: &str,
    action: &str,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&manifest, state.operator()?);
            state.client.post_manifest(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": manifest.name,
                "version": manifest.version,
                "secret": binding,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "{action} Worker {} 的加密 Secret {} 并发布 v{}",
                    manifest.name, binding, manifest.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "secret": binding,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn worker_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let version =
                deploy::delete_worker(&name, &state.client, &state.node, state.operator()?).await?;
            Ok(Json(
                json!({ "ok": true, "name": name, "version": version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let manifest = deploy::prepare_delete(&name, &state.client, &state.node).await?;
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "删除 Worker {}（生成版本 v{}）",
                    manifest.name, manifest.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn approval_status(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let poll = node.management.poll_console(&id, principal.session_id)?;
    Ok(Json(json!({
        "state": poll.state,
        "summary": poll.summary,
        "error": poll.error,
    })))
}

#[derive(Deserialize)]
struct BuildQuery {
    #[serde(default)]
    worker: Option<String>,
}

async fn source_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let sources: Vec<Value> = crate::build::live_sources(node)
        .into_iter()
        .map(|record| {
            let secret = crate::build::webhook_secret(node, &record.source.worker).ok();
            json!({
                "worker": record.source.worker,
                "version": record.source.version,
                "digest": record.digest,
                "repository": record.source.repository,
                "branch": record.source.branch,
                "root": record.source.root,
                "build_command": record.source.build_command,
                "output_dir": record.source.output_dir,
                "use_github_token": record.source.use_github_token,
                "webhook": record.source.webhook,
                "webhook_path": format!("/api/webhooks/github/{}", record.source.worker),
                "webhook_secret": secret,
            })
        })
        .collect();
    Ok(Json(json!({
        "sources": sources,
        "capabilities": {
            "enabled": node.cfg.build.enabled,
            "git": crate::build::configured_binary(node.cfg.build.git.as_deref(), "git"),
            "sandbox": crate::build::configured_binary(node.cfg.build.sandbox.as_deref(), "bwrap"),
            "github_token_configured": std::env::var_os(&node.cfg.build.github_token_env).is_some(),
            "github_token_env": node.cfg.build.github_token_env,
            "timeout_seconds": node.cfg.build.timeout_seconds,
        }
    })))
}

async fn source_connect(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(input): Json<crate::build::SourceInput>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let source = crate::build::prepare_source(node, input)?;
    let approval = node.management.create_source(
        principal.session_id,
        &source,
        format!(
            "将 Worker {} 连接至 {} 的 {} 分支",
            source.worker, source.repository, source.branch
        ),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": source.worker,
        "version": source.version,
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn source_disconnect(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let source = crate::build::prepare_source_delete(node, &name)?;
    let approval = node.management.create_source(
        principal.session_id,
        &source,
        format!("断开 Worker {name} 与 GitHub 仓库的连接"),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": name,
        "version": source.version,
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn worker_build(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let node = state.public_node()?.clone();
    let job = crate::build::start_build(node, &name, "manual", Some(principal.session_id), None)?;
    Ok(Json(json!({ "ok": true, "job": job })))
}

async fn build_list(
    State(state): State<ConsoleState>,
    Query(query): Query<BuildQuery>,
) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    if let Some(worker) = query.worker.as_deref() {
        if !valid_name(worker) {
            return Err(ApiError::bad_request("Worker 名称无效"));
        }
    }
    Ok(Json(json!({
        "jobs": crate::build::build_jobs(node, query.worker.as_deref()),
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn build_get(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let job =
        crate::build::build_job(node, &id).ok_or_else(|| ApiError::not_found("未找到构建任务"))?;
    Ok(Json(json!({
        "job": job,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn worker_rollback(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, version)): Path<(String, u64)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let node = state.public_node()?;
    let envelopes = node.manifest_log(&name)?;
    let chain = rf_core::manifest::verify_chain(&envelopes, &node.cfg.operator)
        .map_err(|error| ApiError::upstream(error.to_string()))?;
    let historical = chain
        .into_iter()
        .find(|manifest| manifest.version == version && !manifest.deleted)
        .ok_or_else(|| ApiError::not_found("未找到可部署的历史版本"))?;
    let manifest = crate::build::rollback_manifest(node, &historical)?;
    let approval = node.management.create_manifest(
        principal.session_id,
        &manifest,
        format!(
            "将 Worker {name} 回滚至 v{version} 的内容，并发布为 v{}",
            manifest.version
        ),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": name,
        "version": manifest.version,
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn github_webhook(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) || body.len() > 2 * 1024 * 1024 {
        return Err(ApiError::bad_request("Webhook 请求无效"));
    }
    let node = state.public_node()?.clone();
    let source = crate::build::source_head(&node, &name)
        .filter(|record| !record.source.deleted && record.source.webhook)
        .ok_or_else(|| ApiError::not_found("此 Worker 尚未启用 GitHub Webhook"))?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let secret = crate::build::webhook_secret(&node, &name)?;
    if !crate::build::verify_webhook(&secret, signature, &body) {
        return Err(ApiError::unauthorized("GitHub Webhook 签名无效"));
    }
    let event = headers
        .get("x-github-event")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if event == "ping" {
        return Ok(Json(json!({ "ok": true, "pong": true })));
    }
    if event != "push" {
        return Err(ApiError::bad_request("目前仅支持 GitHub 推送事件 Webhook"));
    }
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("GitHub Webhook 的 JSON 数据无效"))?;
    let git_ref = payload
        .get("ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if git_ref != format!("refs/heads/{}", source.source.branch) {
        return Ok(Json(json!({ "ok": true, "ignored": "branch" })));
    }
    if payload.get("deleted").and_then(Value::as_bool) == Some(true) {
        return Ok(Json(json!({ "ok": true, "ignored": "deleted branch" })));
    }
    let delivery = headers
        .get("x-github-delivery")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .unwrap_or("unknown");
    let trigger = format!("github:{delivery}");
    let commit = payload
        .get("after")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| ApiError::bad_request("GitHub 推送事件缺少有效的 after 提交值"))?
        .to_string();
    if let Some(job) = crate::build::build_jobs(&node, Some(&name))
        .into_iter()
        .find(|job| job.trigger == trigger)
    {
        return Ok(Json(json!({ "ok": true, "duplicate": true, "job": job })));
    }
    let job = crate::build::start_build(node, &name, trigger, None, Some(commit))?;
    Ok(Json(json!({ "ok": true, "job": job })))
}

async fn worker_log(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let envelopes = state.client.worker_log(&state.node, &name).await?;
    let signer = if envelopes.is_empty() {
        None
    } else {
        state
            .operator_id()
            .or_else(|| envelopes.first().map(|envelope| envelope.signer))
    };
    let chain = match signer {
        Some(signer) => rf_core::manifest::verify_chain(&envelopes, &signer)
            .map_err(|error| ApiError::upstream(error.to_string()))?,
        None => Vec::new(),
    };
    let entries: Vec<Value> = chain
        .iter()
        .zip(&envelopes)
        .map(|(manifest, envelope)| manifest_log_entry(manifest, envelope))
        .collect();
    Ok(Json(json!({
        "worker": name,
        "chain_ok": true,
        "signer": signer.map(|value| value.to_string()),
        "entries": entries,
    })))
}

#[derive(Deserialize)]
struct RuntimeLogQuery {
    #[serde(default = "default_log_limit")]
    limit: usize,
}

fn default_log_limit() -> usize {
    300
}

async fn worker_runtime_log(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<RuntimeLogQuery>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let node = state.public_node()?;
    Ok(Json(json!({
        "worker": name,
        "node": node.id_hex(),
        "lines": node.runtime_logs(&name, query.limit),
    })))
}

#[derive(Deserialize)]
struct WorkerCronRunsQuery {
    #[serde(default)]
    dlq: bool,
    #[serde(default = "default_cron_runs_limit")]
    limit: usize,
}

fn default_cron_runs_limit() -> usize {
    100
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCronFireRequest {
    #[serde(default)]
    expression: Option<String>,
}

async fn worker_cron_runs(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<WorkerCronRunsQuery>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let runs = state
        .client
        .cron_runs(&state.node, &name, query.dlq, query.limit)
        .await?;
    Ok(Json(json!({ "worker": name, "runs": runs })))
}

async fn worker_cron_fire(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<WorkerCronFireRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let run = state
        .client
        .cron_fire(&state.node, &name, request.expression.as_deref())
        .await?;
    Ok(Json(json!({ "ok": true, "run": run })))
}

async fn worker_cron_replay(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let run = state
        .client
        .cron_replay(&state.node, &name, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Cron DLQ 记录不存在"))?;
    Ok(Json(json!({ "ok": true, "run": run })))
}

async fn worker_cron_delete_dlq(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state
        .client
        .cron_delete_dlq(&state.node, &name, &id)
        .await?
    {
        return Err(ApiError::not_found("Cron DLQ 记录不存在"));
    }
    Ok(Json(json!({ "ok": true })))
}

fn manifest_log_entry(manifest: &WorkerManifest, envelope: &rf_core::envelope::Envelope) -> Value {
    json!({
        "version": manifest.version,
        "deleted": manifest.deleted,
        "digest": hex::encode(envelope.digest()),
        "previous": manifest.prev.map(hex::encode),
        "hostnames": manifest.hostnames,
        "modules": manifest.modules.len(),
        "assets": manifest.assets.len(),
    })
}

#[derive(Deserialize)]
struct KvQuery {
    namespace: String,
    #[serde(default)]
    prefix: String,
}

#[derive(Deserialize)]
struct KvValueQuery {
    namespace: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KvWriteRequest {
    namespace: String,
    key: String,
    value: String,
}

fn validate_kv(namespace: &str, key: Option<&str>, writing: bool) -> ApiResult<()> {
    if namespace.trim().is_empty() || namespace.len() > 256 {
        return Err(ApiError::bad_request("命名空间长度必须为 1 至 256 个字符"));
    }
    if writing && namespace.starts_with("__rf") {
        return Err(ApiError::forbidden("内部 __rf 命名空间在控制台中为只读"));
    }
    if let Some(key) = key {
        if key.is_empty() || key.len() > 1024 {
            return Err(ApiError::bad_request("键名长度必须为 1 至 1024 个字符"));
        }
    }
    Ok(())
}

async fn kv_list(
    State(state): State<ConsoleState>,
    Query(query): Query<KvQuery>,
) -> ApiResult<Json<Value>> {
    validate_kv(&query.namespace, None, false)?;
    let keys = state
        .client
        .kv_list(&state.node, &query.namespace, &query.prefix)
        .await?;
    Ok(Json(json!({
        "namespace": query.namespace,
        "prefix": query.prefix,
        "keys": keys,
    })))
}

async fn kv_get(
    State(state): State<ConsoleState>,
    Query(query): Query<KvValueQuery>,
) -> ApiResult<Json<Value>> {
    validate_kv(&query.namespace, Some(&query.key), false)?;
    let value = state
        .client
        .kv_get(&state.node, &query.namespace, &query.key)
        .await?
        .ok_or_else(|| ApiError::not_found("未找到该 KV 键"))?;
    let utf8 = String::from_utf8(value.clone()).ok();
    use base64::Engine as _;
    Ok(Json(json!({
        "namespace": query.namespace,
        "key": query.key,
        "text": utf8,
        "base64": base64::engine::general_purpose::STANDARD.encode(value),
    })))
}

async fn kv_put(
    State(state): State<ConsoleState>,
    Json(request): Json<KvWriteRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    validate_kv(&request.namespace, Some(&request.key), true)?;
    if request.value.len() > MAX_CONSOLE_VALUE {
        return Err(ApiError::bad_request("控制台写入的 KV 值最大为 1 MiB"));
    }
    state
        .client
        .kv_put(
            &state.node,
            &request.namespace,
            &request.key,
            request.value.into_bytes(),
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

async fn kv_delete(
    State(state): State<ConsoleState>,
    Query(query): Query<KvValueQuery>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    validate_kv(&query.namespace, Some(&query.key), true)?;
    state
        .client
        .kv_delete(&state.node, &query.namespace, &query.key)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct D1CreateRequest {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct D1ExecRequest {
    name: String,
    sql: String,
    #[serde(default = "empty_array")]
    params: Value,
}

fn empty_array() -> Value {
    json!([])
}

async fn d1_create(
    State(state): State<ConsoleState>,
    Json(request): Json<D1CreateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&request.name) {
        return Err(ApiError::bad_request(
            "数据库名称须由 1 至 63 个小写字母、数字或连字符组成",
        ));
    }
    let raw = state
        .client
        .post(
            &state.node,
            "/v1/d1/create",
            json!({ "name": request.name }).to_string().into_bytes(),
        )
        .await?;
    Ok(Json(serde_json::from_slice(&raw)?))
}

async fn d1_exec(
    State(state): State<ConsoleState>,
    Json(request): Json<D1ExecRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&request.name) {
        return Err(ApiError::bad_request("数据库名称无效"));
    }
    if request.sql.trim().is_empty() || request.sql.len() > MAX_CONSOLE_VALUE {
        return Err(ApiError::bad_request(
            "SQL 长度必须介于 1 字节与 1 MiB 之间",
        ));
    }
    if !request.params.is_array() {
        return Err(ApiError::bad_request("参数必须是 JSON 数组"));
    }
    let result = state
        .client
        .d1_exec(&state.node, &request.name, &request.sql, request.params)
        .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct R2BucketRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    public_access: bool,
    #[serde(default = "default_storage_backend")]
    storage_backend: String,
    #[serde(default)]
    rclone_remote: String,
    #[serde(default)]
    rclone_prefix: String,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    max_objects: Option<u64>,
    #[serde(default)]
    expire_objects_after_days: Option<u32>,
    #[serde(default)]
    cors_origins: Vec<String>,
    #[serde(default)]
    hostnames: Vec<String>,
}

fn default_storage_backend() -> String {
    "local".into()
}

#[derive(Deserialize)]
struct R2ObjectListQuery {
    #[serde(default)]
    prefix: String,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn r2_bucket_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let buckets = state
        .client
        .resource_heads(&state.node, Some(crate::r2::BUCKET_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .map(|view| {
            let spec = crate::r2::bucket_spec(&view.resource)?;
            Ok(json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let status = state.client.status(&state.node).await?;
    Ok(Json(json!({
        "buckets": buckets,
        "capabilities": status.get("storage").cloned().unwrap_or_else(|| json!({
            "local": true,
            "rclone": false,
        })),
    })))
}

async fn r2_bucket_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<R2BucketRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let storage = match request.storage_backend.as_str() {
        "local" if request.rclone_remote.is_empty() && request.rclone_prefix.is_empty() => {
            crate::objectstore::StorageLocation::Local
        }
        "rclone" if !request.rclone_remote.is_empty() => {
            crate::objectstore::StorageLocation::Rclone {
                remote: request.rclone_remote,
                prefix: request.rclone_prefix,
            }
        }
        "local" => {
            return Err(ApiError::bad_request(
                "本地存储不能同时填写 rclone remote 或前缀",
            ))
        }
        "rclone" => return Err(ApiError::bad_request("请选择 rclone remote")),
        _ => return Err(ApiError::bad_request("存储后端必须是 local 或 rclone")),
    };
    let spec = crate::r2::BucketSpec {
        description: request.description,
        public_access: request.public_access,
        storage,
        max_bytes: request.max_bytes,
        max_objects: request.max_objects,
        expire_objects_after_days: request.expire_objects_after_days,
        cors_origins: request.cors_origins,
        hostnames: request.hostnames,
    };
    let head = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &request.name)
        .await?;
    let record = crate::r2::prepare_bucket_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("创建或更新 R2 bucket {} v{}", record.name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn r2_bucket_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &name)
        .await?
        .ok_or_else(|| ApiError::not_found("R2 bucket 不存在"))?;
    if head.resource.deleted {
        return Err(ApiError::not_found("R2 bucket 已删除"));
    }
    let spec = crate::r2::bucket_spec(&head.resource)?;
    let record = crate::r2::prepare_bucket_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "删除 R2 bucket {}（生成 v{} 墓碑）",
                    record.name, record.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    consumer_worker: Option<String>,
    #[serde(default = "queue_default_batch_size")]
    batch_size: u16,
    #[serde(default = "queue_default_wait_ms")]
    max_wait_ms: u64,
    #[serde(default = "queue_default_retries")]
    max_retries: u16,
    #[serde(default = "queue_default_visibility_ms")]
    visibility_timeout_ms: u64,
    #[serde(default = "queue_default_retention_seconds")]
    retention_seconds: u64,
    #[serde(default)]
    dead_letter_queue: Option<String>,
    #[serde(default)]
    suspended: bool,
}

fn queue_default_batch_size() -> u16 {
    10
}
fn queue_default_wait_ms() -> u64 {
    5_000
}
fn queue_default_retries() -> u16 {
    3
}
fn queue_default_visibility_ms() -> u64 {
    120_000
}
fn queue_default_retention_seconds() -> u64 {
    7 * 24 * 60 * 60
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueSendRequest {
    messages: Vec<crate::queue::SendMessage>,
}

#[derive(Debug, Deserialize)]
struct QueueDeadQuery {
    limit: Option<usize>,
}

async fn queue_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::queue::QUEUE_KIND))
        .await?;
    let mut queues = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::queue::queue_spec(&view.resource)?;
        let stats = state
            .client
            .queue_stats(&state.node, &view.resource.name)
            .await;
        queues.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": spec,
            "stats": stats.ok(),
        }));
    }
    Ok(Json(json!({ "queues": queues })))
}

async fn queue_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<QueueRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let spec = crate::queue::QueueSpec {
        description: request.description,
        consumer_worker: request
            .consumer_worker
            .filter(|worker| !worker.trim().is_empty()),
        batch_size: request.batch_size,
        max_wait_ms: request.max_wait_ms,
        max_retries: request.max_retries,
        visibility_timeout_ms: request.visibility_timeout_ms,
        retention_seconds: request.retention_seconds,
        dead_letter_queue: request
            .dead_letter_queue
            .filter(|queue| !queue.trim().is_empty()),
        suspended: request.suspended,
    };
    let head = state
        .client
        .resource_head(&state.node, crate::queue::QUEUE_KIND, &request.name)
        .await?;
    let record = crate::queue::prepare_queue_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("创建或更新队列 {} v{}", record.name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn queue_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::queue::QUEUE_KIND, &name)
        .await?
        .ok_or_else(|| ApiError::not_found("队列不存在"))?;
    if head.resource.deleted {
        return Err(ApiError::not_found("队列已删除"));
    }
    let spec = crate::queue::queue_spec(&head.resource)?;
    let record = crate::queue::prepare_queue_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "name": name })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("删除队列 {}（生成 v{} 墓碑）", name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn queue_send(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<QueueSendRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let ids = state
        .client
        .queue_send(&state.node, &name, &request.messages)
        .await?;
    Ok(Json(json!({ "ok": true, "message_ids": ids })))
}

async fn queue_dead_letters(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<QueueDeadQuery>,
) -> ApiResult<Json<Value>> {
    let dead_letters = state
        .client
        .queue_dead_letters(&state.node, &name, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "dead_letters": dead_letters })))
}

async fn queue_redrive(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.client.queue_redrive(&state.node, &name, &id).await? {
        return Err(ApiError::not_found("死信不存在"));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsDatasetRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    retention_days: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsWriteRequest {
    points: Vec<crate::analytics::DataPoint>,
}

#[derive(Debug, Deserialize)]
struct AnalyticsRecentQuery {
    before: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AnalyticsGroupQuery {
    #[serde(default = "analytics_default_dimension")]
    dimension: String,
    #[serde(default)]
    dimension_index: usize,
    double_index: Option<usize>,
    since: Option<u64>,
    limit: Option<usize>,
}

fn analytics_default_dimension() -> String {
    "blob".into()
}

async fn analytics_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::analytics::DATASET_KIND))
        .await?;
    let mut datasets = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::analytics::dataset_spec(&view.resource)?;
        let stats = state
            .client
            .analytics_stats(&state.node, &view.resource.name)
            .await
            .ok();
        datasets.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": spec,
            "stats": stats,
        }));
    }
    Ok(Json(json!({ "datasets": datasets })))
}

async fn analytics_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<AnalyticsDatasetRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let spec = crate::analytics::DatasetSpec {
        description: request.description,
        retention_days: request.retention_days,
    };
    let head = state
        .client
        .resource_head(&state.node, crate::analytics::DATASET_KIND, &request.name)
        .await?;
    let record =
        crate::analytics::prepare_dataset_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(
                json!({ "ok": true, "name": record.name, "version": record.version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "创建或更新 Analytics 数据集 {} v{}",
                    record.name, record.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn analytics_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::analytics::DATASET_KIND, &name)
        .await?
        .ok_or_else(|| ApiError::not_found("Analytics 数据集不存在"))?;
    if head.resource.deleted {
        return Err(ApiError::not_found("Analytics 数据集已删除"));
    }
    let spec = crate::analytics::dataset_spec(&head.resource)?;
    let record = crate::analytics::prepare_dataset_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "name": name })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "删除 Analytics 数据集 {}（生成 v{} 墓碑）",
                    name, record.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn analytics_write(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<AnalyticsWriteRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let written = state
        .client
        .analytics_write(&state.node, &name, &request.points)
        .await?;
    Ok(Json(json!({ "ok": true, "written": written })))
}

async fn analytics_recent(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<AnalyticsRecentQuery>,
) -> ApiResult<Json<Value>> {
    let events = state
        .client
        .analytics_recent(&state.node, &name, query.before, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "events": events })))
}

async fn analytics_stats(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::to_value(
        state.client.analytics_stats(&state.node, &name).await?,
    )?))
}

async fn analytics_group(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<AnalyticsGroupQuery>,
) -> ApiResult<Json<Value>> {
    let groups = state
        .client
        .analytics_group(
            &state.node,
            &name,
            &query.dimension,
            query.dimension_index,
            query.double_index,
            query.since.unwrap_or(0),
            query.limit.unwrap_or(20),
        )
        .await?;
    Ok(Json(json!({ "groups": groups })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineRequest {
    name: String,
    #[serde(default)]
    description: String,
    output_bucket: String,
    #[serde(default = "pipeline_default_key_template")]
    output_key_template: String,
    #[serde(default = "pipeline_default_batch_bytes")]
    batch_max_bytes: u64,
    #[serde(default = "pipeline_default_batch_seconds")]
    batch_max_seconds: u64,
    #[serde(default)]
    schema: Option<Value>,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
    #[serde(default)]
    hostnames: Vec<String>,
}

fn pipeline_default_key_template() -> String {
    "{pipeline}/year={yyyy}/month={mm}/day={dd}/hour={hh}/{agent}-{batchId}.jsonl.gz".into()
}

fn pipeline_default_batch_bytes() -> u64 {
    crate::pipeline::DEFAULT_BATCH_BYTES
}

fn pipeline_default_batch_seconds() -> u64 {
    crate::pipeline::DEFAULT_BATCH_SECONDS
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineTokenRequest {
    #[serde(default)]
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineIngestRequest {
    events: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct PipelineBatchQuery {
    limit: Option<usize>,
}

fn pipeline_spec_view(spec: &crate::pipeline::PipelineSpec) -> Value {
    json!({
        "description": spec.description,
        "output_bucket": spec.output_bucket,
        "output_key_template": spec.output_key_template,
        "batch_max_bytes": spec.batch_max_bytes,
        "batch_max_seconds": spec.batch_max_seconds,
        "schema": spec.schema,
        "suspended": spec.suspended,
        "suspend_reason": spec.suspend_reason,
        "hostnames": spec.hostnames,
        "tokens": spec.tokens.iter().map(|token| json!({
            "id": token.id,
            "label": token.label,
            "last_four": token.last_four,
            "created_at_ms": token.created_at_ms,
        })).collect::<Vec<_>>(),
    })
}

async fn pipeline_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::pipeline::PIPELINE_KIND))
        .await?;
    let mut pipelines = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::pipeline::pipeline_spec(&view.resource)?;
        let status = state
            .client
            .pipeline_status(&state.node, &view.resource.name)
            .await
            .ok();
        let default_hostname = match &state.mode {
            ConsoleMode::Public { node, .. } => node.default_pipeline_hostname(&view.resource.name),
            ConsoleMode::Local { .. } => None,
        };
        let hostnames = match &state.mode {
            ConsoleMode::Public { node, .. } => {
                node.effective_pipeline_hostnames(&view.resource.name, &spec)
            }
            ConsoleMode::Local { .. } => spec.hostnames.clone(),
        };
        pipelines.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": pipeline_spec_view(&spec),
            "status": status,
            "default_hostname": default_hostname,
            "hostnames": hostnames,
        }));
    }
    Ok(Json(json!({ "pipelines": pipelines })))
}

async fn pipeline_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<PipelineRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let bucket = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &request.output_bucket)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::bad_request("Pipeline 输出 R2 bucket 不存在"))?;
    crate::r2::bucket_spec(&bucket.resource)?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &request.name)
        .await?;
    let tokens = head
        .as_ref()
        .filter(|view| !view.resource.deleted)
        .map(|view| crate::pipeline::pipeline_spec(&view.resource))
        .transpose()?
        .map(|spec| spec.tokens)
        .unwrap_or_default();
    let mut hostnames: Vec<String> = request
        .hostnames
        .into_iter()
        .map(|hostname| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|hostname| !hostname.is_empty())
        .collect();
    hostnames.sort();
    hostnames.dedup();
    let spec = crate::pipeline::PipelineSpec {
        description: request.description,
        output_bucket: request.output_bucket,
        output_key_template: request.output_key_template,
        batch_max_bytes: request.batch_max_bytes,
        batch_max_seconds: request.batch_max_seconds,
        schema: request.schema,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
        hostnames,
        tokens,
    };
    let record =
        crate::pipeline::prepare_pipeline_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(
                json!({ "ok": true, "name": record.name, "version": record.version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("创建或更新 Pipeline {} v{}", record.name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Pipeline 不存在"))?;
    let spec = crate::pipeline::pipeline_spec(&head.resource)?;
    let record = crate::pipeline::prepare_pipeline_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "name": name })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("删除 Pipeline {}（生成 v{} 墓碑）", name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_token_mint(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<PipelineTokenRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Pipeline 不存在"))?;
    let mut spec = crate::pipeline::pipeline_spec(&head.resource)?;
    let (token, plaintext) = crate::pipeline::mint_token(request.label)?;
    spec.tokens.push(token.clone());
    let record = crate::pipeline::prepare_pipeline_after(&name, spec, false, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": name,
                "version": record.version,
                "token": plaintext,
                "token_id": token.id,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("为 Pipeline {} 创建接收令牌 {}", name, token.label),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "token": plaintext,
                "token_id": token.id,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_token_revoke(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Pipeline 不存在"))?;
    let mut spec = crate::pipeline::pipeline_spec(&head.resource)?;
    let before = spec.tokens.len();
    spec.tokens.retain(|token| token.id != id);
    if spec.tokens.len() == before {
        return Err(ApiError::not_found("Pipeline 令牌不存在"));
    }
    let record = crate::pipeline::prepare_pipeline_after(&name, spec, false, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(
                json!({ "ok": true, "name": name, "version": record.version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("撤销 Pipeline {} 接收令牌 {}", name, id),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_ingest(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<PipelineIngestRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let accepted = state
        .client
        .pipeline_ingest(&state.node, &name, &request.events)
        .await?;
    Ok(Json(json!({ "ok": true, "accepted": accepted })))
}

async fn pipeline_status(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::to_value(
        state.client.pipeline_status(&state.node, &name).await?,
    )?))
}

async fn pipeline_batches(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<PipelineBatchQuery>,
) -> ApiResult<Json<Value>> {
    let batches = state
        .client
        .pipeline_batches(&state.node, &name, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "batches": batches })))
}

async fn pipeline_flush(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let batch = state.client.pipeline_flush(&state.node, &name).await?;
    Ok(Json(json!({ "ok": true, "batch": batch })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowRequest {
    name: String,
    worker: String,
    #[serde(default = "workflow_default_entrypoint")]
    entrypoint: String,
    #[serde(default)]
    description: String,
    #[serde(default = "workflow_default_retention_days")]
    retention_days: u16,
    #[serde(default = "workflow_default_retries")]
    instance_retries: u16,
    #[serde(default = "workflow_default_timeout")]
    instance_timeout_seconds: u64,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
}

fn workflow_default_entrypoint() -> String {
    "MyWorkflow".into()
}

fn workflow_default_retention_days() -> u16 {
    30
}

fn workflow_default_retries() -> u16 {
    3
}

fn workflow_default_timeout() -> u64 {
    25 * 60
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowTriggerRequest {
    instance_key: Option<String>,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
struct WorkflowInstancesQuery {
    status: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowSignalRequest {
    name: String,
    #[serde(default)]
    payload: Value,
}

async fn workflow_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::workflow::WORKFLOW_KIND))
        .await?;
    let mut workflows = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::workflow::workflow_spec(&view.resource)?;
        let stats = state
            .client
            .workflow_stats(&state.node, &view.resource.name)
            .await
            .ok();
        workflows.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": spec,
            "stats": stats,
        }));
    }
    Ok(Json(json!({ "workflows": workflows })))
}

async fn workflow_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<WorkflowRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    current_manifest(&state, &request.worker)
        .await
        .map_err(|_| ApiError::bad_request("Workflow 执行 Worker 不存在或部署链无效"))?;
    let head = state
        .client
        .resource_head(&state.node, crate::workflow::WORKFLOW_KIND, &request.name)
        .await?;
    let spec = crate::workflow::WorkflowSpec {
        description: request.description,
        worker: request.worker,
        entrypoint: request.entrypoint,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
        retention_days: request.retention_days,
        instance_retries: request.instance_retries,
        instance_timeout_seconds: request.instance_timeout_seconds,
    };
    let record =
        crate::workflow::prepare_workflow_after(&request.name, spec, false, head.as_ref())?;
    submit_workflow_resource(
        &state,
        &principal,
        record,
        format!("创建或更新 Workflow {}", request.name),
    )
    .await
}

async fn workflow_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::workflow::WORKFLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Workflow 不存在"))?;
    let spec = crate::workflow::workflow_spec(&head.resource)?;
    let record = crate::workflow::prepare_workflow_after(&name, spec, true, Some(&head))?;
    submit_workflow_resource(&state, &principal, record, format!("删除 Workflow {name}")).await
}

async fn submit_workflow_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn workflow_trigger(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<WorkflowTriggerRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let instance = state
        .client
        .workflow_create(
            &state.node,
            &name,
            request.instance_key.as_deref(),
            request.input,
        )
        .await?;
    Ok(Json(json!({ "ok": true, "instance": instance })))
}

async fn workflow_instances(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<WorkflowInstancesQuery>,
) -> ApiResult<Json<Value>> {
    let instances = state
        .client
        .workflow_instances(
            &state.node,
            &name,
            query.status.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({ "instances": instances })))
}

async fn workflow_instance(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .client
            .workflow_instance(&state.node, &name, &id)
            .await?,
    ))
}

async fn workflow_signal(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
    Json(request): Json<WorkflowSignalRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let signal_id = state
        .client
        .workflow_signal(&state.node, &name, &id, &request.name, request.payload)
        .await?;
    Ok(Json(json!({ "ok": true, "signal_id": signal_id })))
}

async fn workflow_action(
    State(state): State<ConsoleState>,
    Path((name, id, action)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    state
        .client
        .workflow_action(&state.node, &name, &id, &action)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowRequest {
    name: String,
    #[serde(default)]
    description: String,
    graph: crate::flow::FlowGraph,
    #[serde(default)]
    trigger: crate::flow::FlowTrigger,
    #[serde(default)]
    cron: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
    #[serde(default = "flow_default_retention_days")]
    retention_days: u16,
    #[serde(default = "flow_default_max_concurrent_runs")]
    max_concurrent_runs: u16,
    #[serde(default)]
    alert_webhook_env: Option<String>,
    /// When present, mint a first/extra Webhook token in the same signed edit.
    #[serde(default)]
    webhook_token_label: Option<String>,
}

fn flow_default_retention_days() -> u16 {
    30
}

fn flow_default_max_concurrent_runs() -> u16 {
    32
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowTokenRequest {
    #[serde(default)]
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowTriggerRequest {
    #[serde(default)]
    run_key: Option<String>,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
struct FlowRunsQuery {
    status: Option<String>,
    limit: Option<usize>,
}

async fn flow_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::flow::FLOW_KIND))
        .await?;
    let status = state.client.status(&state.node).await.ok();
    let default_domain = status
        .as_ref()
        .and_then(|status| status.get("default_worker_domain"))
        .and_then(Value::as_str);
    let mut flows = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::flow::flow_spec(&view.resource)?;
        let stats = state
            .client
            .flow_stats(&state.node, &view.resource.name)
            .await
            .ok();
        let default_hostname =
            default_domain.map(|domain| format!("flow-{}.{domain}", view.resource.name));
        let mut hostnames = default_hostname.iter().cloned().collect::<Vec<_>>();
        for hostname in &spec.hostnames {
            if !hostnames.contains(hostname) {
                hostnames.push(hostname.clone());
            }
        }
        flows.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "default_hostname": default_hostname,
            "hostnames": hostnames,
            "spec": spec,
            "stats": stats,
        }));
    }
    Ok(Json(json!({ "flows": flows })))
}

async fn flow_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<FlowRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &request.name)
        .await?;
    let mut tokens = head
        .as_ref()
        .and_then(|head| crate::flow::flow_spec(&head.resource).ok())
        .map(|spec| spec.tokens)
        .unwrap_or_default();
    let minted = if let Some(label) = request.webhook_token_label {
        let (token, plaintext) = crate::flow::mint_token(label)?;
        let id = token.id.clone();
        tokens.push(token);
        Some((id, plaintext))
    } else {
        None
    };
    let spec = crate::flow::FlowSpec {
        description: request.description,
        graph: request.graph,
        trigger: request.trigger,
        cron: request.cron,
        hostnames: request.hostnames,
        tokens,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
        retention_days: request.retention_days,
        max_concurrent_runs: request.max_concurrent_runs,
        alert_webhook_env: request.alert_webhook_env,
    };
    let record = crate::flow::prepare_flow_after(&request.name, spec, false, head.as_ref())?;
    let mut response = submit_flow_resource(
        &state,
        &principal,
        record,
        format!("创建或更新 Flow {}", request.name),
    )
    .await?
    .0;
    if let Some((id, plaintext)) = minted {
        response["token"] = Value::String(plaintext);
        response["token_id"] = Value::String(id);
    }
    Ok(Json(response))
}

async fn flow_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Flow 不存在"))?;
    let spec = crate::flow::flow_spec(&head.resource)?;
    let record = crate::flow::prepare_flow_after(&name, spec, true, Some(&head))?;
    submit_flow_resource(&state, &principal, record, format!("删除 Flow {name}")).await
}

async fn flow_token_mint(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<FlowTokenRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Flow 不存在"))?;
    let mut spec = crate::flow::flow_spec(&head.resource)?;
    let (token, plaintext) = crate::flow::mint_token(request.label)?;
    let token_id = token.id.clone();
    spec.tokens.push(token);
    let record = crate::flow::prepare_flow_after(&name, spec, false, Some(&head))?;
    let mut response = submit_flow_resource(
        &state,
        &principal,
        record,
        format!("为 Flow {name} 签发 Webhook 令牌"),
    )
    .await?
    .0;
    response["token"] = Value::String(plaintext);
    response["token_id"] = Value::String(token_id);
    Ok(Json(response))
}

async fn flow_token_revoke(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Flow 不存在"))?;
    let mut spec = crate::flow::flow_spec(&head.resource)?;
    let before = spec.tokens.len();
    spec.tokens.retain(|token| token.id != id);
    if before == spec.tokens.len() {
        return Err(ApiError::not_found("Flow Webhook 令牌不存在"));
    }
    let record = crate::flow::prepare_flow_after(&name, spec, false, Some(&head))?;
    submit_flow_resource(
        &state,
        &principal,
        record,
        format!("撤销 Flow {name} 的 Webhook 令牌 {id}"),
    )
    .await
}

async fn submit_flow_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn flow_trigger(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<FlowTriggerRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let run = state
        .client
        .flow_create(
            &state.node,
            &name,
            request.run_key.as_deref(),
            request.input,
        )
        .await?;
    Ok(Json(json!({ "ok": true, "run": run })))
}

async fn flow_runs(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<FlowRunsQuery>,
) -> ApiResult<Json<Value>> {
    let runs = state
        .client
        .flow_runs(
            &state.node,
            &name,
            query.status.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({ "runs": runs })))
}

async fn flow_run(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(state.client.flow_run(&state.node, &name, &id).await?))
}

async fn flow_action(
    State(state): State<ConsoleState>,
    Path((name, id, action)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let result = state
        .client
        .flow_action(&state.node, &name, &id, &action)
        .await?;
    Ok(Json(json!({ "ok": true, "result": result })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailDomainRequest {
    name: String,
    #[serde(default)]
    description: String,
    domain: String,
    mx_hostname: String,
    bucket: String,
    #[serde(default = "email_default_object_prefix")]
    object_prefix: String,
    #[serde(default)]
    routes: Vec<crate::email::EmailRoute>,
    #[serde(default = "email_default_max_message_bytes")]
    max_message_bytes: u64,
    #[serde(default = "email_default_per_minute")]
    inbound_per_minute: u32,
    #[serde(default = "email_default_per_minute")]
    outbound_per_minute: u32,
    #[serde(default = "email_default_retention_days")]
    retention_days: u16,
    #[serde(default = "email_default_dkim_selector")]
    dkim_selector: String,
    #[serde(default)]
    dkim_public_key: String,
    #[serde(default)]
    dkim_private_key_env: String,
    #[serde(default)]
    rotate_verification: bool,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
}

fn email_default_object_prefix() -> String {
    "mail".into()
}

fn email_default_max_message_bytes() -> u64 {
    25 * 1024 * 1024
}

fn email_default_per_minute() -> u32 {
    1_000
}

fn email_default_retention_days() -> u16 {
    30
}

fn email_default_dkim_selector() -> String {
    "rf".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailSendRequest {
    mail_from: String,
    recipients: Vec<String>,
    raw_base64: String,
}

#[derive(Debug, Deserialize)]
struct EmailMessagesQuery {
    limit: Option<usize>,
}

async fn email_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::email::EMAIL_DOMAIN_KIND))
        .await?;
    let mut domains = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::email::email_domain_spec(&view.resource)?;
        let verification = state
            .client
            .email_verification(&state.node, &view.resource.name)
            .await
            .ok()
            .flatten();
        domains.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": spec,
            "verification": verification,
        }));
    }
    let status = state.client.status(&state.node).await.ok();
    Ok(Json(json!({
        "domains": domains,
        "email_node": status.as_ref().and_then(|value| value.get("email_node")).cloned(),
        "buckets": status.as_ref().and_then(|value| value.get("r2_buckets")).cloned().unwrap_or_else(|| json!([])),
        "workers": status.as_ref().and_then(|value| value.get("workers")).cloned().unwrap_or_else(|| json!([])),
    })))
}

async fn email_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<EmailDomainRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let bucket = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &request.bucket)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::bad_request("邮件原文 R2 bucket 不存在"))?;
    crate::r2::bucket_spec(&bucket.resource)?;
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::email::EMAIL_DOMAIN_KIND))
        .await?;
    for view in records
        .into_iter()
        .filter(|view| !view.resource.deleted && view.resource.name != request.name)
    {
        let existing = crate::email::email_domain_spec(&view.resource)?;
        if existing.domain.eq_ignore_ascii_case(&request.domain) {
            return Err(ApiError::bad_request(format!(
                "邮件域 {} 已由资源 {} 管理",
                request.domain, view.resource.name
            )));
        }
    }
    let head = state
        .client
        .resource_head(&state.node, crate::email::EMAIL_DOMAIN_KIND, &request.name)
        .await?;
    let previous = head
        .as_ref()
        .and_then(|view| crate::email::email_domain_spec(&view.resource).ok());
    let verification_challenge = if request.rotate_verification {
        crate::email::generate_verification_challenge()
    } else {
        previous
            .as_ref()
            .map(|spec| spec.verification_challenge.clone())
            .unwrap_or_else(crate::email::generate_verification_challenge)
    };
    let spec = crate::email::EmailDomainSpec {
        description: request.description,
        domain: request.domain,
        verification_challenge,
        mx_hostname: request.mx_hostname,
        bucket: request.bucket,
        object_prefix: request.object_prefix,
        routes: request.routes,
        max_message_bytes: request.max_message_bytes,
        inbound_per_minute: request.inbound_per_minute,
        outbound_per_minute: request.outbound_per_minute,
        retention_days: request.retention_days,
        dkim_selector: request.dkim_selector,
        dkim_public_key: request.dkim_public_key,
        dkim_private_key_env: request.dkim_private_key_env,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
    };
    let dns = json!({
        "ownership_name": spec.ownership_txt_name(),
        "ownership_value": spec.ownership_txt_value(),
        "mx_name": spec.domain,
        "mx_value": spec.mx_hostname,
        "dkim_name": spec.dkim_txt_name(),
        "dkim_value": spec.dkim_public_key,
    });
    let record =
        crate::email::prepare_email_domain_after(&request.name, spec, false, head.as_ref())?;
    let mut response = submit_email_resource(
        &state,
        &principal,
        record,
        format!("创建或更新邮件域 {}", request.name),
    )
    .await?
    .0;
    response["dns"] = dns;
    Ok(Json(response))
}

async fn email_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::email::EMAIL_DOMAIN_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("邮件域不存在"))?;
    let spec = crate::email::email_domain_spec(&head.resource)?;
    let record = crate::email::prepare_email_domain_after(&name, spec, true, Some(&head))?;
    submit_email_resource(&state, &principal, record, format!("删除邮件域 {name}")).await
}

async fn submit_email_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn email_verification(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let verification = state.client.email_verification(&state.node, &name).await?;
    Ok(Json(json!({ "verification": verification })))
}

async fn email_verify(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let verification = state.client.email_verify(&state.node, &name).await?;
    Ok(Json(json!({ "ok": true, "verification": verification })))
}

async fn email_messages(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<EmailMessagesQuery>,
) -> ApiResult<Json<Value>> {
    let messages = state
        .client
        .email_messages(&state.node, &name, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "messages": messages })))
}

async fn email_message(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let message = state.client.email_message(&state.node, &name, &id).await?;
    Ok(Json(json!({ "message": message })))
}

async fn email_message_raw(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let raw = state
        .client
        .email_message_raw(&state.node, &name, &id)
        .await?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("message/rfc822"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{id}.eml\""))
                    .map_err(|_| ApiError::bad_request("邮件 ID 无效"))?,
            ),
        ],
        raw,
    )
        .into_response())
}

async fn email_send(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<EmailSendRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(request.raw_base64)
        .map_err(|_| ApiError::bad_request("RFC 822 原文不是有效 Base64"))?;
    let metadata = crate::email::EmailSendMetadata {
        mail_from: request.mail_from,
        recipients: request.recipients,
    };
    let queued = state
        .client
        .email_send(&state.node, &name, &metadata, &raw)
        .await?;
    Ok(Json(json!({ "ok": true, "queued": queued })))
}

async fn r2_object_list(
    State(state): State<ConsoleState>,
    Path(bucket): Path<String>,
    Query(query): Query<R2ObjectListQuery>,
) -> ApiResult<Json<Value>> {
    let objects = state
        .client
        .r2_list(
            &state.node,
            &bucket,
            &query.prefix,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({
        "bucket": bucket,
        "objects": objects.objects,
        "truncated": objects.truncated,
        "cursor": objects.cursor,
    })))
}

async fn r2_object_get(
    State(state): State<ConsoleState>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (metadata, bytes) = state
        .client
        .r2_get(&state.node, &bucket, &key)
        .await?
        .ok_or_else(|| ApiError::not_found("R2 对象不存在"))?;
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(
            metadata
                .content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
        )
        .map_err(|_| ApiError::upstream("R2 对象 Content-Type 无效"))?,
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", metadata.etag))
            .map_err(|_| ApiError::upstream("R2 对象 ETag 无效"))?,
    );
    Ok(response)
}

async fn r2_object_put(
    State(state): State<ConsoleState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if body.len() > crate::r2::MAX_DIRECT_OBJECT_BYTES {
        return Err(ApiError::bad_request(
            "控制台单次上传最大为 63 MiB；更大的对象请使用分片上传",
        ));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| *value != "application/octet-stream")
        .map(str::to_string);
    let metadata = state
        .client
        .r2_put(
            &state.node,
            &bucket,
            &key,
            &body,
            &crate::r2::PutOptions {
                content_type,
                ..Default::default()
            },
        )
        .await?;
    Ok(Json(json!({ "ok": true, "object": metadata })))
}

async fn r2_object_delete(
    State(state): State<ConsoleState>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.client.r2_delete(&state.node, &bucket, &key).await? {
        return Err(ApiError::not_found("R2 对象不存在"));
    }
    Ok(Json(json!({ "ok": true })))
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn upstream(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }

    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::upstream(error.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::upstream(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use rf_core::identity::Keypair;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[test]
    fn same_origin_supports_http2_authority_and_rejects_cross_origin() {
        let http2 = Request::builder()
            .uri("https://Console.Example/api/auth/challenge")
            .header(header::ORIGIN, "https://console.example")
            .body(Body::empty())
            .unwrap();
        assert!(same_origin(&http2, "https"));

        let http1 = Request::builder()
            .uri("/api/auth/challenge")
            .header(header::HOST, "127.0.0.1:18080")
            .header(header::ORIGIN, "http://127.0.0.1:18080")
            .body(Body::empty())
            .unwrap();
        assert!(same_origin(&http1, "http"));

        let wrong_host = Request::builder()
            .uri("https://console.example/api/auth/challenge")
            .header(header::ORIGIN, "https://attacker.example")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&wrong_host, "https"));

        let wrong_scheme = Request::builder()
            .uri("https://console.example/api/auth/challenge")
            .header(header::ORIGIN, "http://console.example")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&wrong_scheme, "https"));

        let origin_with_path = Request::builder()
            .uri("https://console.example/api/auth/challenge")
            .header(header::ORIGIN, "https://console.example/not-an-origin")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&origin_with_path, "https"));
    }

    #[test]
    fn editor_paths_are_strict_relative_paths() {
        for path in ["index.js", "src/worker.mjs", "public/中文.txt"] {
            assert!(validate_editor_path(path).is_ok(), "{path}");
        }
        for path in [
            "",
            "/index.js",
            "../secret",
            "src/../secret",
            "src//worker.js",
            "src\\worker.js",
            "./index.js",
            "index.js\nignored",
        ] {
            assert!(validate_editor_path(path).is_err(), "{path:?}");
        }
    }

    fn state() -> ConsoleState {
        ConsoleState::new("127.0.0.1:9".into(), [7u8; 32], None)
    }

    fn operator_state() -> ConsoleState {
        ConsoleState::new(
            "127.0.0.1:9".into(),
            [7u8; 32],
            Some(AnyKeypair::Ed(Keypair::from_seed([9u8; 32]))),
        )
    }

    #[test]
    fn worker_settings_create_a_linked_manifest_and_preserve_internal_metadata() {
        assert!(valid_compatibility_date("2028-02-29"));
        assert!(!valid_compatibility_date("2027-02-29"));
        assert!(!valid_compatibility_date("2026-十三-01"));
        let mut env = BTreeMap::from([("GREETING".into(), "hello".into())]);
        env.insert(
            deploy::DO_METADATA_ENV.into(),
            r#"{"COUNTER":{"class_name":"Counter","unique_key":"counter","enable_sql":true}}"#
                .into(),
        );
        env.insert(
            deploy::R2_METADATA_ENV.into(),
            r#"{"OLD":"archive"}"#.into(),
        );
        env.insert(
            deploy::D1_METADATA_ENV.into(),
            r#"{"OLD_DB":"archive"}"#.into(),
        );
        env.insert(
            deploy::QUEUE_METADATA_ENV.into(),
            r#"{"OLD_QUEUE":"archive"}"#.into(),
        );
        env.insert(
            deploy::ANALYTICS_METADATA_ENV.into(),
            r#"{"OLD_METRICS":"archive"}"#.into(),
        );
        env.insert(
            deploy::PIPELINE_METADATA_ENV.into(),
            r#"{"OLD_PIPE":"archive"}"#.into(),
        );
        let encrypted = crate::worker_secret::encrypt(
            &[7; 32],
            "demo",
            "API_TOKEN",
            "console-must-never-return-this",
        )
        .unwrap();
        env.insert(
            deploy::SECRET_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([("API_TOKEN", encrypted)])).unwrap(),
        );
        let manifest = WorkerManifest {
            name: "demo".into(),
            version: 4,
            prev: Some([3; 32]),
            deleted: false,
            main: String::new(),
            modules: vec![],
            assets: vec![],
            hostnames: vec!["old.example".into()],
            env,
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-08-01".into(),
        };
        let updated = apply_worker_settings(
            manifest,
            [9; 32],
            WorkerSettingsRequest {
                hostnames: Some(vec!["API.Example.com.".into(), "api.example.com".into()]),
                env: Some(BTreeMap::from([("MODE".into(), "production".into())])),
                kv_bindings: Some(BTreeMap::from([("CACHE".into(), "shared".into())])),
                r2_bindings: Some(BTreeMap::from([("ASSETS".into(), "assets".into())])),
                d1_bindings: Some(BTreeMap::from([("DB".into(), "primary".into())])),
                queue_bindings: Some(BTreeMap::from([("JOBS".into(), "jobs".into())])),
                analytics_bindings: Some(BTreeMap::from([(
                    "METRICS".into(),
                    "web-metrics".into(),
                )])),
                pipeline_bindings: Some(BTreeMap::from([("ARCHIVE".into(), "event-pipe".into())])),
                workflow_bindings: Some(BTreeMap::from([(
                    "ORDER_FLOW".into(),
                    "order-flow".into(),
                )])),
                email_bindings: Some(BTreeMap::from([(
                    "SUPPORT_MAIL".into(),
                    "support-mail".into(),
                )])),
                service_bindings: Some(BTreeMap::from([("BACKEND".into(), "backend".into())])),
                crons: Some(vec!["*/5 * * * *".into()]),
                compatibility_date: Some("2026-08-04".into()),
                compatibility_flags: Some(vec!["nodejs_compat".into()]),
            },
        )
        .unwrap();
        assert_eq!(updated.version, 5);
        assert_eq!(updated.prev, Some([9; 32]));
        assert_eq!(updated.hostnames, vec!["api.example.com"]);
        assert_eq!(updated.env["MODE"], "production");
        assert!(updated.env.contains_key(deploy::DO_METADATA_ENV));
        assert_eq!(deploy::r2_bindings(&updated)["ASSETS"], "assets");
        assert_eq!(deploy::d1_bindings(&updated)["DB"], "primary");
        assert_eq!(
            deploy::email_bindings(&updated)["SUPPORT_MAIL"],
            "support-mail"
        );
        assert_eq!(deploy::queue_bindings(&updated)["JOBS"], "jobs");
        assert_eq!(
            deploy::analytics_bindings(&updated)["METRICS"],
            "web-metrics"
        );
        assert_eq!(deploy::pipeline_bindings(&updated)["ARCHIVE"], "event-pipe");
        assert_eq!(
            deploy::workflow_bindings(&updated)["ORDER_FLOW"],
            "order-flow"
        );
        assert_eq!(deploy::service_bindings(&updated)["BACKEND"], "backend");
        assert_eq!(updated.kv_bindings["CACHE"], "shared");
        assert_eq!(updated.crons, vec!["*/5 * * * *"]);
        assert_eq!(deploy::compatibility_flags(&updated), ["nodejs_compat"]);
        assert!(updated.env.contains_key(deploy::SECRET_METADATA_ENV));
        let exposed = worker_console_environment(&updated);
        let exposed_json = serde_json::to_string(&exposed).unwrap();
        assert!(!exposed.contains_key(deploy::SECRET_METADATA_ENV));
        assert!(!exposed_json.contains("console-must-never-return-this"));
        assert_eq!(
            crate::worker_secret::encrypted_secrets(&updated)
                .into_keys()
                .collect::<Vec<_>>(),
            vec!["API_TOKEN"]
        );
    }

    #[test]
    fn pipeline_console_view_never_exposes_token_hashes() {
        let (token, plaintext) = crate::pipeline::mint_token("生产采集器").unwrap();
        let digest = token.sha256.clone();
        let spec = crate::pipeline::PipelineSpec {
            description: String::new(),
            output_bucket: "archive".into(),
            output_key_template: "events/{batchId}.jsonl.gz".into(),
            batch_max_bytes: crate::pipeline::DEFAULT_BATCH_BYTES,
            batch_max_seconds: crate::pipeline::DEFAULT_BATCH_SECONDS,
            schema: None,
            suspended: false,
            suspend_reason: String::new(),
            hostnames: vec![],
            tokens: vec![token],
        };
        let view = pipeline_spec_view(&spec).to_string();
        assert!(!view.contains(&digest));
        assert!(!view.contains(&plaintext));
        assert!(view.contains("生产采集器"));
    }

    fn public_state(secure: bool) -> (ConsoleState, Arc<Node>, AnyKeypair) {
        let operator = AnyKeypair::Ed(Keypair::from_seed([19u8; 32]));
        let data_dir = std::env::temp_dir().join(format!(
            "rf-console-public-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let config: crate::config::NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {data_dir:?}
            cluster_id = "console-test"
            label = "console-node"
            operator = "{operator}"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            public = true
            [gossip]
            listen = "127.0.0.1:17381"
            advertise = "127.0.0.1:17381"
            [peer_api]
            listen = "127.0.0.1:17382"
            advertise = "127.0.0.1:17382"
            [ingress]
            http = "127.0.0.1:18080"
            https = "127.0.0.1:18443"
            default_domain = "example.com"
            [acme]
            email = "ops@example.com"
            hostnames = ["*.example.com"]
            include_worker_hostnames = true
            zone = "example.com"
            "#,
            data_dir = data_dir.display(),
            operator = operator.signer_id(),
        ))
        .unwrap();
        let node = Arc::new(Node::open(config, Keypair::from_seed([20u8; 32])).unwrap());
        let state = ConsoleState::public(node.clone(), secure).unwrap();
        (state, node, operator)
    }

    #[test]
    fn worker_tls_view_reports_certificate_without_exposing_key_material() {
        let (_, node, _) = public_state(false);
        let now = now_ms();
        let record = crate::acme::CertRecord {
            hostname: "*.example.com".into(),
            cert_pem: "CERTIFICATE-MATERIAL".into(),
            key_pem: "PRIVATE-KEY-MATERIAL".into(),
            issued_ms: now,
            expires_ms: now + 60 * 24 * 60 * 60 * 1000,
        };
        node.kv_put(
            crate::acme::NS,
            &crate::acme::cert_kv_key("*.example.com"),
            Some(serde_json::to_vec(&record).unwrap()),
            None,
        )
        .unwrap();

        let view = worker_tls_view(&node, &["api.example.com".into()]);
        assert_eq!(view["enabled"], true);
        assert_eq!(view["include_worker_hostnames"], true);
        assert_eq!(view["certificates"][0]["status"], "active");
        assert_eq!(view["certificates"][0]["coverage"], "wildcard");
        assert_eq!(view["certificates"][0]["covered_by"], "*.example.com");
        let encoded = view.to_string();
        assert!(!encoded.contains("CERTIFICATE-MATERIAL"));
        assert!(!encoded.contains("PRIVATE-KEY-MATERIAL"));
    }

    #[tokio::test]
    async fn static_page_embeds_token_and_security_headers() {
        let state = state();
        let response = router(state.clone())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("RandallFlare 管理控制台"));
        assert!(body.contains(r#"<html lang="zh-CN">"#));
        assert!(body.contains("一次构建，一次验证，处处运行。"));
        assert!(body.contains("尚未选择目录"));
        assert!(!body.contains(">Overview<"));
        assert!(!body.contains(">Sign out<"));
        assert!(body.contains(state.local_token()));
        assert!(!body.contains("__RF_TOKEN__"));
    }

    #[tokio::test]
    async fn api_requires_token_and_session_never_contains_secret() {
        let state = state();
        let app = router(state.clone());
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header(TOKEN_HEADER, state.local_token())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let body = to_bytes(allowed.into_body(), 1024 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("RandallFlare"));
        assert!(!text.contains(&hex::encode([7u8; 32])));
    }

    #[test]
    fn internal_kv_writes_are_rejected() {
        assert!(validate_kv("__rf", Some("d1/test"), true).is_err());
        assert!(validate_kv("public", Some("key"), true).is_ok());
    }

    #[test]
    fn console_only_accepts_loopback_listeners() {
        assert!(validate_listen("127.0.0.1:7390".parse().unwrap()).is_ok());
        assert!(validate_listen("[::1]:7390".parse().unwrap()).is_ok());
        assert!(validate_listen("0.0.0.0:7390".parse().unwrap()).is_err());
        assert!(validate_listen("192.0.2.10:7390".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn observer_mode_rejects_mutations() {
        let state = state();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/kv/value")
                    .header(TOKEN_HEADER, state.local_token())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"namespace":"public","key":"key","value":"value"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn internal_namespace_write_is_rejected_before_network_access() {
        let state = operator_state();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/kv/value")
                    .header(TOKEN_HEADER, state.local_token())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"namespace":"__rf","key":"d1/test","value":"value"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn public_console_requires_operator_signed_stateless_session() {
        use base64::Engine as _;

        let (state, node, operator) = public_state(true);
        let app = router(state.clone());
        let page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "console.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let page = to_bytes(page.into_body(), 1024 * 1024).await.unwrap();
        let page = String::from_utf8(page.to_vec()).unwrap();
        assert!(page.contains("content=\"public\""));
        assert!(!page.contains(&node.cfg.cluster_secret));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header(header::HOST, "console.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let cross_origin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://console.test/api/auth/challenge")
                    .header(header::ORIGIN, "https://attacker.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);

        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://console.test/api/auth/challenge")
                    .header(header::ORIGIN, "https://console.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge = to_bytes(challenge.into_body(), 1024 * 1024).await.unwrap();
        let challenge: Value = serde_json::from_slice(&challenge).unwrap();
        let id = challenge["id"].as_str().unwrap();
        let code = challenge["code"].as_str().unwrap();
        let approval = node.management.view_by_code(code).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(approval.payload_base64)
            .unwrap();
        node.management
            .approve(
                code,
                operator.signer_id(),
                operator.sign(&payload),
                &operator.signer_id(),
            )
            .unwrap();

        let approved = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/auth/challenge/{id}"))
                    .header(header::HOST, "console.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);
        let set_cookie = approved.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));
        assert!(set_cookie.contains("Secure"));
        let cookie = set_cookie.split(';').next().unwrap();

        let session = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header(header::HOST, "console.test")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        let session = to_bytes(session.into_body(), 1024 * 1024).await.unwrap();
        let session: Value = serde_json::from_slice(&session).unwrap();
        assert_eq!(session["auth_mode"], "operator_grant");
        let csrf = session["csrf"].as_str().unwrap();

        let missing_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/logout")
                    .header(header::HOST, "console.test")
                    .header(header::ORIGIN, "https://console.test")
                    .header(header::COOKIE, cookie)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

        let logout = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/logout")
                    .header(header::HOST, "console.test")
                    .header(header::ORIGIN, "https://console.test")
                    .header(header::COOKIE, cookie)
                    .header(CSRF_HEADER, csrf)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(logout.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
    }
}
