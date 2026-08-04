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
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rand::RngCore;
use rf_core::identity::AnyKeypair;
use rf_core::manifest::{valid_name, ManifestError, WorkerManifest};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

const INDEX_HTML: &str = include_str!("console/index.html");
const APP_JS: &str = include_str!("console/app.js");
const STYLES_CSS: &str = include_str!("console/styles.css");
const TOKEN_HEADER: &str = "x-rf-console-token";
const CSRF_HEADER: &str = "x-rf-csrf";
const SESSION_COOKIE: &str = "rf_console_session";
const MAX_CONSOLE_VALUE: usize = 1024 * 1024;
const MAX_CONSOLE_UPLOAD: usize = 64 * 1024 * 1024;
const MAX_CONSOLE_FILES: usize = 2048;

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
            mode: ConsoleMode::Local {
                operator: operator.map(Arc::new),
                token: hex::encode(token).into(),
            },
            started: Instant::now(),
        }
    }

    pub fn public(node: Arc<Node>, secure_cookies: bool) -> Result<Self> {
        let peer = format!("127.0.0.1:{}", node.cfg.peer_api.listen.port());
        Ok(Self {
            node: peer.into(),
            client: PeerClient::new(node.cfg.cluster_secret_bytes()?),
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
    crons: Option<Vec<String>>,
    #[serde(default)]
    compatibility_date: Option<String>,
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
    let mut env = manifest.env.clone();
    env.remove(deploy::DO_METADATA_ENV);
    let durable_objects = deploy::durable_objects(&manifest);
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
            "crons": manifest.crons,
            "compatibility_date": manifest.compatibility_date,
            "durable_objects": durable_objects,
        },
        "source": source,
        "tls": tls,
    })))
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
        crons,
        compatibility_date,
    } = request;
    if hostnames.is_none()
        && env.is_none()
        && kv_bindings.is_none()
        && crons.is_none()
        && compatibility_date.is_none()
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
        if env.contains_key(deploy::DO_METADATA_ENV) {
            return Err(ApiError::bad_request(
                "不能修改 RandallFlare 保留的环境变量",
            ));
        }
        validate_settings_map(&env, "环境变量")?;
        if let Some(durable_objects) = manifest.env.get(deploy::DO_METADATA_ENV).cloned() {
            env.insert(deploy::DO_METADATA_ENV.into(), durable_objects);
        }
        manifest.env = env;
    }
    if let Some(kv_bindings) = kv_bindings {
        validate_settings_map(&kv_bindings, "KV 绑定")?;
        manifest.kv_bindings = kv_bindings;
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
                crons: Some(vec!["*/5 * * * *".into()]),
                compatibility_date: Some("2026-08-04".into()),
            },
        )
        .unwrap();
        assert_eq!(updated.version, 5);
        assert_eq!(updated.prev, Some([9; 32]));
        assert_eq!(updated.hostnames, vec!["api.example.com"]);
        assert_eq!(updated.env["MODE"], "production");
        assert!(updated.env.contains_key(deploy::DO_METADATA_ENV));
        assert_eq!(updated.kv_bindings["CACHE"], "shared");
        assert_eq!(updated.crons, vec!["*/5 * * * *"]);
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
