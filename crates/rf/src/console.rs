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
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rand::RngCore;
use rf_core::identity::AnyKeypair;
use rf_core::manifest::{valid_name, WorkerManifest};
use serde::Deserialize;
use serde_json::{json, Value};
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
                "operator key is not configured; console is read-only",
            )),
            ConsoleMode::Public { .. } => Err(ApiError::forbidden(
                "public console manifests require operator approval",
            )),
        }
    }

    fn require_mutation(&self) -> ApiResult<()> {
        match &self.mode {
            ConsoleMode::Local { operator, .. } if operator.is_none() => Err(ApiError::forbidden(
                "operator key is not configured; console is read-only",
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
            ConsoleMode::Local { .. } => Err(ApiError::bad_request(
                "this endpoint is available only on a public node console",
            )),
        }
    }

    fn is_public(&self) -> bool {
        matches!(self.mode, ConsoleMode::Public { .. })
    }

    fn is_read_only(&self) -> bool {
        matches!(self.mode, ConsoleMode::Local { operator: None, .. })
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
        .with_context(|| format!("binding console at {listen}"))?;
    let addr = listener.local_addr()?;
    println!("RandallFlare Console: http://{addr}");
    println!(
        "mode: {}",
        if !state.is_read_only() {
            "operator"
        } else {
            "read-only (no operator key)"
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
        bail!("console must listen on a loopback address; use an SSH tunnel for remote access");
    }
    Ok(())
}

pub fn router(state: ConsoleState) -> Router {
    let api = Router::new()
        .route("/api/session", get(session))
        .route("/api/overview", get(overview))
        .route("/api/workers/deploy", post(worker_deploy))
        .route("/api/workers/{name}", delete(worker_delete))
        .route("/api/workers/{name}/log", get(worker_log))
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
                return ApiError::unauthorized("missing or invalid console session token")
                    .into_response();
            }
            ConsolePrincipal {
                session_id: [0; 32],
                csrf: String::new(),
            }
        }
        ConsoleMode::Public { node, .. } => {
            let Some(encoded) = cookie_value(request.headers(), SESSION_COOKIE) else {
                return ApiError::unauthorized("operator authorization required").into_response();
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
                    return ApiError::forbidden("missing or invalid CSRF token").into_response();
                }
                if !same_origin(request.headers()) {
                    return ApiError::forbidden("cross-origin management request rejected")
                        .into_response();
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
    ApiError::not_found("console route not found")
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

fn same_origin(headers: &axum::http::HeaderMap) -> bool {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .and_then(|value| value.split('/').next());
    authority == Some(host)
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
        .context("malformed console session")?;
    let envelope = rf_core::envelope::Envelope::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("malformed console session: {error}"))?;
    let grant: ConsoleGrant = envelope
        .open(Some(operator))
        .map_err(|error| anyhow::anyhow!("invalid console session: {error}"))?;
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
    headers: axum::http::HeaderMap,
) -> ApiResult<Json<Value>> {
    if !same_origin(&headers) {
        return Err(ApiError::forbidden(
            "cross-origin authentication request rejected",
        ));
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
            poll.error.unwrap_or_else(|| "authorization failed".into()),
        )),
        ApprovalState::Completed => {
            let envelope = poll
                .envelope
                .ok_or_else(|| ApiError::upstream("approved login is missing its envelope"))?;
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
                    .map_err(|_| ApiError::upstream("could not create console cookie"))?,
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
            .map_err(|_| ApiError::upstream("could not clear console cookie"))?,
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
        .ok_or_else(|| ApiError::upstream("node returned a non-object status"))?;
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
            let requested = request.path.ok_or_else(|| {
                ApiError::bad_request("local console deploy requires a worker path")
            })?;
            let path = requested.canonicalize().map_err(|error| {
                ApiError::bad_request(format!(
                    "cannot resolve worker directory {}: {error}",
                    requested.display()
                ))
            })?;
            if !path.is_dir() {
                return Err(ApiError::bad_request("worker path is not a directory"));
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
                    "upload must contain 1-{MAX_CONSOLE_FILES} files"
                )));
            }
            use base64::Engine as _;
            let mut total = 0usize;
            let mut files = Vec::with_capacity(request.files.len());
            for file in request.files {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&file.data_base64)
                    .map_err(|_| ApiError::bad_request("uploaded file is not valid base64"))?;
                total = total.saturating_add(bytes.len());
                if total > MAX_CONSOLE_UPLOAD {
                    return Err(ApiError::bad_request("Worker upload exceeds 64 MiB"));
                }
                files.push((file.path, bytes));
            }
            let bundle = deploy::read_bundle_files(files)?;
            let manifest = deploy::prepare_manifest(&bundle, &state.client, &state.node).await?;
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "Deploy Worker {} v{} ({} modules, {} assets)",
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

async fn worker_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("invalid worker name"));
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
                format!("Delete Worker {} at v{}", manifest.name, manifest.version),
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
    let poll = node.management.poll_manifest(&id, principal.session_id)?;
    Ok(Json(json!({
        "state": poll.state,
        "summary": poll.summary,
        "error": poll.error,
    })))
}

async fn worker_log(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("invalid worker name"));
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
        return Err(ApiError::bad_request("namespace must be 1-256 characters"));
    }
    if writing && namespace.starts_with("__rf") {
        return Err(ApiError::forbidden(
            "internal __rf namespaces are read-only in the console",
        ));
    }
    if let Some(key) = key {
        if key.is_empty() || key.len() > 1024 {
            return Err(ApiError::bad_request("key must be 1-1024 characters"));
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
        .ok_or_else(|| ApiError::not_found("KV key not found"))?;
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
        return Err(ApiError::bad_request(
            "console KV values are limited to 1 MiB",
        ));
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
            "database name must be [a-z0-9-]{1,63}",
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
        return Err(ApiError::bad_request("invalid database name"));
    }
    if request.sql.trim().is_empty() || request.sql.len() > MAX_CONSOLE_VALUE {
        return Err(ApiError::bad_request("SQL must be 1 byte to 1 MiB"));
    }
    if !request.params.is_array() {
        return Err(ApiError::bad_request("params must be a JSON array"));
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

    fn public_state() -> (ConsoleState, Arc<Node>, AnyKeypair) {
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
            "#,
            data_dir = data_dir.display(),
            operator = operator.signer_id(),
        ))
        .unwrap();
        let node = Arc::new(Node::open(config, Keypair::from_seed([20u8; 32])).unwrap());
        let state = ConsoleState::public(node.clone(), false).unwrap();
        (state, node, operator)
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
        assert!(body.contains("RandallFlare Console"));
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

        let (state, node, operator) = public_state();
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

        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/challenge")
                    .header(header::HOST, "console.test")
                    .header(header::ORIGIN, "http://console.test")
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
                    .header(header::ORIGIN, "http://console.test")
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
                    .header(header::ORIGIN, "http://console.test")
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
