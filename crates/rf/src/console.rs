//! Local operator console. The browser never receives the cluster
//! secret or operator private key: it talks to this loopback-only
//! process, which uses the same encrypted PeerClient as the CLI.

use crate::deploy;
use crate::peers::PeerClient;
use anyhow::{bail, Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, Request, StatusCode};
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
const MAX_CONSOLE_VALUE: usize = 1024 * 1024;

#[derive(Clone)]
pub struct ConsoleState {
    node: Arc<str>,
    client: PeerClient,
    operator: Option<AnyKeypair>,
    token: Arc<str>,
    started: Instant,
}

impl ConsoleState {
    pub fn new(node: String, secret: [u8; 32], operator: Option<AnyKeypair>) -> Self {
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        Self {
            node: node.into(),
            client: PeerClient::new(secret),
            operator,
            token: hex::encode(token).into(),
            started: Instant::now(),
        }
    }

    fn operator(&self) -> ApiResult<&AnyKeypair> {
        self.operator.as_ref().ok_or_else(|| {
            ApiError::forbidden("operator key is not configured; console is read-only")
        })
    }
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
        if state.operator.is_some() {
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
        .route("/api/kv", get(kv_list))
        .route("/api/kv/value", get(kv_get).put(kv_put).delete(kv_delete))
        .route("/api/d1/create", post(d1_create))
        .route("/api/d1/exec", post(d1_exec))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .merge(api)
        .fallback(not_found)
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
}

async fn require_token(
    State(state): State<ConsoleState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let supplied = request
        .headers()
        .get(TOKEN_HEADER)
        .and_then(|value| value.to_str().ok());
    if supplied != Some(state.token.as_ref()) {
        return ApiError::unauthorized("missing or invalid console session token").into_response();
    }
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
    Html(INDEX_HTML.replace("__RF_TOKEN__", state.token.as_ref()))
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

async fn session(State(state): State<ConsoleState>) -> Json<Value> {
    Json(json!({
        "product": "RandallFlare",
        "version": env!("CARGO_PKG_VERSION"),
        "node": state.node.as_ref(),
        "operator": state.operator.as_ref().map(|key| key.signer_id().to_string()),
        "read_only": state.operator.is_none(),
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
            "operator": state.operator.as_ref().map(|key| key.signer_id().to_string()),
            "read_only": state.operator.is_none(),
            "uptime_seconds": state.started.elapsed().as_secs(),
        }),
    );
    Ok(Json(value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployRequest {
    path: PathBuf,
}

async fn worker_deploy(
    State(state): State<ConsoleState>,
    Json(request): Json<DeployRequest>,
) -> ApiResult<Json<Value>> {
    let operator = state.operator()?.clone();
    let path = request.path.canonicalize().map_err(|error| {
        ApiError::bad_request(format!(
            "cannot resolve worker directory {}: {error}",
            request.path.display()
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

async fn worker_delete(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("invalid worker name"));
    }
    let version =
        deploy::delete_worker(&name, &state.client, &state.node, state.operator()?).await?;
    Ok(Json(
        json!({ "ok": true, "name": name, "version": version }),
    ))
}

async fn worker_log(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("invalid worker name"));
    }
    let envelopes = state.client.worker_log(&state.node, &name).await?;
    let signer = envelopes.first().map(|env| env.signer);
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
    state.operator()?;
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
    state.operator()?;
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
    state.operator()?;
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
    state.operator()?;
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
        assert!(body.contains(state.token.as_ref()));
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
                    .header(TOKEN_HEADER, state.token.as_ref())
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
                    .header(TOKEN_HEADER, state.token.as_ref())
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
                    .header(TOKEN_HEADER, state.token.as_ref())
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
}
