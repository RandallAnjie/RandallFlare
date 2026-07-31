//! The peer API: one HTTP surface serving three callers — peer nodes
//! (anti-entropy sync, blob fetch), the operator CLI (deploy, kv,
//! status) and local workerd processes (KV bindings, loopback only).

use crate::auth;
use crate::node::{now_ms, Node};
use crate::peers::encode_envelopes;
use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use rf_core::envelope::Envelope;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct Api {
    pub node: Arc<Node>,
    secret: [u8; 32],
}

pub async fn serve(node: Arc<Node>) -> Result<SocketAddr> {
    let secret = node.cfg.cluster_secret_bytes()?;
    let api = Api { node: node.clone(), secret };
    let app = router(api);
    let listener = tokio::net::TcpListener::bind(node.cfg.peer_api.listen).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("peer api server died: {e}");
        }
    });
    Ok(addr)
}

pub fn router(api: Api) -> Router {
    Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/status", get(status))
        .route("/v1/sync/manifests", get(sync_manifests))
        .route("/v1/sync/claims", get(sync_claims))
        .route("/v1/sync/kv", get(sync_kv_digests))
        .route("/v1/sync/kv/{ns}", get(sync_kv_dump))
        .route("/v1/blob/{sha}", get(blob_get))
        .route("/v1/blob", post(blob_put))
        .route("/v1/manifest", post(manifest_post))
        .route("/v1/worker/{name}", get(worker_get))
        .route(
            "/v1/kv/{ns}/{*key}",
            get(kv_get).post(kv_put).delete(kv_delete),
        )
        .with_state(api)
}

/// Auth gate. Loopback (workerd bindings, same-host CLI) is trusted;
/// everything else needs the cluster MAC over (ts, method, path, body).
fn check(
    api: &Api,
    remote: &SocketAddr,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<(), Response> {
    if remote.ip().is_loopback() {
        return Ok(());
    }
    let ts = headers.get(auth::TS_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    let mac = headers.get(auth::MAC_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    if auth::verify(&api.secret, now_ms(), ts, mac, method.as_str(), uri.path(), body) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "bad or missing cluster MAC").into_response())
    }
}

async fn ping() -> &'static str {
    "rf\n"
}

async fn status(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    let node = &api.node;
    let peers: Vec<serde_json::Value> = node
        .peers()
        .into_iter()
        .map(|(id, v)| {
            serde_json::json!({
                "id": id,
                "label": v.label,
                "public": v.public,
                "api": v.api_addr.map(|a| a.to_string()),
                "ip4": v.ipv4,
            })
        })
        .collect();
    let workers: Vec<serde_json::Value> = node
        .live_manifests()
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "version": m.version,
                "hostnames": m.hostnames,
                "modules": m.modules.len(),
                "assets": m.assets.len(),
                "crons": m.crons,
            })
        })
        .collect();
    axum::Json(serde_json::json!({
        "node": node.id_hex(),
        "label": node.cfg.label,
        "public": node.cfg.public,
        "version": env!("CARGO_PKG_VERSION"),
        "peers": peers,
        "workers": workers,
        "missing_blobs": node.missing_blobs().len(),
    }))
    .into_response()
}

async fn sync_manifests(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    encode_envelopes(&api.node.manifest_envelopes()).into_response()
}

async fn sync_claims(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    encode_envelopes(&api.node.claim_envelopes()).into_response()
}

async fn sync_kv_digests(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    axum::Json(api.node.kv_digests()).into_response()
}

async fn sync_kv_dump(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(ns): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    let dump = api.node.kv_dump(&ns);
    postcard::to_stdvec(&dump).map(|b| b.into_response()).unwrap_or_else(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    })
}

async fn blob_get(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(sha_hex): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    let Ok(sha_bytes) = hex::decode(&sha_hex) else {
        return (StatusCode::BAD_REQUEST, "bad sha").into_response();
    };
    let Ok(sha): Result<[u8; 32], _> = sha_bytes.try_into() else {
        return (StatusCode::BAD_REQUEST, "bad sha length").into_response();
    };
    match api.node.blobs.get(&sha) {
        Ok(bytes) => bytes.into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "no such blob").into_response(),
    }
}

async fn blob_put(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, &body) {
        return r;
    }
    match api.node.blobs.put(&body) {
        Ok(sha) => hex::encode(sha).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn manifest_post(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, &body) {
        return r;
    }
    let Ok(env) = Envelope::from_bytes(&body) else {
        return (StatusCode::BAD_REQUEST, "bad envelope").into_response();
    };
    match api.node.ingest_manifest(&env) {
        Ok(changed) => axum::Json(serde_json::json!({ "changed": changed })).into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response(),
    }
}

async fn worker_get(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    match api.node.manifest(&name) {
        Some(m) => axum::Json(serde_json::json!({
            "name": m.name,
            "version": m.version,
            "deleted": m.deleted,
        }))
        .into_response(),
        None => (StatusCode::NOT_FOUND, "no such worker").into_response(),
    }
}

#[derive(Deserialize)]
struct KvPutQuery {
    expires_at_ms: Option<u64>,
    ttl_ms: Option<u64>,
}

async fn kv_get(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((ns, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    match api.node.kv_get(&ns, &key) {
        Some(v) => v.into_response(),
        None => (StatusCode::NOT_FOUND, "no such key").into_response(),
    }
}

async fn kv_put(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((ns, key)): Path<(String, String)>,
    Query(q): Query<KvPutQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, &body) {
        return r;
    }
    let expires = q.expires_at_ms.or_else(|| q.ttl_ms.map(|t| now_ms() + t));
    match api.node.kv_put(&ns, &key, Some(body.to_vec()), expires) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn kv_delete(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((ns, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r;
    }
    match api.node.kv_put(&ns, &key, None, None) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
