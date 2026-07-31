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
    pub d1: crate::d1::Registry,
    secret: [u8; 32],
}

pub async fn serve(node: Arc<Node>, d1: crate::d1::Registry) -> Result<SocketAddr> {
    let secret = node.cfg.cluster_secret_bytes()?;
    let api = Api { node: node.clone(), d1, secret };
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
        .route("/v1/log/{name}", get(log_get))
        .route(
            "/v1/kv/{ns}/{*key}",
            get(kv_get).post(kv_put).delete(kv_delete),
        )
        .route("/v1/quorum/{db}", post(quorum_msg))
        .route("/v1/d1/create", post(d1_create))
        .route("/v1/d1/{db}/exec", post(d1_exec))
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
        Some(m) => {
            let digest = api.node.manifest_head(&name).map(|(_, d)| hex::encode(d));
            axum::Json(serde_json::json!({
                "name": m.name,
                "version": m.version,
                "deleted": m.deleted,
                "digest": digest,
                "prev": m.prev.map(hex::encode),
            }))
            .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no such worker").into_response(),
    }
}

/// Transparency log: the full accepted manifest history of a worker,
/// as an envelope list. Anyone with cluster access can audit the
/// hash chain offline (`rf log <worker>`).
async fn log_get(
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
    match api.node.manifest_log(&name) {
        Ok(envs) => encode_envelopes(&envs).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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

/// Raft transport between group members.
async fn quorum_msg(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(db): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, &body) {
        return r;
    }
    let Ok(wire) = postcard::from_bytes::<crate::d1::WireMsg>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad quorum message").into_response();
    };
    let tx = api.d1.lock().unwrap().get(&db).cloned();
    match tx {
        Some(tx) => {
            let _ = tx.send(crate::d1::DriverCmd::Net(wire)).await;
            StatusCode::NO_CONTENT.into_response()
        }
        None => (StatusCode::NOT_FOUND, "not a member of this db's group").into_response(),
    }
}

#[derive(serde::Deserialize)]
struct D1CreateReq {
    name: String,
}

/// Create a database: pick the replica group by rendezvous hashing
/// over live nodes (incl. us) and record it in replicated KV. The
/// managers on group members spawn drivers from there.
async fn d1_create(
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
    let Ok(req) = serde_json::from_slice::<D1CreateReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad request").into_response();
    };
    if !rf_core::manifest::valid_name(&req.name) {
        return (StatusCode::BAD_REQUEST, "db name must be [a-z0-9-]{1,63}").into_response();
    }
    let key = crate::d1::kv_key(&req.name);
    if api.node.kv_get(crate::acme::NS, &key).is_some() {
        return (StatusCode::CONFLICT, "database exists").into_response();
    }
    let mut universe: Vec<rf_core::identity::PublicId> = vec![api.node.id()];
    for (id_hex, _) in api.node.peers() {
        if let Ok(id) = id_hex.parse() {
            universe.push(id);
        }
    }
    let group = rf_core::quorum::rendezvous_group(&req.name, &universe, 3);
    let meta = crate::d1::DbMeta { group: group.clone(), created_ms: now_ms() };
    if let Err(e) =
        api.node.kv_put(crate::acme::NS, &key, Some(serde_json::to_vec(&meta).unwrap()), None)
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    axum::Json(serde_json::json!({
        "name": req.name,
        "group": group.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct D1ExecReq {
    sql: String,
    #[serde(default)]
    params: Vec<serde_json::Value>,
}

async fn d1_exec(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(db): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, &body) {
        return r;
    }
    let Ok(req) = serde_json::from_slice::<D1ExecReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad request").into_response();
    };
    let tx = api.d1.lock().unwrap().get(&db).cloned();
    let Some(tx) = tx else {
        // Not a group member: point the caller at one that is.
        if let Some(raw) = api.node.kv_get(crate::acme::NS, &crate::d1::kv_key(&db)) {
            if let Ok(meta) = serde_json::from_slice::<crate::d1::DbMeta>(&raw) {
                let peers = api.node.peers();
                let hint = meta.group.iter().find_map(|g| {
                    peers.get(&g.to_string()).and_then(|p| p.api_addr).map(|a| a.to_string())
                });
                return (
                    StatusCode::MISDIRECTED_REQUEST,
                    axum::Json(serde_json::json!({ "leader_hint": hint })).into_response(),
                )
                    .into_response();
            }
        }
        return (StatusCode::NOT_FOUND, "no such database").into_response();
    };
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    if tx
        .send(crate::d1::DriverCmd::Exec { sql: req.sql, params: req.params, resp: resp_tx })
        .await
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "driver gone").into_response();
    }
    match tokio::time::timeout(std::time::Duration::from_secs(15), resp_rx).await {
        Ok(Ok(Ok(result))) => {
            if result.leader_hint.is_some() || (result.rows.is_none() && result.rows_affected.is_none()) {
                (
                    StatusCode::MISDIRECTED_REQUEST,
                    axum::Json(serde_json::json!({ "leader_hint": result.leader_hint })),
                )
                    .into_response()
            } else {
                axum::Json(serde_json::json!({
                    "rows": result.rows,
                    "rows_affected": result.rows_affected,
                }))
                .into_response()
            }
        }
        Ok(Ok(Err(e))) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response(),
        Ok(Err(_)) => (StatusCode::SERVICE_UNAVAILABLE, "driver dropped").into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "commit timed out").into_response(),
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
