//! The workerd KV-binding backend: a dedicated loopback listener
//! speaking the wire protocol workerd's `kvNamespace` binding emits
//! (observed against workerd 2026-07-31):
//!
//!   GET    /<key>?urlencoded=true          → 200 body | 404 (null)
//!   PUT    /<key>?urlencoded=true[&expiration_ttl=s|&expiration=s]
//!   DELETE /<key>?urlencoded=true
//!   GET    /?prefix=&limit=&cursor=        → {"keys":[{"name",...}],
//!                                             "list_complete","cursor"}
//!
//! The namespace arrives via an injected header (x-rf-kv-ns) that the
//! generated workerd config attaches per binding. Loopback-only: the
//! only client is workerd on this host.

use crate::node::{now_ms, Node};
use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

pub const NS_HEADER: &str = "x-rf-kv-ns";

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let app = router(node);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("kvbind server died: {e}");
        }
    });
    Ok(port)
}

pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/{*key}", get(kget).put(kput).delete(kdelete))
        .with_state(node)
}

fn ns_of(headers: &HeaderMap, remote: &SocketAddr) -> Result<String, Response> {
    if !remote.ip().is_loopback() {
        return Err((StatusCode::FORBIDDEN, "loopback only").into_response());
    }
    headers
        .get(NS_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing kv namespace header").into_response())
}

#[derive(Deserialize)]
struct PutQuery {
    expiration_ttl: Option<u64>,
    expiration: Option<u64>,
}

#[derive(Deserialize)]
struct ListQuery {
    prefix: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn kget(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ns = match ns_of(&headers, &remote) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    match node.kv_get(&ns, &key) {
        Some(v) => v.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn kput(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
    Query(q): Query<PutQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ns = match ns_of(&headers, &remote) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let expires_at_ms = q
        .expiration
        .map(|secs| secs * 1000)
        .or_else(|| q.expiration_ttl.map(|ttl| now_ms() + ttl * 1000));
    match node.kv_put(&ns, &key, Some(body.to_vec()), expires_at_ms) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn kdelete(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ns = match ns_of(&headers, &remote) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    match node.kv_put(&ns, &key, None, None) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Query(q): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let ns = match ns_of(&headers, &remote) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let limit = q.limit.unwrap_or(1000).clamp(1, 1000);
    let (keys, complete, cursor) = node.kv_list_page(
        &ns,
        q.prefix.as_deref().unwrap_or(""),
        limit,
        q.cursor.as_deref(),
    );
    let keys_json: Vec<serde_json::Value> = keys
        .into_iter()
        .map(|(name, expiration_ms)| match expiration_ms {
            Some(ms) => serde_json::json!({"name": name, "expiration": ms / 1000}),
            None => serde_json::json!({"name": name}),
        })
        .collect();
    let mut body = serde_json::json!({
        "keys": keys_json,
        "list_complete": complete,
    });
    if let Some(c) = cursor {
        body["cursor"] = serde_json::Value::String(c);
    }
    axum::Json(body).into_response()
}
