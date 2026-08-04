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
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

pub const NS_HEADER: &str = "x-rf-kv-ns";
const METADATA_HEADER: &str = "cf-kv-metadata";
const MAX_METADATA_BYTES: usize = 1024;

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
        .route("/bulk/get", axum::routing::post(bulk_get))
        .route("/{*key}", get(kget).put(kput).delete(kdelete))
        .layer(DefaultBodyLimit::max(25 * 1024 * 1024))
        .with_state(node)
}

fn ns_of(
    headers: &HeaderMap,
    remote: &SocketAddr,
) -> std::result::Result<String, (StatusCode, &'static str)> {
    if !remote.ip().is_loopback() {
        return Err((StatusCode::FORBIDDEN, "loopback only"));
    }
    headers
        .get(NS_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or((StatusCode::BAD_REQUEST, "missing kv namespace header"))
}

#[derive(Deserialize)]
struct PutQuery {
    expiration_ttl: Option<u64>,
    expiration: Option<u64>,
}

#[derive(Deserialize)]
struct ListQuery {
    prefix: Option<String>,
    #[serde(alias = "key_count_limit")]
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
        Err(r) => return r.into_response(),
    };
    match node.kv_get_with_metadata(&ns, &key) {
        Some((value, metadata)) => {
            let mut response = value.into_response();
            if let Some(metadata) = metadata {
                if let Ok(value) = HeaderValue::from_bytes(&metadata) {
                    response.headers_mut().insert(METADATA_HEADER, value);
                }
            }
            response
        }
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
        Err(r) => return r.into_response(),
    };
    let expires_at_ms = q
        .expiration
        .map(|secs| secs * 1000)
        .or_else(|| q.expiration_ttl.map(|ttl| now_ms() + ttl * 1000));
    if q.expiration_ttl.is_some_and(|ttl| ttl < 60)
        || q.expiration
            .is_some_and(|expiration| expiration.saturating_mul(1000) < now_ms() + 60_000)
    {
        return (
            StatusCode::BAD_REQUEST,
            "KV expiration must be at least 60 seconds",
        )
            .into_response();
    }
    let metadata = match headers.get(METADATA_HEADER) {
        Some(value) if value.as_bytes().len() > MAX_METADATA_BYTES => {
            return (StatusCode::BAD_REQUEST, "KV metadata exceeds 1024 bytes").into_response();
        }
        Some(value) => match serde_json::from_slice::<serde_json::Value>(value.as_bytes()) {
            Ok(metadata) => Some(serde_json::to_vec(&metadata).expect("JSON re-encodes")),
            Err(_) => return (StatusCode::BAD_REQUEST, "KV metadata is not JSON").into_response(),
        },
        None => None,
    };
    match node.kv_put_with_metadata(&ns, &key, Some(body.to_vec()), expires_at_ms, metadata) {
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
        Err(r) => return r.into_response(),
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
        Err(r) => return r.into_response(),
    };
    let limit = q.limit.unwrap_or(1000).clamp(1, 1000);
    let (keys, complete, cursor) = node.kv_list_page_with_metadata(
        &ns,
        q.prefix.as_deref().unwrap_or(""),
        limit,
        q.cursor.as_deref(),
    );
    let keys_json: Vec<serde_json::Value> = keys
        .into_iter()
        .map(|(name, expiration_ms, metadata)| {
            let mut key = serde_json::json!({"name": name});
            if let Some(ms) = expiration_ms {
                key["expiration"] = serde_json::json!(ms / 1000);
            }
            if let Some(metadata) = metadata {
                // workerd deliberately expects this field to contain a JSON
                // string and parses it into the public metadata value.
                key["metadata"] = serde_json::Value::String(
                    String::from_utf8(metadata).unwrap_or_else(|_| "null".into()),
                );
            }
            key
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkGetRequest {
    keys: Vec<String>,
    #[serde(default)]
    with_metadata: bool,
    #[serde(default)]
    r#type: String,
}

async fn bulk_get(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<BulkGetRequest>,
) -> Response {
    let ns = match ns_of(&headers, &remote) {
        Ok(ns) => ns,
        Err(response) => return response.into_response(),
    };
    if request.keys.is_empty() || request.keys.len() > 100 {
        return (StatusCode::BAD_REQUEST, "KV bulk get accepts 1..100 keys").into_response();
    }
    let mut output = serde_json::Map::new();
    for key in request.keys {
        let Some((bytes, metadata)) = node.kv_get_with_metadata(&ns, &key) else {
            output.insert(key, serde_json::Value::Null);
            continue;
        };
        let value = match request.r#type.as_str() {
            "json" => match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(_) => return (StatusCode::BAD_GATEWAY, "KV value is not JSON").into_response(),
            },
            "" | "text" => match String::from_utf8(bytes) {
                Ok(value) => serde_json::Value::String(value),
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "KV value is not UTF-8").into_response()
                }
            },
            _ => {
                return (StatusCode::BAD_REQUEST, "unsupported KV bulk value type").into_response()
            }
        };
        if request.with_metadata {
            let metadata = metadata
                .as_deref()
                .and_then(|value| serde_json::from_slice(value).ok())
                .unwrap_or(serde_json::Value::Null);
            output.insert(
                key,
                serde_json::json!({ "value": value, "metadata": metadata }),
            );
        } else {
            output.insert(key, value);
        }
    }
    axum::Json(output).into_response()
}
