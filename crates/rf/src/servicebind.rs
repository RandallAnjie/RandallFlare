//! Loopback dynamic proxy behind Worker-to-Worker service bindings.
//!
//! A workerd external service injects the signed source Worker and target
//! Worker names. The adapter re-checks the current manifest before resolving
//! the target's local runtime port. This keeps service bindings stable across
//! target restarts without exposing arbitrary loopback access to user code.

use crate::node::Node;
use anyhow::{bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;

pub const SOURCE_HEADER: &str = "x-rf-service-source";
pub const TARGET_HEADER: &str = "x-rf-service-target";
pub const MAX_SERVICE_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct ServiceState {
    node: Arc<Node>,
    client: reqwest::Client,
}

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let state = ServiceState {
        node,
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?,
    };
    let app = Router::new()
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_SERVICE_BODY_BYTES))
        .with_state(state);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Service binding server died: {error}");
        }
    });
    Ok(port)
}

async fn proxy(
    State(state): State<ServiceState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match proxy_inner(&state, &remote, method, uri, headers, body).await {
        Ok(response) => response,
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

async fn proxy_inner(
    state: &ServiceState,
    remote: &SocketAddr,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    if !remote.ip().is_loopback() {
        bail!("Service binding 仅允许本机 workerd 访问");
    }
    let source = header(&headers, SOURCE_HEADER, "Service binding 缺少来源 Worker")?;
    let target = header(&headers, TARGET_HEADER, "Service binding 缺少目标 Worker")?;
    if !rf_core::manifest::valid_name(source)
        || !rf_core::manifest::valid_name(target)
        || source == target
    {
        bail!("Service binding Worker 身份无效");
    }
    let source_manifest = state
        .node
        .manifest(source)
        .context("Service binding 来源 Worker 不存在")?;
    if !crate::deploy::service_bindings(&source_manifest)
        .values()
        .any(|bound| bound == target)
    {
        bail!("当前签名清单未授权此 Service binding 目标");
    }
    state
        .node
        .manifest(target)
        .filter(|manifest| !manifest.deleted && !manifest.main.is_empty())
        .context("Service binding 目标不存在或不是模块 Worker")?;
    let port = state
        .node
        .worker_port(target)
        .context("Service binding 目标当前未在此节点运行")?;
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let method = reqwest::Method::from_bytes(method.as_str().as_bytes())?;
    let mut request = state
        .client
        .request(method, format!("http://127.0.0.1:{port}{path}"))
        .body(body.to_vec());
    for (name, value) in &headers {
        if matches!(name.as_str(), SOURCE_HEADER | TARGET_HEADER)
            || super::ingress::is_hop_header(name.as_str())
        {
            continue;
        }
        request = request.header(name.as_str(), value.as_bytes());
    }
    let upstream = request.send().await?;
    let status = StatusCode::from_u16(upstream.status().as_u16())?;
    let mut response = Response::builder().status(status);
    for (name, value) in upstream.headers() {
        if !super::ingress::is_hop_header(name.as_str()) {
            response = response.header(name.as_str(), value.as_bytes());
        }
    }
    Ok(response
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()))
}

fn header<'a>(headers: &'a HeaderMap, name: &str, missing: &str) -> Result<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .with_context(|| missing.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_headers_are_distinct_and_body_is_bounded() {
        assert_ne!(SOURCE_HEADER, TARGET_HEADER);
        const { assert!(MAX_SERVICE_BODY_BYTES <= 64 * 1024 * 1024) };
    }
}
