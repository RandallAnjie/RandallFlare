//! Loopback service behind Worker Pipeline producer bindings.

use crate::node::Node;
use anyhow::{bail, Context, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

pub const PIPELINE_HEADER: &str = "x-rf-pipeline";

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/", post(send))
        .layer(DefaultBodyLimit::max(
            crate::pipeline::MAX_INGEST_BYTES + 1024 * 1024,
        ))
        .with_state(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Pipeline binding server died: {error}");
        }
    });
    Ok(port)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
    events: Vec<Value>,
}

async fn send(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SendRequest>,
) -> Response {
    match send_inner(&node, &remote, &headers, request).await {
        Ok(accepted) => Json(json!({ "accepted": accepted })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

async fn send_inner(
    node: &Node,
    remote: &SocketAddr,
    headers: &HeaderMap,
    request: SendRequest,
) -> Result<usize> {
    if !remote.ip().is_loopback() {
        bail!("Pipeline binding 仅允许本机 workerd 访问");
    }
    let pipeline = headers
        .get(PIPELINE_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("Pipeline binding 缺少 Pipeline 标头")?;
    if !rf_core::manifest::valid_name(pipeline) {
        bail!("Pipeline binding 名称无效");
    }
    crate::pipeline::ingest(node, pipeline, request.events).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_pipeline_forgery() {
        assert!(
            serde_json::from_str::<SendRequest>(r#"{"events":[],"pipeline":"forged"}"#).is_err()
        );
    }
}
