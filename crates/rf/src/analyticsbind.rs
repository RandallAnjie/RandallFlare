//! Loopback service behind Worker Analytics Engine bindings.
//!
//! The signed dataset name is injected by workerd's external-service
//! configuration. Worker code can submit data points, but cannot redirect a
//! binding to another dataset.

use crate::analytics::DataPoint;
use crate::node::Node;
use anyhow::{bail, Context, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

pub const DATASET_HEADER: &str = "x-rf-analytics-dataset";

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/", post(write))
        .layer(DefaultBodyLimit::max(crate::analytics::MAX_WRITE_BYTES))
        .with_state(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Analytics binding server died: {error}");
        }
    });
    Ok(port)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteRequest {
    points: Vec<DataPoint>,
}

async fn write(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<WriteRequest>,
) -> Response {
    match write_inner(&node, &remote, &headers, request).await {
        Ok(written) => Json(json!({ "written": written })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

async fn write_inner(
    node: &Node,
    remote: &SocketAddr,
    headers: &HeaderMap,
    request: WriteRequest,
) -> Result<usize> {
    if !remote.ip().is_loopback() {
        bail!("Analytics binding 仅允许本机 workerd 访问");
    }
    let dataset = headers
        .get(DATASET_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("Analytics binding 缺少数据集标头")?;
    if !rf_core::manifest::valid_name(dataset) {
        bail!("Analytics binding 数据集名称无效");
    }
    crate::analytics::write(node, dataset, request.points).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_dataset_forgery() {
        assert!(
            serde_json::from_str::<WriteRequest>(r#"{"points":[],"dataset":"forged"}"#).is_err()
        );
    }
}
