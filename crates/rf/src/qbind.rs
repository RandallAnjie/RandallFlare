//! Loopback producer service behind Worker Queue bindings.
//!
//! The generated Worker facade sends JSON to this listener. The signed queue
//! name is injected by workerd's external-service configuration, so user code
//! cannot redirect a binding to a different queue at request time.

use crate::node::Node;
use crate::queue::SendMessage;
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

pub const QUEUE_HEADER: &str = "x-rf-queue";

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/", post(send))
        .layer(DefaultBodyLimit::max(
            crate::queue::MAX_MESSAGE_BYTES * crate::queue::MAX_BATCH_MESSAGES + 1024 * 1024,
        ))
        .with_state(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("queue binding server died: {error}");
        }
    });
    Ok(port)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
    messages: Vec<SendMessage>,
}

async fn send(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SendRequest>,
) -> Response {
    match send_inner(&node, &remote, &headers, request).await {
        Ok(ids) => Json(json!({ "message_ids": ids })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

async fn send_inner(
    node: &Node,
    remote: &SocketAddr,
    headers: &HeaderMap,
    request: SendRequest,
) -> Result<Vec<String>> {
    if !remote.ip().is_loopback() {
        bail!("Queue binding 仅允许本机 workerd 访问");
    }
    let queue = headers
        .get(QUEUE_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("Queue binding 缺少队列标头")?;
    if !rf_core::manifest::valid_name(queue) {
        bail!("Queue binding 队列名称无效");
    }
    crate::queue::enqueue(node, queue, request.messages).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<SendRequest>(r#"{"messages":[],"queue":"forged"}"#).is_err()
        );
    }
}
