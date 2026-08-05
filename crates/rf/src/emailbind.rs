//! Loopback service behind Worker outbound-email bindings.
//!
//! Workerd injects both the signed Email Domain resource name and Worker
//! identity. The adapter then verifies that the current signed manifest still
//! owns that binding before it accepts a raw RFC 822 message. User code cannot
//! choose another domain by forging JSON or ordinary request headers.

use crate::node::Node;
use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

pub const EMAIL_DOMAIN_HEADER: &str = "x-rf-email-domain";
pub const WORKER_HEADER: &str = "x-rf-worker";
pub const FROM_HEADER: &str = "x-rf-email-from";
pub const TO_HEADER: &str = "x-rf-email-to";

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/send", post(send))
        .layer(DefaultBodyLimit::max(
            crate::email::MAX_MESSAGE_BYTES as usize,
        ))
        .with_state(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Email binding server died: {error}");
        }
    });
    Ok(port)
}

async fn send(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match send_inner(&node, &remote, &headers, &body).await {
        Ok(queued) => Json(json!({ "queued": queued })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

async fn send_inner(
    node: &Node,
    remote: &SocketAddr,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Vec<crate::email::QueuedMessage>> {
    if !remote.ip().is_loopback() {
        bail!("Email binding 仅允许本机 workerd 访问");
    }
    let domain = header(headers, EMAIL_DOMAIN_HEADER, "Email binding 缺少邮件域身份")?;
    let worker = header(headers, WORKER_HEADER, "Email binding 缺少 Worker 身份")?;
    let mail_from = header(headers, FROM_HEADER, "Email binding 缺少发件地址")?;
    let recipient = header(headers, TO_HEADER, "Email binding 缺少收件地址")?;
    if !rf_core::manifest::valid_name(domain) || !rf_core::manifest::valid_name(worker) {
        bail!("Email binding 身份无效");
    }
    let manifest = node
        .manifest(worker)
        .context("Email binding Worker 不存在")?;
    if manifest.deleted
        || !crate::deploy::email_bindings(&manifest)
            .values()
            .any(|bound| bound == domain)
    {
        bail!("当前 Worker 的签名清单未授权此邮件域");
    }
    crate::email::queue_outbound(node, domain, mail_from, &[recipient.to_string()], body).await
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

    const _: () = assert!(crate::email::MAX_MESSAGE_BYTES <= 63 * 1024 * 1024);

    #[test]
    fn binding_metadata_headers_are_not_payload_fields() {
        assert_ne!(EMAIL_DOMAIN_HEADER, FROM_HEADER);
        assert_ne!(WORKER_HEADER, TO_HEADER);
    }
}
