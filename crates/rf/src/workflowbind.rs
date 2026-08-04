//! Loopback service for Workflow bindings and durable step operations.
//!
//! Workerd injects signed metadata as headers. Public Worker code can create
//! and control only the Workflow named by its manifest binding; the generated
//! runtime uses a separate worker-identity header for replay-log operations.

use crate::node::Node;
use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

pub const WORKFLOW_HEADER: &str = "x-rf-workflow";
pub const WORKER_HEADER: &str = "x-rf-worker";

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/binding", post(binding))
        .route("/step", post(step))
        .layer(DefaultBodyLimit::max(
            crate::workflow::MAX_INPUT_BYTES + 1024 * 1024,
        ))
        .with_state(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Workflow binding server died: {error}");
        }
    });
    Ok(port)
}

async fn binding(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match binding_inner(&node, &remote, &headers, &body).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum BindingRequest {
    Create {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        params: Value,
    },
    Status {
        id: String,
    },
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
    Terminate {
        id: String,
    },
    Restart {
        id: String,
    },
    SendEvent {
        id: String,
        event_type: String,
        #[serde(default)]
        payload: Value,
    },
}

async fn binding_inner(
    node: &Node,
    remote: &SocketAddr,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Value> {
    loopback(remote)?;
    let workflow = header(
        headers,
        WORKFLOW_HEADER,
        "Workflow binding 缺少 Workflow 标头",
    )?;
    if !rf_core::manifest::valid_name(workflow) {
        bail!("Workflow binding 名称无效");
    }
    crate::workflow::workflow_record(node, workflow)
        .context("Workflow binding 指向不存在的资源")?;
    let request: BindingRequest =
        serde_json::from_slice(body).context("Workflow binding 请求无效")?;
    match request {
        BindingRequest::Create { id, params } => {
            let instance =
                crate::workflow::create_instance(node, workflow, id.as_deref(), params).await?;
            Ok(json!({ "id": instance.id, "status": instance.status }))
        }
        BindingRequest::Status { id } => {
            let instance = crate::workflow::instance(node, workflow, &id)
                .await?
                .context("Workflow 实例不存在")?;
            Ok(json!({
                "id": instance.id,
                "status": instance.status,
                "error": instance.last_error,
                "output": instance.output,
                "queuedAt": instance.started_at_ms,
                "modifiedAt": instance.updated_at_ms,
            }))
        }
        BindingRequest::Pause { id } => {
            action_result(crate::workflow::pause(node, workflow, &id).await?)
        }
        BindingRequest::Resume { id } => {
            action_result(crate::workflow::resume(node, workflow, &id).await?)
        }
        BindingRequest::Terminate { id } => {
            action_result(crate::workflow::terminate(node, workflow, &id).await?)
        }
        BindingRequest::Restart { id } => {
            action_result(crate::workflow::restart(node, workflow, &id).await?)
        }
        BindingRequest::SendEvent {
            id,
            event_type,
            payload,
        } => {
            let signal_id =
                crate::workflow::send_signal(node, workflow, &id, &event_type, payload).await?;
            Ok(json!({ "ok": true, "signalId": signal_id }))
        }
    }
}

fn action_result(changed: bool) -> Result<Value> {
    if !changed {
        bail!("Workflow 实例不存在或当前状态不允许此操作");
    }
    Ok(json!({ "ok": true }))
}

async fn step(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match step_inner(&node, &remote, &headers, &body).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum StepRequest {
    Lookup {
        workflow: String,
        instance_id: String,
        lease: String,
        name: String,
    },
    Record {
        workflow: String,
        instance_id: String,
        lease: String,
        name: String,
        status: String,
        #[serde(default)]
        result: Option<Value>,
        #[serde(default)]
        error: Option<String>,
        #[serde(default = "one")]
        attempts: u16,
    },
    Sleep {
        workflow: String,
        instance_id: String,
        lease: String,
        name: String,
        duration_ms: u64,
    },
    Signal {
        workflow: String,
        instance_id: String,
        lease: String,
        name: String,
    },
}

fn one() -> u16 {
    1
}

async fn step_inner(
    node: &Node,
    remote: &SocketAddr,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Value> {
    loopback(remote)?;
    let worker = header(headers, WORKER_HEADER, "Workflow 步骤请求缺少 Worker 身份")?;
    if !rf_core::manifest::valid_name(worker) {
        bail!("Workflow 步骤 Worker 身份无效");
    }
    let request: StepRequest = serde_json::from_slice(body).context("Workflow 步骤请求无效")?;
    let workflow = match &request {
        StepRequest::Lookup { workflow, .. }
        | StepRequest::Record { workflow, .. }
        | StepRequest::Sleep { workflow, .. }
        | StepRequest::Signal { workflow, .. } => workflow,
    };
    let (_, spec) = crate::workflow::workflow_record(node, workflow).context("Workflow 不存在")?;
    if spec.worker != worker {
        bail!("当前 Worker 不是此 Workflow 的签名执行入口");
    }
    match request {
        StepRequest::Lookup {
            workflow,
            instance_id,
            lease,
            name,
        } => crate::workflow::step_lookup(node, &workflow, &instance_id, &lease, &name).await,
        StepRequest::Record {
            workflow,
            instance_id,
            lease,
            name,
            status,
            result,
            error,
            attempts,
        } => {
            crate::workflow::step_record(
                node,
                &workflow,
                &instance_id,
                &lease,
                &name,
                crate::workflow::StepOutcome {
                    status: &status,
                    result,
                    error: error.as_deref(),
                    attempts,
                },
            )
            .await?;
            Ok(json!({ "ok": true }))
        }
        StepRequest::Sleep {
            workflow,
            instance_id,
            lease,
            name,
            duration_ms,
        } => {
            crate::workflow::step_sleep(node, &workflow, &instance_id, &lease, &name, duration_ms)
                .await
        }
        StepRequest::Signal {
            workflow,
            instance_id,
            lease,
            name,
        } => crate::workflow::step_signal(node, &workflow, &instance_id, &lease, &name).await,
    }
}

fn loopback(remote: &SocketAddr) -> Result<()> {
    if !remote.ip().is_loopback() {
        bail!("Workflow binding 仅允许本机 workerd 访问");
    }
    Ok(())
}

fn header<'a>(headers: &'a HeaderMap, name: &str, missing: &str) -> Result<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .context(missing.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_and_step_requests_reject_identity_forgery() {
        assert!(serde_json::from_str::<BindingRequest>(
            r#"{"op":"status","id":"x","workflow":"forged"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<StepRequest>(
            r#"{"op":"lookup","workflow":"w","instance_id":"i","lease":"l","name":"n","worker":"forged"}"#
        )
        .is_err());
    }
}
