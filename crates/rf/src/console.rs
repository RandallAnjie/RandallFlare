//! RandallFlare management console.
//!
//! Local mode keeps the original loopback token + optional in-process
//! operator key. Public-node mode is mounted as the default ingress and uses
//! operator-signed, stateless [`crate::management::ConsoleGrant`] cookies.
//! Every node verifies those grants independently; no central identity
//! service, cluster secret, or operator private key reaches the browser.

use crate::deploy;
use crate::management::{ApprovalState, ConsoleGrant};
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};
use axum::{Json, Router};
use futures_util::StreamExt;
use rand::RngCore;
use rf_core::identity::AnyKeypair;
use rf_core::manifest::{valid_name, AssetFile, ManifestError, Module, WorkerManifest};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroize;

const INDEX_HTML: &str = include_str!("console/index.html");
const APP_JS: &str = include_str!("console/app.js");
const STYLES_CSS: &str = include_str!("console/styles.css");
const TOKEN_HEADER: &str = "x-rf-console-token";
const CSRF_HEADER: &str = "x-rf-csrf";
const SESSION_COOKIE: &str = "rf_console_session";
const MAX_CONSOLE_VALUE: usize = 1024 * 1024;
const MAX_CONSOLE_UPLOAD: usize = crate::binary::MAX_BINARY_BYTES;
const MAX_CONSOLE_FILES: usize = 2048;
const MAX_EDITOR_CHANGES: usize = 256;
const MAX_EDITOR_FILE: usize = 25 * 1024 * 1024;
const MAX_EDITOR_READ: usize = 5 * 1024 * 1024;
const MAX_KV_VALUE: usize = 25 * 1024 * 1024;
const MAX_KV_TRANSFER: usize = 64 * 1024 * 1024;
const MAX_KV_TRANSFER_ENTRIES: usize = 10_000;
const MAX_D1_IMPORT: usize = 64 * 1024 * 1024;
const MAX_D1_IMPORT_STATEMENTS: usize = 10_000;

#[derive(Clone)]
enum ConsoleMode {
    Local {
        operator: Option<Arc<AnyKeypair>>,
        token: Arc<str>,
    },
    Public {
        node: Arc<Node>,
        secure_cookies: bool,
    },
}

#[derive(Clone)]
pub struct ConsoleState {
    node: Arc<str>,
    client: PeerClient,
    secret: [u8; 32],
    mode: ConsoleMode,
    started: Instant,
}

impl ConsoleState {
    pub fn new(node: String, secret: [u8; 32], operator: Option<AnyKeypair>) -> Self {
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        Self {
            node: node.into(),
            client: PeerClient::new(secret),
            secret,
            mode: ConsoleMode::Local {
                operator: operator.map(Arc::new),
                token: hex::encode(token).into(),
            },
            started: Instant::now(),
        }
    }

    pub fn public(node: Arc<Node>, secure_cookies: bool) -> Result<Self> {
        let peer = format!("127.0.0.1:{}", node.cfg.peer_api.listen.port());
        let secret = node.cfg.cluster_secret_bytes()?;
        Ok(Self {
            node: peer.into(),
            client: PeerClient::new(secret),
            secret,
            mode: ConsoleMode::Public {
                node,
                secure_cookies,
            },
            started: Instant::now(),
        })
    }

    fn operator(&self) -> ApiResult<&AnyKeypair> {
        match &self.mode {
            ConsoleMode::Local {
                operator: Some(operator),
                ..
            } => Ok(operator),
            ConsoleMode::Local { operator: None, .. } => Err(ApiError::forbidden(
                "尚未配置管理员密钥；控制台当前为只读模式",
            )),
            ConsoleMode::Public { .. } => Err(ApiError::forbidden(
                "公共控制台提交的部署清单需要管理员批准",
            )),
        }
    }

    fn require_mutation(&self) -> ApiResult<()> {
        match &self.mode {
            ConsoleMode::Local { operator, .. } if operator.is_none() => Err(ApiError::forbidden(
                "尚未配置管理员密钥；控制台当前为只读模式",
            )),
            _ => Ok(()),
        }
    }

    fn operator_id(&self) -> Option<rf_core::identity::SignerId> {
        match &self.mode {
            ConsoleMode::Local {
                operator: Some(operator),
                ..
            } => Some(operator.signer_id()),
            ConsoleMode::Local { operator: None, .. } => None,
            ConsoleMode::Public { node, .. } => Some(node.cfg.operator),
        }
    }

    fn public_node(&self) -> ApiResult<&Arc<Node>> {
        match &self.mode {
            ConsoleMode::Public { node, .. } => Ok(node),
            ConsoleMode::Local { .. } => Err(ApiError::bad_request("此接口仅供公共节点控制台使用")),
        }
    }

    fn is_public(&self) -> bool {
        matches!(self.mode, ConsoleMode::Public { .. })
    }

    fn is_read_only(&self) -> bool {
        matches!(self.mode, ConsoleMode::Local { operator: None, .. })
    }

    fn allows_secret_writes(&self) -> bool {
        matches!(
            self.mode,
            ConsoleMode::Local { .. }
                | ConsoleMode::Public {
                    secure_cookies: true,
                    ..
                }
        )
    }

    fn origin_scheme(&self) -> &'static str {
        match &self.mode {
            ConsoleMode::Public {
                secure_cookies: true,
                ..
            } => "https",
            ConsoleMode::Local { .. } | ConsoleMode::Public { .. } => "http",
        }
    }

    #[cfg(test)]
    fn local_token(&self) -> &str {
        match &self.mode {
            ConsoleMode::Local { token, .. } => token,
            ConsoleMode::Public { .. } => panic!("public console has no local token"),
        }
    }
}

#[derive(Debug, Clone)]
struct ConsolePrincipal {
    session_id: [u8; 32],
    csrf: String,
}

pub async fn serve(
    listen: SocketAddr,
    node: String,
    secret: [u8; 32],
    operator: Option<AnyKeypair>,
) -> Result<()> {
    validate_listen(listen)?;
    let state = ConsoleState::new(node, secret, operator);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("在 {listen} 监听控制台"))?;
    let addr = listener.local_addr()?;
    println!("RandallFlare 管理控制台：http://{addr}");
    println!(
        "模式：{}",
        if !state.is_read_only() {
            "管理员"
        } else {
            "只读（未配置管理员密钥）"
        }
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn validate_listen(listen: SocketAddr) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("控制台只能监听回环地址；如需远程访问，请使用 SSH 隧道");
    }
    Ok(())
}

pub fn router(state: ConsoleState) -> Router {
    let token_api = Router::new()
        .route("/api/v1", get(public_api_discovery))
        .route("/api/v1/status", get(public_api_status))
        .route("/api/v1/workers", get(public_api_workers))
        .route(
            "/api/v1/workers/{name}",
            get(public_api_worker).post(public_api_worker_submit),
        )
        .route(
            "/api/v1/resources",
            get(public_api_resources).post(public_api_resource_submit),
        )
        .route("/api/v1/resources/{kind}/{name}", get(public_api_resource))
        .route("/api/v1/audit", get(public_api_audit))
        .route("/api/v1/kv/{namespace}", get(public_api_kv_list))
        .route(
            "/api/v1/kv/{namespace}/{*key}",
            get(public_api_kv_get)
                .put(public_api_kv_put)
                .delete(public_api_kv_delete),
        )
        .route("/api/v1/r2", get(public_api_r2_buckets))
        .route("/api/v1/r2/{bucket}", get(public_api_r2_list))
        .route(
            "/api/v1/r2/{bucket}/{*key}",
            get(public_api_r2_get)
                .put(public_api_r2_put)
                .delete(public_api_r2_delete),
        )
        .route("/api/v1/binaries/blob", post(public_api_binary_blob))
        .route("/api/v1/d1", get(public_api_d1_list))
        .route("/api/v1/d1/{database}/query", post(public_api_d1_query))
        .route("/api/v1/d1/{database}/exec", post(public_api_d1_exec))
        .route("/api/v1/d1/{database}/batch", post(public_api_d1_batch))
        .route("/api/v1/queues", get(public_api_queues))
        .route(
            "/api/v1/queues/{queue}",
            get(public_api_queue_status).post(public_api_queue_send),
        )
        .route("/api/v1/queues/{queue}/dead", get(public_api_queue_dead))
        .route(
            "/api/v1/queues/{queue}/dead/{id}/redrive",
            post(public_api_queue_redrive),
        )
        .route("/api/v1/analytics", get(public_api_analytics))
        .route(
            "/api/v1/analytics/{dataset}/events",
            get(public_api_analytics_events).post(public_api_analytics_write),
        )
        .route(
            "/api/v1/analytics/{dataset}/stats",
            get(public_api_analytics_stats),
        )
        .route(
            "/api/v1/analytics/{dataset}/query",
            post(public_api_analytics_query),
        )
        .route("/api/v1/pipelines", get(public_api_pipelines))
        .route(
            "/api/v1/pipelines/{pipeline}/events",
            post(public_api_pipeline_ingest),
        )
        .route(
            "/api/v1/pipelines/{pipeline}/status",
            get(public_api_pipeline_status),
        )
        .route(
            "/api/v1/pipelines/{pipeline}/batches",
            get(public_api_pipeline_batches),
        )
        .route(
            "/api/v1/pipelines/{pipeline}/flush",
            post(public_api_pipeline_flush),
        )
        .route("/api/v1/workflows", get(public_api_workflows))
        .route(
            "/api/v1/workflows/{workflow}/instances",
            get(public_api_workflow_instances).post(public_api_workflow_trigger),
        )
        .route(
            "/api/v1/workflows/{workflow}/instances/{id}",
            get(public_api_workflow_instance),
        )
        .route(
            "/api/v1/workflows/{workflow}/instances/{id}/signal",
            post(public_api_workflow_signal),
        )
        .route(
            "/api/v1/workflows/{workflow}/instances/{id}/{action}",
            post(public_api_workflow_action),
        )
        .route("/api/v1/flows", get(public_api_flows))
        .route(
            "/api/v1/flows/{flow}/runs",
            get(public_api_flow_runs).post(public_api_flow_trigger),
        )
        .route("/api/v1/flows/{flow}/runs/{id}", get(public_api_flow_run))
        .route(
            "/api/v1/flows/{flow}/runs/{id}/{action}",
            post(public_api_flow_action),
        )
        .route("/api/v1/email", get(public_api_email_domains))
        .route("/api/v1/network", get(public_api_network))
        .route(
            "/api/v1/email/{domain}/messages",
            get(public_api_email_messages).post(public_api_email_send),
        )
        .route(
            "/api/v1/email/{domain}/messages/{id}",
            get(public_api_email_message),
        )
        .route(
            "/api/v1/email/{domain}/messages/{id}/raw",
            get(public_api_email_raw),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_access_token,
        ));
    let api = Router::new()
        .route("/api/session", get(session))
        .route("/api/overview", get(overview))
        .route("/api/nodes", get(node_list))
        .route("/api/nodes/{id}", axum::routing::patch(node_update))
        .route("/api/security", get(security_overview))
        .route("/api/security/audit", get(security_audit))
        .route("/api/security/audit/archive", post(data_audit_archive))
        .route("/api/security/quota", axum::routing::patch(quota_update))
        .route("/api/security/tokens", post(access_token_create))
        .route("/api/security/tokens/{id}", delete(access_token_revoke))
        .route("/api/security/s3", post(s3_credential_create))
        .route(
            "/api/security/s3/{id}",
            axum::routing::patch(s3_credential_update).delete(s3_credential_revoke),
        )
        .route("/api/workers/deploy", post(worker_deploy))
        .route("/api/workers/{name}/export", get(worker_export))
        .route(
            "/api/workers/{name}",
            get(worker_get).patch(worker_update).delete(worker_delete),
        )
        .route("/api/workers/{name}/log", get(worker_log))
        .route("/api/workers/{name}/runtime-log", get(worker_runtime_log))
        .route("/api/workers/{name}/request-log", get(worker_request_log))
        .route(
            "/api/workers/{name}/previews",
            get(worker_preview_list).post(worker_preview_create),
        )
        .route(
            "/api/workers/{name}/previews/{alias}",
            delete(worker_preview_delete),
        )
        .route("/api/workers/{name}/build", post(worker_build))
        .route("/api/workers/{name}/files", post(worker_files_update))
        .route("/api/workers/{name}/files/{*path}", get(worker_file_get))
        .route("/api/workers/{name}/cron-runs", get(worker_cron_runs))
        .route("/api/workers/{name}/cron-fire", post(worker_cron_fire))
        .route(
            "/api/workers/{name}/cron-runs/{id}",
            delete(worker_cron_delete_dlq),
        )
        .route(
            "/api/workers/{name}/cron-runs/{id}/replay",
            post(worker_cron_replay),
        )
        .route("/api/workers/{name}/secrets", get(worker_secret_list))
        .route(
            "/api/workers/{name}/secrets/{binding}",
            put(worker_secret_put).delete(worker_secret_delete),
        )
        .route(
            "/api/workers/{name}/rollback/{version}",
            post(worker_rollback),
        )
        .route("/api/sources", get(source_list).post(source_connect))
        .route("/api/sources/{name}", delete(source_disconnect))
        .route("/api/builds", get(build_list))
        .route("/api/builds/{id}", get(build_get))
        .route("/api/approvals/{id}", get(approval_status))
        .route("/api/hostnames", get(hostname_list).post(hostname_claim))
        .route("/api/hostnames/{hostname}", delete(hostname_delete))
        .route(
            "/api/hostnames/{hostname}/verification",
            post(hostname_verify),
        )
        .route("/api/kv", get(kv_list))
        .route("/api/kv/value", get(kv_get).put(kv_put).delete(kv_delete))
        .route("/api/kv/export", get(kv_export))
        .route("/api/kv/import", post(kv_import))
        .route("/api/d1/create", post(d1_create))
        .route("/api/d1/exec", post(d1_exec))
        .route("/api/d1/batch", post(d1_batch))
        .route("/api/d1/info", get(d1_info))
        .route("/api/d1/import", post(d1_import))
        .route("/api/d1/export", get(d1_export))
        .route("/api/d1/backup", post(d1_backup))
        .route("/api/r2/buckets", get(r2_bucket_list).post(r2_bucket_apply))
        .route("/api/storage", get(storage_get).post(storage_apply))
        .route("/api/storage/probe", post(storage_probe))
        .route("/api/r2/buckets/{name}", delete(r2_bucket_delete))
        .route("/api/r2/objects/{bucket}", get(r2_object_list))
        .route("/api/r2/multipart/{bucket}", get(r2_multipart_list))
        .route(
            "/api/r2/multipart/{bucket}/{upload_id}",
            get(r2_multipart_detail).delete(r2_multipart_abort),
        )
        .route(
            "/api/r2/object/{bucket}/{*key}",
            get(r2_object_get)
                .put(r2_object_put)
                .delete(r2_object_delete),
        )
        .route("/api/binaries", get(binary_list).post(binary_apply))
        .route("/api/binaries/blob", post(binary_blob_upload))
        .route("/api/binaries/{name}", delete(binary_delete))
        .route("/api/queues", get(queue_list).post(queue_apply))
        .route("/api/queues/{name}", delete(queue_delete))
        .route("/api/queues/{name}/messages", post(queue_send))
        .route("/api/queues/{name}/dead", get(queue_dead_letters))
        .route("/api/queues/{name}/dead/{id}/redrive", post(queue_redrive))
        .route("/api/analytics", get(analytics_list).post(analytics_apply))
        .route("/api/analytics/{name}", delete(analytics_delete))
        .route(
            "/api/analytics/{name}/events",
            get(analytics_recent).post(analytics_write),
        )
        .route("/api/analytics/{name}/stats", get(analytics_stats))
        .route("/api/analytics/{name}/group", get(analytics_group))
        .route("/api/analytics/{name}/query", post(analytics_query))
        .route("/api/pipelines", get(pipeline_list).post(pipeline_apply))
        .route("/api/pipelines/{name}", delete(pipeline_delete))
        .route("/api/pipelines/{name}/tokens", post(pipeline_token_mint))
        .route(
            "/api/pipelines/{name}/tokens/{id}",
            delete(pipeline_token_revoke),
        )
        .route("/api/pipelines/{name}/events", post(pipeline_ingest))
        .route("/api/pipelines/{name}/status", get(pipeline_status))
        .route("/api/pipelines/{name}/batches", get(pipeline_batches))
        .route("/api/pipelines/{name}/flush", post(pipeline_flush))
        .route("/api/workflows", get(workflow_list).post(workflow_apply))
        .route("/api/workflows/{name}", delete(workflow_delete))
        .route("/api/workflows/{name}/tokens", post(workflow_token_mint))
        .route(
            "/api/workflows/{name}/tokens/{id}",
            delete(workflow_token_revoke),
        )
        .route(
            "/api/workflows/{name}/instances",
            get(workflow_instances).post(workflow_trigger),
        )
        .route(
            "/api/workflows/{name}/instances/{id}",
            get(workflow_instance),
        )
        .route(
            "/api/workflows/{name}/instances/{id}/signal",
            post(workflow_signal),
        )
        .route(
            "/api/workflows/{name}/instances/{id}/{action}",
            post(workflow_action),
        )
        .route("/api/flows", get(flow_list).post(flow_apply))
        .route("/api/flows/{name}", delete(flow_delete))
        .route("/api/flows/{name}/tokens", post(flow_token_mint))
        .route("/api/flows/{name}/tokens/{id}", delete(flow_token_revoke))
        .route("/api/flows/{name}/runs", get(flow_runs).post(flow_trigger))
        .route("/api/flows/{name}/runs/{id}", get(flow_run))
        .route("/api/flows/{name}/runs/{id}/{action}", post(flow_action))
        .route("/api/email", get(email_list).post(email_apply))
        .route("/api/email/{name}", delete(email_delete))
        .route(
            "/api/email/{name}/verification",
            get(email_verification).post(email_verify),
        )
        .route(
            "/api/email/{name}/messages",
            get(email_messages).post(email_send),
        )
        .route("/api/email/{name}/messages/{id}", get(email_message))
        .route(
            "/api/email/{name}/messages/{id}/raw",
            get(email_message_raw),
        )
        .route("/api/network", get(network_list))
        .route("/api/network/rules", post(network_rule_apply))
        .route("/api/network/rules/{name}", delete(network_rule_delete))
        .route("/api/network/devices", post(network_device_create))
        .route(
            "/api/network/devices/{name}",
            axum::routing::patch(network_device_update).delete(network_device_delete),
        )
        .route("/api/auth/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_console_auth,
        ));
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .route("/device/v1/config/{name}", get(device_public_config))
        .route("/api/auth/challenge", post(auth_challenge))
        .route("/api/auth/challenge/{id}", get(auth_poll))
        .route("/api/webhooks/github/{name}", post(github_webhook))
        .route("/api/webhooks/github-app", post(github_app_webhook))
        .route("/s3", any(s3_endpoint))
        .route("/s3/{*path}", any(s3_endpoint))
        .merge(token_api)
        .merge(api)
        .fallback(not_found)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_CONSOLE_UPLOAD * 2))
        .layer(middleware::from_fn(security_headers))
}

async fn device_public_config(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result = (|| -> ApiResult<crate::exitproxy::DeviceConfig> {
        let node = state.public_node()?;
        let raw = crate::access::bearer(&headers)
            .ok_or_else(|| ApiError::unauthorized("设备令牌缺失、过期或已撤销"))?;
        let principal = crate::exit::resolve_device(node, &name, raw)
            .ok_or_else(|| ApiError::unauthorized("设备令牌缺失、过期或已撤销"))?;
        Ok(crate::exitproxy::config_for_device(node, &principal))
    })();
    match result {
        Ok(config) => {
            let mut response = Json(config).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => {
            let unauthorized = error.status == StatusCode::UNAUTHORIZED;
            let mut response = error.into_response();
            if unauthorized {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"RandallFlare device\""),
                );
            }
            response
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkRuleRequest {
    name: String,
    #[serde(flatten)]
    spec: crate::exit::ExitRuleSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkDeviceCreateRequest {
    name: String,
    label: String,
    #[serde(default)]
    allowed_rules: Vec<String>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
    #[serde(default)]
    suspended: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkDeviceUpdateRequest {
    label: String,
    #[serde(default)]
    allowed_rules: Vec<String>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    revoke: bool,
}

async fn network_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    if let Ok(node) = state.public_node() {
        return Ok(Json(network_snapshot(node)));
    }
    let rule_views = state
        .client
        .resource_heads(&state.node, Some(crate::exit::EXIT_RULE_KIND))
        .await?;
    let rules = rule_views
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = crate::exit::exit_rule_spec(&view.resource).ok()?;
            Some(json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            }))
        })
        .collect::<Vec<_>>();
    let known_rules = rules
        .iter()
        .filter_map(|rule| rule.get("name").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let now = now_ms();
    let devices = state
        .client
        .resource_heads(&state.node, Some(crate::exit::DEVICE_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = crate::exit::device_spec(&view.resource).ok()?;
            let rules_ready = spec
                .allowed_rules
                .iter()
                .all(|rule| known_rules.contains(rule.as_str()));
            Some(json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "label": spec.label,
                "token_prefix": spec.token_prefix,
                "allowed_rules": spec.allowed_rules,
                "created_at_ms": spec.created_at_ms,
                "expires_at_ms": spec.expires_at_ms,
                "revoked_at_ms": spec.revoked_at_ms,
                "suspended": spec.suspended,
                "rules_ready": rules_ready,
                "active": spec.active(now) && rules_ready,
                "last_used_at_ms": Value::Null,
            }))
        })
        .collect::<Vec<_>>();
    let status = state.client.status(&state.node).await?;
    let exit_role = status
        .get("exit_node")
        .cloned()
        .unwrap_or_else(|| json!({ "enabled": false }));
    let mut exits = Vec::new();
    if exit_role
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        exits.push(json!({
            "node_id": status.get("node"),
            "label": status.get("label"),
            "endpoint": exit_role.get("endpoint"),
            "local": true,
            "live": true,
        }));
    }
    if let Some(peers) = status.get("peers").and_then(Value::as_array) {
        for peer in peers {
            if let Some(endpoint) = peer.get("exit_endpoint").filter(|value| !value.is_null()) {
                exits.push(json!({
                    "node_id": peer.get("id"),
                    "label": peer.get("label"),
                    "endpoint": endpoint,
                    "local": false,
                    "live": true,
                }));
            }
        }
    }
    Ok(Json(json!({
        "rules": rules,
        "devices": devices,
        "exits": exits,
        "exit_role": exit_role,
    })))
}

async fn validate_console_device_rules(state: &ConsoleState, names: &[String]) -> ApiResult<()> {
    if names.is_empty() {
        return Err(ApiError::bad_request("请至少选择一条出口规则"));
    }
    let available = state
        .client
        .resource_heads(&state.node, Some(crate::exit::EXIT_RULE_KIND))
        .await?
        .into_iter()
        .filter(|view| {
            !view.resource.deleted && crate::exit::exit_rule_spec(&view.resource).is_ok()
        })
        .map(|view| view.resource.name)
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(missing) = names.iter().find(|name| !available.contains(*name)) {
        return Err(ApiError::bad_request(format!(
            "设备引用的出口规则不存在：{missing}"
        )));
    }
    Ok(())
}

fn network_snapshot(node: &Node) -> Value {
    let rules = crate::exit::rule_records(node)
        .into_iter()
        .map(|(view, spec)| {
            json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect::<Vec<_>>();
    let devices = crate::exit::device_views(node);
    let mut exits = Vec::new();
    if node.cfg.exit.enabled {
        exits.push(json!({
            "node_id": node.id_hex(),
            "label": node.cfg.label,
            "endpoint": node.cfg.exit.advertise,
            "local": true,
            "live": true,
        }));
    }
    exits.extend(node.peers().into_iter().filter_map(|(node_id, peer)| {
        peer.capabilities.contains("exit").then(|| {
            json!({
                "node_id": node_id,
                "label": peer.label,
                "endpoint": peer.exit_endpoint,
                "local": false,
                "live": true,
            })
        })
    }));
    exits.sort_by(|left, right| {
        left.get("node_id")
            .and_then(Value::as_str)
            .cmp(&right.get("node_id").and_then(Value::as_str))
    });
    json!({
        "rules": rules,
        "devices": devices,
        "exits": exits,
        "exit_role": {
            "enabled": node.cfg.exit.enabled,
            "listen": node.cfg.exit.listen,
            "advertise": node.cfg.exit.advertise,
            "max_sessions": node.cfg.exit.max_sessions,
        },
    })
}

async fn submit_network_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Value> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            }))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            }))
        }
    }
}

async fn network_rule_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<NetworkRuleRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&request.name) {
        return Err(ApiError::bad_request("出口规则名称无效"));
    }
    request.spec.validate()?;
    let head = state
        .client
        .resource_head(&state.node, crate::exit::EXIT_RULE_KIND, &request.name)
        .await?;
    let record = crate::resource::prepare_after(
        crate::exit::EXIT_RULE_KIND,
        &request.name,
        serde_json::to_value(request.spec)?,
        false,
        head.as_ref(),
    )?;
    Ok(Json(
        submit_network_resource(
            &state,
            &principal,
            record,
            format!("创建或更新出口规则 {}", request.name),
        )
        .await?,
    ))
}

async fn network_rule_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::exit::EXIT_RULE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("出口规则不存在"))?;
    let spec = crate::exit::exit_rule_spec(&head.resource)?;
    let record = crate::resource::prepare_after(
        crate::exit::EXIT_RULE_KIND,
        &name,
        serde_json::to_value(spec)?,
        true,
        Some(&head),
    )?;
    let referenced = state
        .client
        .resource_heads(&state.node, Some(crate::exit::DEVICE_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| crate::exit::device_spec(&view.resource).ok())
        .any(|device| device.allowed_rules.iter().any(|rule| rule == &name));
    if referenced {
        return Err(ApiError::bad_request(
            "仍有客户端设备引用此出口规则，不能删除",
        ));
    }
    Ok(Json(
        submit_network_resource(&state, &principal, record, format!("删除出口规则 {name}")).await?,
    ))
}

async fn network_device_create(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<NetworkDeviceCreateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.allows_secret_writes() {
        return Err(ApiError::forbidden("设备令牌只能通过 HTTPS 管理界面签发"));
    }
    validate_console_device_rules(&state, &request.allowed_rules).await?;
    if state
        .client
        .resource_head(&state.node, crate::exit::DEVICE_KIND, &request.name)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request("此设备 ID 已存在或已进入历史链"));
    }
    let (mut record, token) = crate::exit::mint_device_record(
        &request.name,
        request.label,
        request.allowed_rules,
        request.expires_at_ms,
    )?;
    if request.suspended {
        let mut spec = crate::exit::device_spec(&record)?;
        spec.suspended = true;
        record = crate::resource::prepare_after(
            crate::exit::DEVICE_KIND,
            &request.name,
            serde_json::to_value(spec)?,
            false,
            None,
        )?;
    }
    let token = zeroize::Zeroizing::new(token);
    let mut response = submit_network_resource(
        &state,
        &principal,
        record,
        format!("注册客户端设备 {}", request.name),
    )
    .await?;
    response["token"] = Value::String(token.to_string());
    Ok(Json(response))
}

async fn network_device_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<NetworkDeviceUpdateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    validate_console_device_rules(&state, &request.allowed_rules).await?;
    let head = state
        .client
        .resource_head(&state.node, crate::exit::DEVICE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("客户端设备不存在"))?;
    let mut spec = crate::exit::device_spec(&head.resource)?;
    spec.label = request.label;
    spec.allowed_rules = request.allowed_rules;
    spec.expires_at_ms = request.expires_at_ms;
    spec.suspended = request.suspended;
    if request.revoke && spec.revoked_at_ms.is_none() {
        spec.revoked_at_ms = Some(now_ms());
    }
    spec.label = spec.label.trim().to_string();
    spec.validate()?;
    let record = crate::resource::prepare_after(
        crate::exit::DEVICE_KIND,
        &name,
        serde_json::to_value(spec)?,
        false,
        Some(&head),
    )?;
    Ok(Json(
        submit_network_resource(&state, &principal, record, format!("更新客户端设备 {name}"))
            .await?,
    ))
}

async fn network_device_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::exit::DEVICE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("客户端设备不存在"))?;
    let spec = crate::exit::device_spec(&head.resource)?;
    let record = crate::resource::prepare_after(
        crate::exit::DEVICE_KIND,
        &name,
        serde_json::to_value(spec)?,
        true,
        Some(&head),
    )?;
    Ok(Json(
        submit_network_resource(&state, &principal, record, format!("删除客户端设备 {name}"))
            .await?,
    ))
}

async fn s3_endpoint(
    State(state): State<ConsoleState>,
    request: Request<axum::body::Body>,
) -> Response {
    match state.public_node() {
        Ok(node) => crate::s3::handle(node.clone(), request).await,
        Err(error) => error.into_response(),
    }
}

async fn require_access_token(
    State(state): State<ConsoleState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let node = match state.public_node() {
        Ok(node) => node,
        Err(error) => return error.into_response(),
    };
    let principal =
        crate::access::bearer(request.headers()).and_then(|raw| crate::access::resolve(node, raw));
    let Some(principal) = principal else {
        let mut response =
            ApiError::unauthorized("Bearer API 访问令牌缺失、过期或已撤销").into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"RandallFlare API\""),
        );
        return response;
    };
    request.extensions_mut().insert(principal);
    next.run(request).await
}

fn require_api_scope(principal: &crate::access::AccessPrincipal, scope: &str) -> ApiResult<()> {
    if principal.allows(scope) {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!("访问令牌缺少作用域 {scope}")))
    }
}

async fn public_api_discovery(
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> Json<Value> {
    Json(json!({
        "name": "RandallFlare API",
        "version": "v1",
        "principal": { "id": principal.id, "label": principal.label, "scopes": principal.scopes },
        "endpoints": {
            "workers": "/api/v1/workers",
            "resources": "/api/v1/resources",
            "kv": "/api/v1/kv/{namespace}/{key}",
            "d1": "/api/v1/d1/{database}/query",
            "r2": "/api/v1/r2/{bucket}/{key}",
            "queues": "/api/v1/queues/{queue}",
            "analytics": "/api/v1/analytics/{dataset}/events",
            "pipelines": "/api/v1/pipelines/{pipeline}/events",
            "workflows": "/api/v1/workflows/{workflow}/instances",
            "flows": "/api/v1/flows/{flow}/runs",
            "email": "/api/v1/email/{domain}/messages",
            "network": "/api/v1/network",
            "audit": "/api/v1/audit",
            "s3": "/s3"
        }
    }))
}

async fn public_api_status(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "node:read")?;
    let node = state.public_node()?;
    let peers = node.peers();
    Ok(Json(json!({
        "cluster_id": node.cfg.cluster_id,
        "node_id": node.id_hex(),
        "label": node.cfg.label,
        "public": node.cfg.public,
        "live_nodes": peers.len() + 1,
        "workers": node.live_manifests().len(),
        "manifest_digest": node.anchor_digest().0,
    })))
}

async fn public_api_workers(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "worker:read")?;
    let node = state.public_node()?;
    let workers = node
        .live_manifests()
        .into_iter()
        .map(|manifest| public_worker_view(node, manifest))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "workers": workers })))
}

async fn public_api_worker(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "worker:read")?;
    let node = state.public_node()?;
    let manifest = node
        .manifest(&name)
        .filter(|manifest| !manifest.deleted)
        .ok_or_else(|| ApiError::not_found("Worker 不存在"))?;
    Ok(Json(public_worker_view(node, manifest)))
}

fn public_worker_view(node: &Node, manifest: WorkerManifest) -> Value {
    json!({
        "name": manifest.name,
        "version": manifest.version,
        "main": manifest.main,
        "hostnames": node.effective_worker_hostnames(&manifest),
        "custom_hostnames": manifest.hostnames,
        "environment": worker_console_environment(&manifest),
        "secret_names": crate::worker_secret::encrypted_secrets(&manifest).into_keys().collect::<Vec<_>>(),
        "kv_bindings": manifest.kv_bindings,
        "r2_bindings": deploy::r2_bindings(&manifest),
        "d1_bindings": deploy::d1_bindings(&manifest),
        "queue_bindings": deploy::queue_bindings(&manifest),
        "analytics_bindings": deploy::analytics_bindings(&manifest),
        "pipeline_bindings": deploy::pipeline_bindings(&manifest),
        "workflow_bindings": deploy::workflow_bindings(&manifest),
        "email_bindings": deploy::email_bindings(&manifest),
        "service_bindings": deploy::service_bindings(&manifest),
        "binary_bindings": deploy::binary_bindings(&manifest),
        "required_tags": crate::placement::required_tags(&manifest),
        "crons": manifest.crons,
        "compatibility_date": manifest.compatibility_date,
        "modules": manifest.modules,
        "assets": manifest.assets,
    })
}

async fn public_api_worker_submit(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(name): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "worker:write")?;
    let envelope = rf_core::envelope::Envelope::from_bytes(&body)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let node = state.public_node()?;
    let manifest: WorkerManifest = envelope
        .open(Some(&node.cfg.operator))
        .map_err(|error| ApiError::forbidden(format!("Worker 清单签名无效：{error}")))?;
    if manifest.name != name {
        return Err(ApiError::bad_request("路径 Worker 名称与签名清单不一致"));
    }
    crate::quota::validate_manifest_admission(node, &manifest)?;
    state.client.post_manifest(&state.node, &envelope).await?;
    Ok(Json(
        json!({ "ok": true, "name": name, "version": manifest.version }),
    ))
}

#[derive(Debug, Deserialize)]
struct PublicResourceQuery {
    kind: Option<String>,
}

async fn public_api_resources(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Query(query): Query<PublicResourceQuery>,
) -> ApiResult<Json<Value>> {
    let kind = query
        .kind
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("必须指定 kind 查询参数"))?;
    let scope = crate::access::scope_for_resource(kind, false)
        .ok_or_else(|| ApiError::forbidden("此资源类型不允许通过公开 API 读取"))?;
    require_api_scope(&principal, &scope)?;
    let node = state.public_node()?;
    let resources = crate::resource::heads(node, Some(kind))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .map(|view| public_resource_view(node, &view))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "resources": resources })))
}

async fn public_api_resource(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((kind, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let scope = crate::access::scope_for_resource(&kind, false)
        .ok_or_else(|| ApiError::forbidden("此资源类型不允许通过公开 API 读取"))?;
    require_api_scope(&principal, &scope)?;
    let resource = crate::resource::head(state.public_node()?, &kind, &name)
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("平台资源不存在"))?;
    Ok(Json(public_resource_view(state.public_node()?, &resource)))
}

fn public_resource_view(node: &Node, view: &crate::resource::ResourceView) -> Value {
    json!({
        "schema": view.resource.schema,
        "kind": view.resource.kind,
        "name": view.resource.name,
        "version": view.resource.version,
        "previous": view.resource.prev.map(hex::encode),
        "deleted": view.resource.deleted,
        "spec": public_resource_spec(node, &view.resource),
        "digest": view.digest,
    })
}

fn public_resource_spec(node: &Node, record: &crate::resource::ResourceRecord) -> Value {
    if record.deleted {
        return Value::Null;
    }
    match record.kind.as_str() {
        crate::pipeline::PIPELINE_KIND => crate::pipeline::pipeline_spec(record)
            .map(|spec| pipeline_spec_view(&spec))
            .unwrap_or(Value::Null),
        crate::flow::FLOW_KIND => crate::flow::flow_spec(record)
            .map(|spec| public_flow_spec(&spec))
            .unwrap_or(Value::Null),
        crate::preview::PREVIEW_KIND => crate::preview::preview_spec(record)
            .map(|spec| {
                json!({
                    "schema": spec.schema,
                    "worker": spec.worker,
                    "hostname": spec.hostname,
                    "manifest": public_worker_view(node, spec.manifest),
                    "source": spec.source,
                    "created_at_ms": spec.created_at_ms,
                    "expires_at_ms": spec.expires_at_ms,
                })
            })
            .unwrap_or(Value::Null),
        crate::access::TOKEN_KIND | crate::s3::CREDENTIAL_KIND | crate::exit::DEVICE_KIND => {
            Value::Null
        }
        _ => record.spec().unwrap_or(Value::Null),
    }
}

async fn public_api_resource_submit(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let envelope = rf_core::envelope::Envelope::from_bytes(&body)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let node = state.public_node()?;
    let record: crate::resource::ResourceRecord = envelope
        .open(Some(&node.cfg.operator))
        .map_err(|error| ApiError::forbidden(format!("平台资源签名无效：{error}")))?;
    let scope = crate::access::scope_for_resource(&record.kind, true)
        .ok_or_else(|| ApiError::forbidden("此资源类型不允许通过公开 API 写入"))?;
    require_api_scope(&principal, &scope)?;
    crate::quota::validate_resource_admission(node, &record)?;
    state.client.post_resource(&state.node, &envelope).await?;
    Ok(Json(
        json!({ "ok": true, "kind": record.kind, "name": record.name, "version": record.version }),
    ))
}

async fn public_api_audit(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "audit:read")?;
    let node = state.public_node()?;
    let mut records = crate::resource::records(node, None, None)
        .into_iter()
        .map(|view| {
            json!({
                "kind": view.resource.kind,
                "name": view.resource.name,
                "version": view.resource.version,
                "previous": view.resource.prev.map(hex::encode),
                "deleted": view.resource.deleted,
                "digest": view.digest,
            })
        })
        .collect::<Vec<_>>();
    records.extend(worker_audit_records(node, None)?);
    records.sort_by(audit_value_order);
    let mutations = crate::data_audit::cluster_entries(node, None, 500).await?;
    Ok(Json(json!({ "records": records, "mutations": mutations })))
}

#[derive(Debug, Deserialize)]
struct PublicListQuery {
    #[serde(default)]
    prefix: String,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn public_api_kv_list(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(namespace): Path<String>,
    Query(query): Query<PublicListQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "kv:read")?;
    validate_kv(&namespace, None, false)?;
    let page = state
        .client
        .kv_list_page(
            &state.node,
            &namespace,
            &query.prefix,
            query.cursor.as_deref(),
            query.limit.unwrap_or(1000),
        )
        .await?;
    Ok(Json(json!({
        "namespace": namespace,
        "keys": page.entries.iter().map(|entry| entry.key.clone()).collect::<Vec<_>>(),
        "entries": page.entries,
        "list_complete": page.list_complete,
        "cursor": page.cursor,
    })))
}

async fn public_api_kv_get(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((namespace, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    require_api_scope(&principal, "kv:read")?;
    validate_kv(&namespace, Some(&key), false)?;
    let value = state
        .client
        .kv_get(&state.node, &namespace, &key)
        .await?
        .ok_or_else(|| ApiError::not_found("KV 键不存在"))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], value).into_response())
}

async fn public_api_kv_put(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((namespace, key)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "kv:write")?;
    validate_kv(&namespace, Some(&key), true)?;
    if body.len() > MAX_KV_VALUE {
        return Err(ApiError::bad_request("KV 值不得超过 25 MiB"));
    }
    state
        .client
        .kv_put(&state.node, &namespace, &key, body.to_vec())
        .await?;
    Ok(Json(json!({ "ok": true })))
}

async fn public_api_kv_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((namespace, key)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "kv:write")?;
    validate_kv(&namespace, Some(&key), true)?;
    state
        .client
        .kv_delete(&state.node, &namespace, &key)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

async fn public_api_r2_buckets(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "r2:read")?;
    let buckets = crate::r2::bucket_records(state.public_node()?)
        .into_iter()
        .map(|(view, spec)| json!({ "name": view.resource.name, "version": view.resource.version, "spec": spec }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "buckets": buckets })))
}

async fn public_api_r2_list(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(bucket): Path<String>,
    Query(query): Query<PublicListQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "r2:read")?;
    let list = state
        .client
        .r2_list(
            &state.node,
            &bucket,
            &query.prefix,
            query.cursor.as_deref(),
            query.limit.unwrap_or(1000),
        )
        .await?;
    Ok(Json(serde_json::to_value(list)?))
}

async fn public_api_r2_get(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    require_api_scope(&principal, "r2:read")?;
    let (meta, bytes) = state
        .client
        .r2_get(&state.node, &bucket, &key)
        .await?
        .ok_or_else(|| ApiError::not_found("R2 对象不存在"))?;
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", meta.etag)).unwrap(),
    );
    if let Some(content_type) = meta
        .content_type
        .and_then(|value| HeaderValue::from_str(&value).ok())
    {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    Ok(response)
}

async fn public_api_r2_put(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "r2:write")?;
    let options = crate::r2::PutOptions {
        content_type: headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        ..Default::default()
    };
    let meta = state
        .client
        .r2_put(&state.node, &bucket, &key, &body, &options)
        .await?;
    Ok(Json(serde_json::to_value(meta)?))
}

async fn public_api_r2_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "r2:write")?;
    let deleted = state.client.r2_delete(&state.node, &bucket, &key).await?;
    Ok(Json(json!({ "ok": true, "deleted": deleted })))
}

async fn public_api_binary_blob(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Query(query): Query<BinaryBlobQuery>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "binary:write")?;
    if body.is_empty() || body.len() > crate::binary::MAX_BINARY_BYTES {
        return Err(ApiError::bad_request(
            "Binary 文件必须介于 1 字节和 200 MiB 之间",
        ));
    }
    let storage = binary_storage(query)?;
    let (sha256, size_bytes) =
        crate::binary::store_bytes(state.public_node()?, &storage, &body).await?;
    Ok(Json(json!({
        "ok": true,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "storage": storage,
    })))
}

async fn public_api_d1_list(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "d1:read")?;
    Ok(Json(
        json!({ "databases": crate::d1::database_names(state.public_node()?) }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicD1Request {
    sql: String,
    #[serde(default = "empty_json_array")]
    params: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicD1BatchRequest {
    statements: Vec<crate::d1::Statement>,
}

fn empty_json_array() -> Value {
    json!([])
}

async fn public_api_d1_query(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(database): Path<String>,
    Json(request): Json<PublicD1Request>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "d1:read")?;
    validate_public_d1_request(&database, &request)?;
    if !public_sql_is_read_only(&request.sql) {
        return Err(ApiError::forbidden(
            "d1:read 只允许 SELECT、只读 WITH、EXPLAIN 或只读 PRAGMA",
        ));
    }
    let result = state
        .client
        .d1_exec(&state.node, &database, &request.sql, request.params)
        .await?;
    Ok(Json(result))
}

async fn public_api_d1_exec(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(database): Path<String>,
    Json(request): Json<PublicD1Request>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "d1:write")?;
    validate_public_d1_request(&database, &request)?;
    let result = state
        .client
        .d1_exec(&state.node, &database, &request.sql, request.params)
        .await?;
    Ok(Json(result))
}

async fn public_api_d1_batch(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(database): Path<String>,
    Json(request): Json<PublicD1BatchRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "d1:write")?;
    validate_d1_batch(&database, &request.statements)?;
    let result = state
        .client
        .d1_batch(&state.node, &database, &request.statements)
        .await?;
    Ok(Json(result))
}

fn validate_d1_batch(database: &str, statements: &[crate::d1::Statement]) -> ApiResult<()> {
    if !valid_name(database) {
        return Err(ApiError::bad_request("数据库名称无效"));
    }
    if statements.is_empty() || statements.len() > 100 {
        return Err(ApiError::bad_request(
            "D1 原子批处理必须包含 1 至 100 条语句",
        ));
    }
    for statement in statements {
        let request = PublicD1Request {
            sql: statement.sql.clone(),
            params: Value::Array(statement.params.clone()),
        };
        validate_public_d1_request(database, &request)?;
    }
    Ok(())
}

fn validate_public_d1_request(database: &str, request: &PublicD1Request) -> ApiResult<()> {
    if !valid_name(database) {
        return Err(ApiError::bad_request("数据库名称无效"));
    }
    if request.sql.trim().is_empty() || request.sql.len() > MAX_CONSOLE_VALUE {
        return Err(ApiError::bad_request(
            "SQL 长度必须介于 1 字节与 1 MiB 之间",
        ));
    }
    let params = request
        .params
        .as_array()
        .ok_or_else(|| ApiError::bad_request("参数必须是 JSON 数组"))?;
    if params.len() > 1000 {
        return Err(ApiError::bad_request("D1 单条语句最多接受 1000 个参数"));
    }
    Ok(())
}

fn public_sql_is_read_only(sql: &str) -> bool {
    let mut cleaned = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut quote = None;
    while let Some(character) = chars.next() {
        if let Some(end) = quote {
            if character == end {
                quote = None;
            }
            cleaned.push(' ');
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
            cleaned.push(' ');
            continue;
        }
        if character == '-' && chars.peek() == Some(&'-') {
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
            cleaned.push(' ');
            continue;
        }
        if character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
            cleaned.push(' ');
            continue;
        }
        cleaned.push(character);
    }
    let statement = cleaned.trim();
    let statement = statement.strip_suffix(';').unwrap_or(statement).trim_end();
    if statement.contains(';') {
        return false;
    }
    let tokens = statement
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_uppercase)
        .collect::<Vec<_>>();
    let Some(first) = tokens.first().map(String::as_str) else {
        return false;
    };
    if !matches!(first, "SELECT" | "WITH" | "EXPLAIN" | "PRAGMA") {
        return false;
    }
    if tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "INSERT"
                | "UPDATE"
                | "DELETE"
                | "REPLACE"
                | "CREATE"
                | "DROP"
                | "ALTER"
                | "VACUUM"
                | "ATTACH"
                | "DETACH"
                | "REINDEX"
                | "ANALYZE"
        )
    }) {
        return false;
    }
    if first != "PRAGMA" {
        return true;
    }

    // SQLite PRAGMA has both query and assignment forms. A lexical "no DML"
    // check alone would let d1:read mutate persistent database metadata.
    if cleaned.contains('=') {
        return false;
    }
    let pragma = tokens
        .iter()
        .skip(1)
        .find(|token| !matches!(token.as_str(), "MAIN" | "TEMP"))
        .map(String::as_str);
    let Some(pragma) = pragma else {
        return false;
    };
    let argument_is_read_only = matches!(
        pragma,
        "TABLE_INFO"
            | "TABLE_XINFO"
            | "INDEX_LIST"
            | "INDEX_INFO"
            | "INDEX_XINFO"
            | "FOREIGN_KEY_LIST"
            | "FOREIGN_KEY_CHECK"
            | "INTEGRITY_CHECK"
            | "QUICK_CHECK"
    );
    if cleaned.contains('(') && !argument_is_read_only {
        return false;
    }
    argument_is_read_only
        || matches!(
            pragma,
            "DATABASE_LIST"
                | "TABLE_LIST"
                | "COMPILE_OPTIONS"
                | "COLLATION_LIST"
                | "FUNCTION_LIST"
                | "MODULE_LIST"
                | "PRAGMA_LIST"
                | "ENCODING"
                | "PAGE_COUNT"
                | "FREELIST_COUNT"
                | "SCHEMA_VERSION"
                | "USER_VERSION"
                | "APPLICATION_ID"
        )
}

async fn public_api_queues(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "queue:read")?;
    let queues = crate::queue::queue_records(state.public_node()?)
        .into_iter()
        .map(|(view, spec)| json!({ "name": view.resource.name, "version": view.resource.version, "spec": spec }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "queues": queues })))
}

async fn public_api_queue_status(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(queue): Path<String>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "queue:read")?;
    Ok(Json(serde_json::to_value(
        state.client.queue_stats(&state.node, &queue).await?,
    )?))
}

async fn public_api_queue_send(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(queue): Path<String>,
    Json(request): Json<QueueSendRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "queue:write")?;
    let message_ids = state
        .client
        .queue_send(&state.node, &queue, &request.messages)
        .await?;
    Ok(Json(json!({ "message_ids": message_ids })))
}

async fn public_api_queue_dead(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(queue): Path<String>,
    Query(query): Query<QueueDeadQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "queue:read")?;
    let dead_letters = state
        .client
        .queue_dead_letters(&state.node, &queue, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "dead_letters": dead_letters })))
}

async fn public_api_queue_redrive(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((queue, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "queue:write")?;
    let redriven = state.client.queue_redrive(&state.node, &queue, &id).await?;
    Ok(Json(json!({ "ok": redriven })))
}

async fn public_api_analytics(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "analytics:read")?;
    let datasets = crate::analytics::dataset_records(state.public_node()?)
        .into_iter()
        .map(|(view, spec)| json!({ "name": view.resource.name, "version": view.resource.version, "spec": spec }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "datasets": datasets })))
}

async fn public_api_analytics_events(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(dataset): Path<String>,
    Query(query): Query<AnalyticsRecentQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "analytics:read")?;
    let events = state
        .client
        .analytics_recent(
            &state.node,
            &dataset,
            query.before,
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({ "events": events })))
}

async fn public_api_analytics_write(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(dataset): Path<String>,
    Json(request): Json<AnalyticsWriteRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "analytics:write")?;
    let written = state
        .client
        .analytics_write(&state.node, &dataset, &request.points)
        .await?;
    Ok(Json(json!({ "written": written })))
}

async fn public_api_analytics_stats(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(dataset): Path<String>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "analytics:read")?;
    Ok(Json(serde_json::to_value(
        state.client.analytics_stats(&state.node, &dataset).await?,
    )?))
}

async fn public_api_analytics_query(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(dataset): Path<String>,
    Json(request): Json<AnalyticsSqlRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "analytics:read")?;
    Ok(Json(serde_json::to_value(
        state
            .client
            .analytics_query(
                &state.node,
                &dataset,
                &request.sql,
                request.params,
                request.limit,
            )
            .await?,
    )?))
}

async fn public_api_pipelines(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "pipeline:read")?;
    let pipelines = crate::pipeline::pipeline_records(state.public_node()?)
        .into_iter()
        .map(|(view, spec)| json!({ "name": view.resource.name, "version": view.resource.version, "spec": pipeline_spec_view(&spec) }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "pipelines": pipelines })))
}

async fn public_api_pipeline_ingest(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(pipeline): Path<String>,
    Json(request): Json<PipelineIngestRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "pipeline:write")?;
    let accepted = state
        .client
        .pipeline_ingest(&state.node, &pipeline, &request.events)
        .await?;
    Ok(Json(json!({ "accepted": accepted })))
}

async fn public_api_pipeline_status(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(pipeline): Path<String>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "pipeline:read")?;
    Ok(Json(serde_json::to_value(
        state.client.pipeline_status(&state.node, &pipeline).await?,
    )?))
}

async fn public_api_pipeline_batches(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(pipeline): Path<String>,
    Query(query): Query<PipelineBatchQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "pipeline:read")?;
    let batches = state
        .client
        .pipeline_batches(&state.node, &pipeline, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "batches": batches })))
}

async fn public_api_pipeline_flush(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(pipeline): Path<String>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "pipeline:write")?;
    let batch = state.client.pipeline_flush(&state.node, &pipeline).await?;
    Ok(Json(json!({ "batch": batch })))
}

async fn public_api_workflows(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "workflow:read")?;
    let workflows = crate::workflow::workflow_records(state.public_node()?)
        .into_iter()
        .map(|(view, spec)| json!({ "name": view.resource.name, "version": view.resource.version, "spec": public_workflow_spec(&spec) }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "workflows": workflows })))
}

fn public_workflow_spec(spec: &crate::workflow::WorkflowSpec) -> Value {
    let mut value = serde_json::to_value(spec).unwrap_or(Value::Null);
    if let Some(tokens) = value.get_mut("tokens").and_then(Value::as_array_mut) {
        for token in tokens {
            if let Some(object) = token.as_object_mut() {
                object.remove("sha256");
            }
        }
    }
    value
}

async fn public_api_workflow_instances(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(workflow): Path<String>,
    Query(query): Query<WorkflowInstancesQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "workflow:read")?;
    let instances = state
        .client
        .workflow_instances(
            &state.node,
            &workflow,
            query.status.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({ "instances": instances })))
}

async fn public_api_workflow_trigger(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(workflow): Path<String>,
    Json(request): Json<WorkflowTriggerRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "workflow:write")?;
    let instance = state
        .client
        .workflow_create(
            &state.node,
            &workflow,
            request.instance_key.as_deref(),
            request.concurrency_group.as_deref(),
            request.input,
        )
        .await?;
    Ok(Json(json!({ "instance": instance })))
}

async fn public_api_workflow_instance(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((workflow, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "workflow:read")?;
    Ok(Json(
        state
            .client
            .workflow_instance(&state.node, &workflow, &id)
            .await?,
    ))
}

async fn public_api_workflow_signal(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((workflow, id)): Path<(String, String)>,
    Json(request): Json<WorkflowSignalRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "workflow:write")?;
    let signal_id = state
        .client
        .workflow_signal(&state.node, &workflow, &id, &request.name, request.payload)
        .await?;
    Ok(Json(json!({ "signal_id": signal_id })))
}

async fn public_api_workflow_action(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((workflow, id, action)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "workflow:write")?;
    state
        .client
        .workflow_action(&state.node, &workflow, &id, &action)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

fn public_flow_spec(spec: &crate::flow::FlowSpec) -> Value {
    let mut value = serde_json::to_value(spec).unwrap_or(Value::Null);
    if let Some(tokens) = value.get_mut("tokens").and_then(Value::as_array_mut) {
        for token in tokens {
            if let Some(object) = token.as_object_mut() {
                object.remove("sha256");
            }
        }
    }
    value
}

async fn public_api_flows(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "flow:read")?;
    let flows = crate::flow::flow_records(state.public_node()?)
        .into_iter()
        .map(|(view, spec)| json!({ "name": view.resource.name, "version": view.resource.version, "spec": public_flow_spec(&spec) }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "flows": flows })))
}

async fn public_api_flow_runs(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(flow): Path<String>,
    Query(query): Query<FlowRunsQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "flow:read")?;
    let runs = state
        .client
        .flow_runs(
            &state.node,
            &flow,
            query.status.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({ "runs": runs })))
}

async fn public_api_flow_trigger(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(flow): Path<String>,
    Json(request): Json<FlowTriggerRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "flow:write")?;
    let run = state
        .client
        .flow_create(
            &state.node,
            &flow,
            request.run_key.as_deref(),
            request.input,
        )
        .await?;
    Ok(Json(json!({ "run": run })))
}

async fn public_api_flow_run(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((flow, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "flow:read")?;
    Ok(Json(state.client.flow_run(&state.node, &flow, &id).await?))
}

async fn public_api_flow_action(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((flow, id, action)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "flow:write")?;
    Ok(Json(
        state
            .client
            .flow_action(&state.node, &flow, &id, &action)
            .await?,
    ))
}

async fn public_api_email_domains(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "email:read")?;
    let domains = crate::email::email_domain_records(state.public_node()?)
        .into_iter()
        .map(|(view, spec)| json!({ "name": view.resource.name, "version": view.resource.version, "spec": spec }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "domains": domains })))
}

async fn public_api_email_messages(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(domain): Path<String>,
    Query(query): Query<EmailMessagesQuery>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "email:read")?;
    let messages = state
        .client
        .email_messages(&state.node, &domain, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "messages": messages })))
}

async fn public_api_email_message(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((domain, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "email:read")?;
    Ok(Json(
        json!({ "message": state.client.email_message(&state.node, &domain, &id).await? }),
    ))
}

async fn public_api_email_raw(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path((domain, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    require_api_scope(&principal, "email:read")?;
    let raw = state
        .client
        .email_message_raw(&state.node, &domain, &id)
        .await?;
    Ok(([(header::CONTENT_TYPE, "message/rfc822")], raw).into_response())
}

async fn public_api_email_send(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
    Path(domain): Path<String>,
    Json(request): Json<EmailSendRequest>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "email:write")?;
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(request.raw_base64)
        .map_err(|_| ApiError::bad_request("RFC 822 原文不是有效 Base64"))?;
    let metadata = crate::email::EmailSendMetadata {
        mail_from: request.mail_from,
        recipients: request.recipients,
    };
    let queued = state
        .client
        .email_send(&state.node, &domain, &metadata, &raw)
        .await?;
    Ok(Json(json!({ "queued": queued })))
}

async fn public_api_network(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<crate::access::AccessPrincipal>,
) -> ApiResult<Json<Value>> {
    require_api_scope(&principal, "network:read")?;
    Ok(Json(network_snapshot(state.public_node()?)))
}

async fn require_console_auth(
    State(state): State<ConsoleState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let principal = match &state.mode {
        ConsoleMode::Local { token, .. } => {
            let supplied = request
                .headers()
                .get(TOKEN_HEADER)
                .and_then(|value| value.to_str().ok());
            if supplied != Some(token.as_ref()) {
                return ApiError::unauthorized("控制台会话令牌缺失或无效").into_response();
            }
            ConsolePrincipal {
                session_id: [0; 32],
                csrf: String::new(),
            }
        }
        ConsoleMode::Public { node, .. } => {
            let Some(encoded) = cookie_value(request.headers(), SESSION_COOKIE) else {
                return ApiError::unauthorized("需要操作员授权").into_response();
            };
            let grant = match decode_grant(encoded, &node.cfg.operator, &node.cfg.cluster_id) {
                Ok(grant) => grant,
                Err(error) => return ApiError::unauthorized(error.to_string()).into_response(),
            };
            if is_mutating(request.method()) {
                let csrf = request
                    .headers()
                    .get(CSRF_HEADER)
                    .and_then(|value| value.to_str().ok());
                if csrf != Some(grant.csrf_hex().as_str()) {
                    return ApiError::forbidden("CSRF 令牌缺失或无效").into_response();
                }
                if !same_origin(&request, state.origin_scheme()) {
                    log_origin_rejection(&request, state.origin_scheme(), "management");
                    return ApiError::forbidden("已拒绝跨源管理请求").into_response();
                }
            }
            ConsolePrincipal {
                session_id: grant.session_id,
                csrf: grant.csrf_hex(),
            }
        }
    };
    request.extensions_mut().insert(principal);
    next.run(request).await
}

async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

async fn index(State(state): State<ConsoleState>) -> Html<String> {
    let (mode, token) = match &state.mode {
        ConsoleMode::Local { token, .. } => ("local", token.as_ref()),
        ConsoleMode::Public { .. } => ("public", ""),
    };
    Html(
        INDEX_HTML
            .replace("__RF_TOKEN__", token)
            .replace("__RF_MODE__", mode),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn styles_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLES_CSS,
    )
}

async fn not_found() -> ApiError {
    ApiError::not_found("未找到对应的控制台路由")
}

fn is_mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn cookie_value<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn request_authority(request: &Request<axum::body::Body>) -> Option<&str> {
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
}

fn same_origin(request: &Request<axum::body::Body>, expected_scheme: &str) -> bool {
    let Some(authority) = request_authority(request) else {
        return false;
    };
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Ok(origin) = origin.parse::<Uri>() else {
        return false;
    };
    origin.scheme_str() == Some(expected_scheme)
        && origin
            .authority()
            .is_some_and(|origin| origin.as_str().eq_ignore_ascii_case(authority))
        && origin.path() == "/"
        && origin.query().is_none()
}

fn log_origin_rejection(
    request: &Request<axum::body::Body>,
    expected_scheme: &str,
    endpoint: &str,
) {
    let authority = request_authority(request).unwrap_or("<missing>");
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>");
    tracing::warn!(
        endpoint,
        authority,
        origin,
        expected_scheme,
        "console: rejected cross-origin request"
    );
}

fn encode_grant(envelope: &rf_core::envelope::Envelope) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope.to_bytes())
}

fn decode_grant(
    encoded: &str,
    operator: &rf_core::identity::SignerId,
    cluster_id: &str,
) -> Result<ConsoleGrant> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("控制台会话格式有误")?;
    let envelope = rf_core::envelope::Envelope::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("控制台会话格式有误：{error}"))?;
    let grant: ConsoleGrant = envelope
        .open(Some(operator))
        .map_err(|error| anyhow::anyhow!("控制台会话无效：{error}"))?;
    grant.validate(cluster_id, now_ms())?;
    Ok(grant)
}

fn session_cookie(envelope: &rf_core::envelope::Envelope, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
        encode_grant(envelope),
        crate::management::CONSOLE_SESSION_TTL_MS / 1000,
    )
}

fn expired_session_cookie(secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
}

async fn auth_challenge(
    State(state): State<ConsoleState>,
    request: Request<axum::body::Body>,
) -> ApiResult<Json<Value>> {
    if !same_origin(&request, state.origin_scheme()) {
        log_origin_rejection(&request, state.origin_scheme(), "auth_challenge");
        return Err(ApiError::forbidden("已拒绝跨源身份验证请求"));
    }
    let node = state.public_node()?;
    let approval = node
        .management
        .create_login(&node.cfg.cluster_id, &node.cfg.label)?;
    Ok(Json(json!({
        "id": approval.id,
        "code": approval.code,
        "summary": approval.summary,
        "expires_at_ms": approval.expires_at_ms,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
        "operator": node.cfg.operator.to_string(),
    })))
}

async fn auth_poll(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let node = state.public_node()?;
    let poll = node.management.poll_login(&id)?;
    match poll.state {
        ApprovalState::Pending => Ok(Json(json!({ "state": "pending" })).into_response()),
        ApprovalState::Failed => Err(ApiError::forbidden(
            poll.error.unwrap_or_else(|| "授权失败".into()),
        )),
        ApprovalState::Completed => {
            let envelope = poll
                .envelope
                .ok_or_else(|| ApiError::upstream("已批准的登录缺少签名信封"))?;
            let grant: ConsoleGrant = envelope
                .open(Some(&node.cfg.operator))
                .map_err(|error| ApiError::forbidden(error.to_string()))?;
            grant
                .validate(&node.cfg.cluster_id, now_ms())
                .map_err(|error| ApiError::forbidden(error.to_string()))?;
            let secure = matches!(
                state.mode,
                ConsoleMode::Public {
                    secure_cookies: true,
                    ..
                }
            );
            let mut response = Json(json!({
                "state": "completed",
                "expires_at_ms": grant.expires_at_ms,
            }))
            .into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&session_cookie(&envelope, secure))
                    .map_err(|_| ApiError::upstream("无法创建控制台会话 Cookie"))?,
            );
            Ok(response)
        }
    }
}

async fn logout(State(state): State<ConsoleState>) -> ApiResult<Response> {
    let secure = matches!(
        state.mode,
        ConsoleMode::Public {
            secure_cookies: true,
            ..
        }
    );
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&expired_session_cookie(secure))
            .map_err(|_| ApiError::upstream("无法清除控制台会话 Cookie"))?,
    );
    Ok(response)
}

async fn session(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
) -> Json<Value> {
    let (operator, auth_mode, secure_transport) = match &state.mode {
        ConsoleMode::Local { operator, .. } => (
            operator.as_ref().map(|key| key.signer_id().to_string()),
            "local_token",
            true,
        ),
        ConsoleMode::Public {
            node,
            secure_cookies,
        } => (
            Some(node.cfg.operator.to_string()),
            "operator_grant",
            *secure_cookies,
        ),
    };
    Json(json!({
        "product": "RandallFlare",
        "version": env!("CARGO_PKG_VERSION"),
        "node": state.node.as_ref(),
        "operator": operator,
        "read_only": state.is_read_only(),
        "auth_mode": auth_mode,
        "csrf": principal.csrf,
        "secure_transport": secure_transport,
        "uptime_seconds": state.started.elapsed().as_secs(),
    }))
}

async fn overview(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let mut value = state.client.status(&state.node).await?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ApiError::upstream("节点返回了无效的状态数据"))?;
    object.insert(
        "console".into(),
        json!({
            "connected_to": state.node.as_ref(),
            "operator": state.operator_id().map(|operator| operator.to_string()),
            "read_only": state.is_read_only(),
            "auth_mode": if state.is_public() { "operator_grant" } else { "local_token" },
            "uptime_seconds": state.started.elapsed().as_secs(),
        }),
    );
    Ok(Json(value))
}

async fn node_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let status = state.client.status(&state.node).await?;
    let policies = state
        .client
        .resource_heads(&state.node, Some(crate::placement::NODE_POLICY_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            crate::placement::policy_spec(&view.resource)
                .ok()
                .map(|policy| (policy.node_id.clone(), (view, policy)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut live = BTreeMap::<String, Value>::new();
    if let Some(id) = status.get("node").and_then(Value::as_str) {
        live.insert(
            id.to_string(),
            json!({
                "id": id,
                "label": status.get("label").cloned().unwrap_or(Value::Null),
                "public": status.get("public").and_then(Value::as_bool).unwrap_or(false),
                "api": status.pointer("/console/connected_to").cloned().unwrap_or_else(|| Value::String(state.node.to_string())),
                "ip4": Value::Null,
                "capabilities": status.get("capabilities").cloned().unwrap_or_else(|| json!([])),
                "deployments": status.get("deployments").cloned().unwrap_or_else(|| json!({})),
                "local": true,
                "live": true,
            }),
        );
    }
    for peer in status
        .get("peers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(id) = peer.get("id").and_then(Value::as_str) {
            let mut peer = peer.clone();
            if let Some(object) = peer.as_object_mut() {
                object.insert("local".into(), Value::Bool(false));
                object.insert("live".into(), Value::Bool(true));
            }
            live.insert(id.to_string(), peer);
        }
    }
    let mut ids = live
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    ids.extend(policies.keys().cloned());
    let nodes = ids
        .into_iter()
        .map(|id| {
            let mut node = live.remove(&id).unwrap_or_else(|| {
                json!({
                    "id": id,
                    "label": "离线节点",
                    "public": false,
                    "api": null,
                    "ip4": null,
                    "capabilities": [],
                    "deployments": {},
                    "local": false,
                    "live": false,
                })
            });
            let (resource_version, region, tags, drain, suspended, reason) = policies
                .get(&id)
                .map(|(view, policy)| {
                    (
                        view.resource.version,
                        policy.region.clone(),
                        policy.tags.clone(),
                        policy.drain,
                        policy.suspended,
                        policy.reason.clone(),
                    )
                })
                .unwrap_or((0, String::new(), vec![], false, false, String::new()));
            let mut effective = node
                .get("capabilities")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<std::collections::BTreeSet<_>>();
            if node.get("public").and_then(Value::as_bool) == Some(true) {
                effective.insert("public".into());
            }
            effective.extend(tags.iter().cloned());
            if !region.is_empty() {
                effective.insert(format!("region-{region}"));
            }
            if let Some(object) = node.as_object_mut() {
                object.insert("resource_version".into(), resource_version.into());
                object.insert("region".into(), region.into());
                object.insert("tags".into(), json!(tags));
                object.insert("effective_tags".into(), json!(effective));
                object.insert("drain".into(), drain.into());
                object.insert("suspended".into(), suspended.into());
                object.insert("reason".into(), reason.into());
            }
            node
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "nodes": nodes })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodePolicyRequest {
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    drain: Option<bool>,
    #[serde(default)]
    suspended: Option<bool>,
    #[serde(default)]
    reason: Option<String>,
}

async fn node_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(id): Path<String>,
    Json(request): Json<NodePolicyRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("节点身份必须是 64 位十六进制值"));
    }
    if request.region.is_none()
        && request.tags.is_none()
        && request.drain.is_none()
        && request.suspended.is_none()
        && request.reason.is_none()
    {
        return Err(ApiError::bad_request("没有需要更新的节点策略"));
    }
    let name = crate::placement::resource_name(&id)?;
    let head = state
        .client
        .resource_head(&state.node, crate::placement::NODE_POLICY_KIND, &name)
        .await?;
    let current = head
        .as_ref()
        .filter(|head| !head.resource.deleted)
        .map(|head| crate::placement::policy_spec(&head.resource))
        .transpose()?
        .unwrap_or(crate::placement::NodePolicy {
            schema: crate::placement::NODE_POLICY_SCHEMA,
            node_id: id.to_ascii_lowercase(),
            region: String::new(),
            tags: vec![],
            drain: false,
            suspended: false,
            reason: String::new(),
        });
    let policy = crate::placement::NodePolicy {
        schema: crate::placement::NODE_POLICY_SCHEMA,
        node_id: id.to_ascii_lowercase(),
        region: request.region.unwrap_or(current.region),
        tags: request.tags.unwrap_or(current.tags),
        drain: request.drain.unwrap_or(current.drain),
        suspended: request.suspended.unwrap_or(current.suspended),
        reason: request.reason.unwrap_or(current.reason),
    };
    let record = crate::placement::prepare_after(policy, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "node": id,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "更新节点 {} 的调度策略 v{}",
                    short_node_id(&id),
                    record.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "node": id,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

fn short_node_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

async fn security_overview(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let quota = crate::quota::policy(node)?;
    let usage = crate::quota::usage(node).await?;
    Ok(Json(json!({
        "quota": quota,
        "usage": usage,
        "access_tokens": crate::access::views(node),
        "s3_credentials": crate::s3::views(node),
        "scopes": crate::access::ALL_SCOPES,
        "s3_endpoint": "/s3",
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaUpdateRequest {
    max_workers: u32,
    max_custom_hostnames: u32,
    max_worker_bytes: u64,
    max_requests_per_minute: u64,
    worker_outbound_allowed: bool,
    max_r2_local_bytes: u64,
    max_r2_objects: u64,
}

async fn quota_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<QuotaUpdateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let head = crate::resource::head(node, crate::quota::POLICY_KIND, crate::quota::POLICY_NAME);
    let policy = crate::quota::ClusterQuotaPolicy {
        schema: crate::quota::POLICY_SCHEMA,
        max_workers: request.max_workers,
        max_custom_hostnames: request.max_custom_hostnames,
        max_worker_bytes: request.max_worker_bytes,
        max_requests_per_minute: request.max_requests_per_minute,
        worker_outbound_allowed: request.worker_outbound_allowed,
        max_r2_local_bytes: request.max_r2_local_bytes,
        max_r2_objects: request.max_r2_objects,
    };
    let record = crate::quota::prepare_after(policy, head.as_ref())?;
    submit_security_resource(
        &state,
        &principal,
        node,
        record,
        "更新 RandallFlare 集群安全配额".into(),
        json!({}),
    )
    .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessTokenCreateRequest {
    label: String,
    scopes: Vec<String>,
    #[serde(default)]
    expires_in_days: Option<u32>,
}

async fn access_token_create(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<AccessTokenCreateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.allows_secret_writes() {
        return Err(ApiError::forbidden(
            "API 访问令牌只允许通过 HTTPS 或本机控制台创建",
        ));
    }
    let node = state.public_node()?;
    let expires_at_ms = request
        .expires_in_days
        .map(|days| {
            if !(1..=3650).contains(&days) {
                return Err(ApiError::bad_request(
                    "API 访问令牌有效期必须介于 1 和 3650 天",
                ));
            }
            Ok(now_ms().saturating_add(u64::from(days) * 86_400_000))
        })
        .transpose()?;
    let (record, raw) = crate::access::mint(node, request.label, request.scopes, expires_at_ms)?;
    submit_security_resource(
        &state,
        &principal,
        node,
        record,
        "创建有作用域的 RandallFlare API 访问令牌".into(),
        json!({ "token": raw, "shown_once": true }),
    )
    .await
}

async fn access_token_revoke(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let record = crate::access::revoke(node, &id)?;
    submit_security_resource(
        &state,
        &principal,
        node,
        record,
        format!("撤销 API 访问令牌 {id}"),
        json!({}),
    )
    .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3CredentialCreateRequest {
    label: String,
    #[serde(default)]
    acl_enabled: bool,
    #[serde(default)]
    grants: BTreeMap<String, crate::s3::BucketGrant>,
}

async fn s3_credential_create(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<S3CredentialCreateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.allows_secret_writes() {
        return Err(ApiError::forbidden(
            "R2/S3 凭据只允许通过 HTTPS 或本机控制台创建",
        ));
    }
    let node = state.public_node()?;
    let (record, access_key_id, secret_access_key) =
        crate::s3::mint(node, request.label, request.acl_enabled, request.grants)?;
    submit_security_resource(
        &state,
        &principal,
        node,
        record,
        "创建加密的 R2/S3 Signature V4 凭据".into(),
        json!({
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "shown_once": true,
        }),
    )
    .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3CredentialUpdateRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    acl_enabled: Option<bool>,
    #[serde(default)]
    grants: Option<BTreeMap<String, crate::s3::BucketGrant>>,
}

async fn s3_credential_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(id): Path<String>,
    Json(request): Json<S3CredentialUpdateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let record = crate::s3::update(
        node,
        &id,
        request.label,
        request.acl_enabled,
        request.grants,
        false,
    )?;
    submit_security_resource(
        &state,
        &principal,
        node,
        record,
        format!("更新 R2/S3 凭据 {id} 的最小权限"),
        json!({}),
    )
    .await
}

async fn s3_credential_revoke(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let record = crate::s3::update(node, &id, None, None, None, true)?;
    submit_security_resource(
        &state,
        &principal,
        node,
        record,
        format!("撤销 R2/S3 凭据 {id}"),
        json!({}),
    )
    .await
}

async fn submit_security_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    node: &Node,
    record: crate::resource::ResourceRecord,
    summary: String,
    extra: Value,
) -> ApiResult<Json<Value>> {
    crate::quota::validate_resource_admission(node, &record)?;
    let mut response = extra.as_object().cloned().unwrap_or_default();
    response.insert("ok".into(), Value::Bool(true));
    response.insert("name".into(), Value::String(record.name.clone()));
    response.insert("version".into(), Value::from(record.version));
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
        }
        ConsoleMode::Public { .. } => {
            let approval =
                node.management
                    .create_resource(principal.session_id, &record, summary)?;
            response.insert("pending_approval".into(), Value::Bool(true));
            response.insert("approval".into(), serde_json::to_value(approval)?);
            response.insert(
                "approve_node".into(),
                Value::String(node.cfg.peer_api_advertise().to_string()),
            );
        }
    }
    Ok(Json(Value::Object(response)))
}

#[derive(Debug, Deserialize)]
struct SecurityAuditQuery {
    kind: Option<String>,
    name: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DataAuditArchiveRequest {
    bucket: String,
    #[serde(default = "console_default_data_audit_prefix")]
    prefix: String,
    #[serde(default)]
    before_ms: Option<u64>,
}

fn console_default_data_audit_prefix() -> String {
    "data-audit".into()
}

async fn data_audit_archive(
    State(state): State<ConsoleState>,
    Json(request): Json<DataAuditArchiveRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let archive = state
        .client
        .data_audit_archive(
            &state.node,
            &request.bucket,
            &request.prefix,
            request.before_ms,
        )
        .await?;
    Ok(Json(serde_json::to_value(archive)?))
}

async fn security_audit(
    State(state): State<ConsoleState>,
    Query(query): Query<SecurityAuditQuery>,
) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let limit = query.limit.unwrap_or(500).clamp(1, 5000);
    let include_resources = query.kind.as_deref() != Some("worker_manifest");
    let resource_kind = query
        .kind
        .as_deref()
        .filter(|kind| *kind != "worker_manifest");
    let mut records = if include_resources {
        crate::resource::records(node, resource_kind, query.name.as_deref())
    } else {
        Vec::new()
    }
    .into_iter()
    .map(|view| {
        let sensitive = matches!(
            view.resource.kind.as_str(),
            crate::access::TOKEN_KIND
                | crate::s3::CREDENTIAL_KIND
                | crate::pipeline::PIPELINE_KIND
                | crate::flow::FLOW_KIND
                | crate::preview::PREVIEW_KIND
                | crate::exit::DEVICE_KIND
        );
        json!({
            "kind": view.resource.kind,
            "name": view.resource.name,
            "version": view.resource.version,
            "previous": view.resource.prev.map(hex::encode),
            "digest": view.digest,
            "deleted": view.resource.deleted,
            "spec": public_resource_spec(node, &view.resource),
            "redacted": sensitive,
        })
    })
    .collect::<Vec<_>>();
    if query
        .kind
        .as_deref()
        .is_none_or(|kind| kind == "worker_manifest")
    {
        records.extend(worker_audit_records(node, query.name.as_deref())?);
    }
    records.sort_by(audit_value_order);
    records.truncate(limit);
    let mutations = if query.kind.is_none() && query.name.is_none() {
        crate::data_audit::cluster_entries(node, None, limit).await?
    } else {
        Vec::new()
    };
    Ok(Json(json!({ "records": records, "mutations": mutations })))
}

fn worker_audit_records(node: &Node, name: Option<&str>) -> ApiResult<Vec<Value>> {
    let mut records = Vec::new();
    for worker in node
        .manifest_names()
        .into_iter()
        .filter(|worker| name.is_none_or(|name| worker == name))
    {
        let envelopes = node.manifest_log(&worker)?;
        let chain = rf_core::manifest::verify_chain(&envelopes, &node.cfg.operator)
            .map_err(|error| ApiError::upstream(error.to_string()))?;
        records.extend(chain.iter().zip(&envelopes).map(|(manifest, envelope)| {
            json!({
                "kind": "worker_manifest",
                "name": manifest.name,
                "version": manifest.version,
                "previous": manifest.prev.map(hex::encode),
                "digest": hex::encode(envelope.digest()),
                "deleted": manifest.deleted,
                "spec": {
                    "hostnames": manifest.hostnames,
                    "modules": manifest.modules.len(),
                    "assets": manifest.assets.len(),
                    "bytes": crate::quota::worker_bytes(manifest),
                    "secret_bindings": crate::worker_secret::encrypted_secrets(manifest).len(),
                },
                "redacted": true,
            })
        }));
    }
    Ok(records)
}

fn audit_value_order(left: &Value, right: &Value) -> std::cmp::Ordering {
    let version = |value: &Value| value.get("version").and_then(Value::as_u64).unwrap_or(0);
    (
        audit_string(right, "kind"),
        audit_string(right, "name"),
        version(right),
    )
        .cmp(&(
            audit_string(left, "kind"),
            audit_string(left, "name"),
            version(left),
        ))
}

fn audit_string<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployRequest {
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    files: Vec<UploadedFile>,
    #[serde(default)]
    archive: Option<UploadedArchive>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadedFile {
    path: String,
    data_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadedArchive {
    filename: String,
    data_base64: String,
}

async fn worker_deploy(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<DeployRequest>,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let operator = state.operator()?.clone();
            let requested = request
                .path
                .ok_or_else(|| ApiError::bad_request("从本地控制台部署时必须提供 Worker 路径"))?;
            let path = requested.canonicalize().map_err(|error| {
                ApiError::bad_request(format!(
                    "无法解析 Worker 目录 {}：{error}",
                    requested.display()
                ))
            })?;
            let bundle = if path.is_dir() {
                deploy::read_bundle(&path)?
            } else if path.is_file() {
                let bytes = std::fs::read(&path).map_err(|error| {
                    ApiError::bad_request(format!("无法读取 Worker 压缩包：{error}"))
                })?;
                let filename = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| ApiError::bad_request("Worker 压缩包文件名无效"))?;
                deploy::read_bundle_archive(&bytes, filename)?
            } else {
                return Err(ApiError::bad_request("Worker 路径不是目录或压缩包"));
            };
            let name = bundle.spec.name.clone();
            let version = deploy::deploy(&bundle, &state.client, &state.node, &operator).await?;
            Ok(Json(
                json!({ "ok": true, "name": name, "version": version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            use base64::Engine as _;
            if request.archive.is_some() && !request.files.is_empty() {
                return Err(ApiError::bad_request("目录与压缩包不能同时上传"));
            }
            let bundle = if let Some(archive) = request.archive {
                if archive.filename.is_empty() || archive.filename.len() > 255 {
                    return Err(ApiError::bad_request("Worker 压缩包文件名无效"));
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&archive.data_base64)
                    .map_err(|_| ApiError::bad_request("Worker 压缩包不是有效的 Base64 数据"))?;
                deploy::read_bundle_archive(&bytes, &archive.filename)?
            } else {
                if request.files.is_empty() || request.files.len() > MAX_CONSOLE_FILES {
                    return Err(ApiError::bad_request(format!(
                        "上传内容必须包含 1 至 {MAX_CONSOLE_FILES} 个文件"
                    )));
                }
                let mut total = 0usize;
                let mut files = Vec::with_capacity(request.files.len());
                for file in request.files {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(&file.data_base64)
                        .map_err(|_| ApiError::bad_request("上传文件不是有效的 Base64 数据"))?;
                    total = total.saturating_add(bytes.len());
                    if total > MAX_CONSOLE_UPLOAD {
                        return Err(ApiError::bad_request("Worker 上传内容超过 64 MiB"));
                    }
                    files.push((file.path, bytes));
                }
                deploy::read_bundle_files(files)?
            };
            let manifest = deploy::prepare_manifest(&bundle, &state.client, &state.node).await?;
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "部署 Worker {} v{}（{} 个模块，{} 项静态资源）",
                    manifest.name,
                    manifest.version,
                    manifest.modules.len(),
                    manifest.assets.len()
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Deserialize)]
struct WorkerExportQuery {
    #[serde(default = "default_worker_export_format")]
    format: String,
}

fn default_worker_export_format() -> String {
    "zip".into()
}

async fn worker_export(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<WorkerExportQuery>,
) -> ApiResult<Response> {
    let (manifest, _) = current_manifest(&state, &name).await?;
    let format = match query.format.as_str() {
        "zip" => deploy::ExportFormat::Zip,
        "tar" => deploy::ExportFormat::Tar,
        "tar.gz" | "tgz" => deploy::ExportFormat::TarGz,
        _ => return Err(ApiError::bad_request("导出格式只允许 zip、tar 或 tar.gz")),
    };
    let mut blobs = BTreeMap::new();
    for (sha256, size) in manifest
        .modules
        .iter()
        .map(|module| (module.sha256, module.size))
        .chain(
            manifest
                .assets
                .iter()
                .map(|asset| (asset.sha256, asset.size)),
        )
    {
        if blobs.contains_key(&sha256) {
            continue;
        }
        let bytes = state.client.fetch_blob(&state.node, &sha256).await?;
        if bytes.len() as u64 != size || crate::blob::sha256_hex(&bytes) != hex::encode(sha256) {
            return Err(ApiError::upstream("导出内容块的大小或 SHA-256 不匹配"));
        }
        blobs.insert(sha256, bytes);
    }
    let files = deploy::export_bundle_files(&manifest, blobs)?;
    let bytes = deploy::write_bundle_archive(&files, format)?;
    let (extension, content_type) = match format {
        deploy::ExportFormat::Zip => ("zip", "application/zip"),
        deploy::ExportFormat::Tar => ("tar", "application/x-tar"),
        deploy::ExportFormat::TarGz => ("tar.gz", "application/gzip"),
    };
    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{name}.{extension}\""))
            .map_err(|_| ApiError::upstream("导出文件名无效"))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSettingsRequest {
    #[serde(default)]
    hostnames: Option<Vec<String>>,
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    kv_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    r2_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    d1_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    queue_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    analytics_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pipeline_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    workflow_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    email_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    service_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    binary_bindings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    crons: Option<Vec<String>>,
    #[serde(default)]
    compatibility_date: Option<String>,
    #[serde(default)]
    compatibility_flags: Option<Vec<String>>,
    #[serde(default)]
    required_tags: Option<Vec<String>>,
}

fn manifest_error_zh(error: ManifestError) -> String {
    match error {
        ManifestError::Envelope(_) => "部署清单封装无效".into(),
        ManifestError::NotOperator => "部署清单并非由集群管理员签署".into(),
        ManifestError::BadName => "Worker 名称须由小写字母、数字或连字符组成".into(),
        ManifestError::MainNotInModules => "入口模块不在构建产物的模块列表中".into(),
        ManifestError::BadCron(value) => format!("Cron 表达式无效：{value}"),
        ManifestError::BadHostname(value) => format!("域名格式无效：{value}"),
        ManifestError::BadPath(value) => format!("Worker 包含不安全的文件路径：{value}"),
        ManifestError::DuplicatePath(value) => format!("Worker 包含重复的文件路径：{value}"),
        ManifestError::ChainBroken => "部署清单的版本哈希链已断裂".into(),
    }
}

async fn current_manifest(
    state: &ConsoleState,
    name: &str,
) -> ApiResult<(WorkerManifest, [u8; 32])> {
    if !valid_name(name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let envelopes = state.client.worker_log(&state.node, name).await?;
    let operator = configured_operator(state).await?;
    let chain = rf_core::manifest::verify_chain(&envelopes, &operator)
        .map_err(|error| ApiError::upstream(manifest_error_zh(error)))?;
    let manifest = chain
        .last()
        .filter(|manifest| !manifest.deleted)
        .cloned()
        .ok_or_else(|| ApiError::not_found("Worker 不存在或已删除"))?;
    let digest = envelopes
        .last()
        .map(rf_core::envelope::Envelope::digest)
        .ok_or_else(|| ApiError::not_found("未找到 Worker 部署清单"))?;
    Ok((manifest, digest))
}

async fn configured_operator(state: &ConsoleState) -> ApiResult<rf_core::identity::SignerId> {
    if let Some(operator) = state.operator_id() {
        return Ok(operator);
    }
    state
        .client
        .status(&state.node)
        .await?
        .get("operator")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::upstream("节点状态缺少管理员公钥身份"))?
        .parse()
        .map_err(|error| ApiError::upstream(format!("节点返回的管理员身份无效：{error}")))
}

async fn worker_get(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let env = worker_console_environment(&manifest);
    let durable_objects = deploy::durable_objects(&manifest);
    let r2_bindings = deploy::r2_bindings(&manifest);
    let d1_bindings = deploy::d1_bindings(&manifest);
    let queue_bindings = deploy::queue_bindings(&manifest);
    let analytics_bindings = deploy::analytics_bindings(&manifest);
    let pipeline_bindings = deploy::pipeline_bindings(&manifest);
    let workflow_bindings = deploy::workflow_bindings(&manifest);
    let email_bindings = deploy::email_bindings(&manifest);
    let service_bindings = deploy::service_bindings(&manifest);
    let binary_bindings = deploy::binary_bindings(&manifest);
    let secret_names: Vec<String> = crate::worker_secret::encrypted_secrets_checked(&manifest)?
        .into_keys()
        .collect();
    let source = match &state.mode {
        ConsoleMode::Public { node, .. } => crate::build::source_head(node, &name)
            .filter(|record| !record.source.deleted)
            .map(|record| serde_json::to_value(record).unwrap_or(Value::Null)),
        ConsoleMode::Local { .. } => None,
    };
    let hostname_claims = state
        .client
        .resource_heads(&state.node, Some(crate::hostname::HOSTNAME_CLAIM_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = crate::hostname::claim_spec(&view.resource).ok()?;
            manifest.hostnames.contains(&spec.hostname).then(|| {
                json!({
                    "hostname": spec.hostname,
                    "verified": spec.verified_at_ms.is_some(),
                    "verified_at_ms": spec.verified_at_ms,
                    "txt_name": spec.txt_name(),
                    "txt_value": spec.txt_value(),
                    "version": view.resource.version,
                })
            })
        })
        .collect::<Vec<_>>();
    let (default_hostname, effective_hostnames) = match &state.mode {
        ConsoleMode::Public { node, .. } => (
            node.default_worker_hostname(&manifest.name),
            node.effective_worker_hostnames(&manifest),
        ),
        ConsoleMode::Local { .. } => (
            None,
            manifest
                .hostnames
                .iter()
                .filter(|hostname| {
                    hostname_claims.iter().any(|claim| {
                        claim["hostname"].as_str() == Some(hostname)
                            && claim["verified"].as_bool() == Some(true)
                    })
                })
                .cloned()
                .collect(),
        ),
    };
    let tls = match &state.mode {
        ConsoleMode::Public { node, .. } => worker_tls_view(node, &effective_hostnames),
        ConsoleMode::Local { .. } => json!({
            "enabled": false,
            "acme_enabled": false,
            "acme_ready": false,
            "include_worker_hostnames": false,
            "zone": null,
            "dns_target": null,
            "certificates": effective_hostnames.iter().map(|hostname| json!({
                "hostname": hostname,
                "status": "unknown",
                "source": "unknown",
                "coverage": "unknown",
                "covered_by": null,
                "issued_ms": null,
                "expires_ms": null,
                "days_remaining": null,
                "auto_managed": false,
            })).collect::<Vec<_>>(),
        }),
    };
    Ok(Json(json!({
        "worker": {
            "name": manifest.name,
            "version": manifest.version,
            "digest": hex::encode(digest),
            "main": manifest.main,
            "modules": manifest.modules,
            "assets": manifest.assets,
            "hostnames": effective_hostnames,
            "custom_hostnames": manifest.hostnames,
            "hostname_claims": hostname_claims,
            "default_hostname": default_hostname,
            "env": env,
            "kv_bindings": manifest.kv_bindings,
            "r2_bindings": r2_bindings,
            "d1_bindings": d1_bindings,
            "queue_bindings": queue_bindings,
            "analytics_bindings": analytics_bindings,
            "pipeline_bindings": pipeline_bindings,
            "workflow_bindings": workflow_bindings,
            "email_bindings": email_bindings,
            "service_bindings": service_bindings,
            "binary_bindings": binary_bindings,
            "secret_names": secret_names,
            "crons": manifest.crons,
            "compatibility_date": manifest.compatibility_date,
            "compatibility_flags": deploy::compatibility_flags(&manifest),
            "required_tags": crate::placement::required_tags_checked(&manifest)?,
            "durable_objects": durable_objects,
        },
        "source": source,
        "tls": tls,
    })))
}

fn worker_console_environment(manifest: &WorkerManifest) -> BTreeMap<String, String> {
    let mut env = manifest.env.clone();
    env.remove(deploy::DO_METADATA_ENV);
    env.remove(deploy::R2_METADATA_ENV);
    env.remove(deploy::D1_METADATA_ENV);
    env.remove(deploy::QUEUE_METADATA_ENV);
    env.remove(deploy::ANALYTICS_METADATA_ENV);
    env.remove(deploy::PIPELINE_METADATA_ENV);
    env.remove(deploy::WORKFLOW_METADATA_ENV);
    env.remove(deploy::EMAIL_METADATA_ENV);
    env.remove(deploy::SERVICE_METADATA_ENV);
    env.remove(deploy::BINARY_METADATA_ENV);
    env.remove(deploy::SECRET_METADATA_ENV);
    env.remove(deploy::COMPATIBILITY_FLAGS_METADATA_ENV);
    env.remove(crate::placement::REQUIRED_TAGS_METADATA_ENV);
    env
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerFileType {
    Module,
    Asset,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerFileChange {
    Put {
        path: String,
        content_base64: String,
        #[serde(default)]
        file_type: Option<WorkerFileType>,
    },
    Delete {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerFilesRequest {
    changes: Vec<WorkerFileChange>,
    #[serde(default)]
    main: Option<String>,
}

#[derive(Clone)]
enum EditableWorkerFile {
    Module(Module),
    Asset(AssetFile),
}

impl EditableWorkerFile {
    fn set_path(&mut self, path: String) {
        match self {
            Self::Module(module) => {
                module.kind = deploy::module_kind(std::path::Path::new(&path));
                module.path = path;
            }
            Self::Asset(asset) => asset.path = path,
        }
    }
}

async fn worker_file_get(
    State(state): State<ConsoleState>,
    Path((name, path)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (manifest, _) = current_manifest(&state, &name).await?;
    let (sha256, size, file_type, module_kind) =
        if let Some(module) = manifest.modules.iter().find(|module| module.path == path) {
            (
                module.sha256,
                module.size,
                "module",
                Some(format!("{:?}", module.kind)),
            )
        } else if let Some(asset) = manifest.assets.iter().find(|asset| asset.path == path) {
            (asset.sha256, asset.size, "asset", None)
        } else {
            return Err(ApiError::not_found("当前 Worker 版本中没有这个文件"));
        };
    if size > MAX_EDITOR_READ as u64 {
        return Ok(Json(json!({
            "path": path,
            "file_type": file_type,
            "module_kind": module_kind,
            "size": size,
            "sha256": hex::encode(sha256),
            "editable": false,
            "reason": "文件超过 5 MiB，请通过目录上传或 Git 构建替换",
        })));
    }
    let bytes = state.client.fetch_blob(&state.node, &sha256).await?;
    if crate::blob::sha256_hex(&bytes) != hex::encode(sha256) {
        return Err(ApiError::upstream("节点返回的文件内容摘要不匹配"));
    }
    use base64::Engine as _;
    let text = String::from_utf8(bytes.clone())
        .ok()
        .filter(|value| !value.contains('\0'));
    Ok(Json(json!({
        "path": path,
        "file_type": file_type,
        "module_kind": module_kind,
        "size": size,
        "sha256": hex::encode(sha256),
        "editable": true,
        "text": text,
        "content_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
    })))
}

async fn worker_files_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<WorkerFilesRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if request.changes.is_empty() && request.main.is_none() {
        return Err(ApiError::bad_request("没有需要发布的文件或入口修改"));
    }
    if request.changes.len() > MAX_EDITOR_CHANGES {
        return Err(ApiError::bad_request("一次最多修改 256 个文件"));
    }
    let (mut manifest, digest) = current_manifest(&state, &name).await?;
    let mut files = BTreeMap::new();
    for module in manifest.modules.drain(..) {
        files.insert(module.path.clone(), EditableWorkerFile::Module(module));
    }
    for asset in manifest.assets.drain(..) {
        if files
            .insert(asset.path.clone(), EditableWorkerFile::Asset(asset))
            .is_some()
        {
            return Err(ApiError::upstream("当前 Worker 清单包含重复文件路径"));
        }
    }

    let mut uploaded_bytes = 0usize;
    use base64::Engine as _;
    for change in request.changes {
        match change {
            WorkerFileChange::Put {
                path,
                content_base64,
                file_type,
            } => {
                validate_editor_path(&path)?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(content_base64)
                    .map_err(|_| ApiError::bad_request("文件内容不是有效的 Base64"))?;
                if bytes.len() > MAX_EDITOR_FILE {
                    return Err(ApiError::bad_request("单个编辑文件不能超过 25 MiB"));
                }
                uploaded_bytes = uploaded_bytes.saturating_add(bytes.len());
                if uploaded_bytes > MAX_CONSOLE_UPLOAD {
                    return Err(ApiError::bad_request("单次文件修改不能超过 64 MiB"));
                }
                let resolved_type = file_type.or_else(|| {
                    files.get(&path).map(|file| match file {
                        EditableWorkerFile::Module(_) => WorkerFileType::Module,
                        EditableWorkerFile::Asset(_) => WorkerFileType::Asset,
                    })
                });
                let resolved_type = resolved_type.ok_or_else(|| {
                    ApiError::bad_request("创建新文件时必须指定 module 或 asset 类型")
                })?;
                if matches!(resolved_type, WorkerFileType::Module)
                    && deploy::reserved_module_path(&path)
                {
                    return Err(ApiError::bad_request("__rf_ 模块路径由 RandallFlare 保留"));
                }
                let sha_hex = state.client.put_blob(&state.node, bytes.clone()).await?;
                let sha256 = decode_console_sha(&sha_hex)?;
                if crate::blob::sha256_hex(&bytes) != sha_hex.trim().to_ascii_lowercase() {
                    return Err(ApiError::upstream("节点返回的内容摘要与上传文件不匹配"));
                }
                let file = match resolved_type {
                    WorkerFileType::Module => EditableWorkerFile::Module(Module {
                        path: path.clone(),
                        sha256,
                        kind: deploy::module_kind(std::path::Path::new(&path)),
                        size: bytes.len() as u64,
                    }),
                    WorkerFileType::Asset => EditableWorkerFile::Asset(AssetFile {
                        path: path.clone(),
                        sha256,
                        size: bytes.len() as u64,
                    }),
                };
                files.insert(path, file);
            }
            WorkerFileChange::Delete { path } => {
                validate_editor_path(&path)?;
                if files.remove(&path).is_none() {
                    return Err(ApiError::not_found(format!("文件 {path} 不存在")));
                }
            }
            WorkerFileChange::Rename { from, to } => {
                validate_editor_path(&from)?;
                validate_editor_path(&to)?;
                if files.contains_key(&to) {
                    return Err(ApiError::bad_request(format!("目标文件 {to} 已存在")));
                }
                let mut file = files
                    .remove(&from)
                    .ok_or_else(|| ApiError::not_found(format!("文件 {from} 不存在")))?;
                file.set_path(to.clone());
                if manifest.main == from {
                    if !matches!(file, EditableWorkerFile::Module(_)) {
                        return Err(ApiError::bad_request("入口模块不能重命名为静态资源"));
                    }
                    manifest.main = to.clone();
                }
                files.insert(to, file);
            }
        }
    }
    if files.len() > 5_000 {
        return Err(ApiError::bad_request("一个 Worker 最多包含 5000 个文件"));
    }
    if let Some(main) = request.main {
        manifest.main = main.trim().to_string();
    }
    manifest.modules = files
        .values()
        .filter_map(|file| match file {
            EditableWorkerFile::Module(module) => Some(module.clone()),
            EditableWorkerFile::Asset(_) => None,
        })
        .collect();
    manifest.assets = files
        .values()
        .filter_map(|file| match file {
            EditableWorkerFile::Module(_) => None,
            EditableWorkerFile::Asset(asset) => Some(asset.clone()),
        })
        .collect();
    if manifest
        .modules
        .iter()
        .any(|module| deploy::reserved_module_path(&module.path))
    {
        return Err(ApiError::bad_request("__rf_ 模块路径由 RandallFlare 保留"));
    }
    if manifest.main.is_empty() && manifest.assets.is_empty() {
        return Err(ApiError::bad_request(
            "Worker 必须设置入口模块，或至少保留一个静态资源",
        ));
    }
    manifest.version = manifest
        .version
        .checked_add(1)
        .ok_or_else(|| ApiError::bad_request("Worker 版本号已耗尽"))?;
    manifest.prev = Some(digest);
    manifest.validate().map_err(|error| {
        ApiError::bad_request(format!("Worker 文件无效：{}", manifest_error_zh(error)))
    })?;
    submit_file_manifest(&state, &principal, manifest, files.len()).await
}

async fn submit_file_manifest(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    manifest: WorkerManifest,
    file_count: usize,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&manifest, state.operator()?);
            state.client.post_manifest(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": manifest.name,
                "version": manifest.version,
                "files": file_count,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "发布 Worker {} 的文件修改为 v{}（{} 个文件）",
                    manifest.name, manifest.version, file_count
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "files": file_count,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

fn validate_editor_path(path: &str) -> ApiResult<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.starts_with('/')
        || path.contains('\\')
        || path.as_bytes().iter().any(|byte| byte.is_ascii_control())
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(ApiError::bad_request("文件路径不是安全的相对路径"));
    }
    Ok(())
}

fn decode_console_sha(value: &str) -> ApiResult<[u8; 32]> {
    hex::decode(value.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::upstream("节点返回了无效的内容摘要"))
}

fn worker_tls_view(node: &Node, hostnames: &[String]) -> Value {
    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    const RENEWAL_MS: u64 = 30 * DAY_MS;

    let https_enabled = node.cfg.ingress.https.is_some();
    let acme = node.cfg.acme.as_ref();
    let zone = acme
        .and_then(|cfg| cfg.zone.clone())
        .or_else(|| node.cfg.dns.as_ref().map(|cfg| cfg.zone.clone()));
    let configured: Vec<String> = acme
        .map(|cfg| {
            cfg.hostnames
                .iter()
                .map(|hostname| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let include_worker_hostnames = acme
        .map(|cfg| cfg.include_worker_hostnames)
        .unwrap_or(false);
    let token_env = acme
        .and_then(|cfg| cfg.api_token_env.clone())
        .or_else(|| node.cfg.dns.as_ref().map(|cfg| cfg.api_token_env.clone()))
        .unwrap_or_else(|| "CF_API_TOKEN".into());
    let acme_ready = acme.is_some()
        && zone.is_some()
        && std::env::var(&token_env)
            .ok()
            .is_some_and(|token| !token.is_empty());
    let cert_dir = node.cfg.data_dir.join("certs");
    let now = now_ms();

    let certificates = hostnames
        .iter()
        .map(|hostname| {
            let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
            let wildcard = hostname
                .split_once('.')
                .map(|(_, suffix)| format!("*.{suffix}"));
            let candidates = std::iter::once((hostname.clone(), "exact"))
                .chain(wildcard.clone().map(|name| (name, "wildcard")));

            let mut record = None;
            let mut manual = None;
            for (candidate, coverage) in candidates {
                if record.is_none() {
                    record = node
                        .kv_get(crate::acme::NS, &crate::acme::cert_kv_key(&candidate))
                        .and_then(|raw| {
                            serde_json::from_slice::<crate::acme::CertRecord>(&raw).ok()
                        })
                        .map(|record| (candidate.clone(), coverage, record));
                }
                if manual.is_none() {
                    let stem = crate::acme::file_stem(&candidate);
                    if cert_dir.join(format!("{stem}.crt")).is_file()
                        && cert_dir.join(format!("{stem}.key")).is_file()
                    {
                        manual = Some((candidate, coverage));
                    }
                }
            }

            let zone_match = zone.as_deref().is_some_and(|zone| {
                let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
                hostname == zone || hostname.ends_with(&format!(".{zone}"))
            });
            let configured_name = configured
                .iter()
                .find(|name| **name == hostname || wildcard.as_ref() == Some(*name))
                .cloned();
            let auto_managed = acme.is_some()
                && (configured_name.is_some() || (include_worker_hostnames && zone_match));

            let (status, source, coverage, covered_by, issued_ms, expires_ms, days_remaining) =
                if !https_enabled {
                    ("https_disabled", "none", "none", None, None, None, None)
                } else if let Some((covered_by, coverage, record)) = record {
                    let remaining = record.expires_ms.saturating_sub(now);
                    let status = if record.expires_ms <= now {
                        "expired"
                    } else if remaining < RENEWAL_MS {
                        "renewing"
                    } else {
                        "active"
                    };
                    (
                        status,
                        "acme",
                        coverage,
                        Some(covered_by),
                        Some(record.issued_ms),
                        Some(record.expires_ms),
                        Some(remaining / DAY_MS),
                    )
                } else if let Some((covered_by, coverage)) = manual {
                    (
                        "installed",
                        "manual",
                        coverage,
                        Some(covered_by),
                        None,
                        None,
                        None,
                    )
                } else if auto_managed && acme_ready {
                    (
                        "provisioning",
                        "acme",
                        if configured_name
                            .as_deref()
                            .is_some_and(|name| name.starts_with("*."))
                        {
                            "wildcard"
                        } else {
                            "exact"
                        },
                        configured_name.or_else(|| Some(hostname.clone())),
                        None,
                        None,
                        None,
                    )
                } else if auto_managed {
                    (
                        "acme_unavailable",
                        "acme",
                        if configured_name
                            .as_deref()
                            .is_some_and(|name| name.starts_with("*."))
                        {
                            "wildcard"
                        } else {
                            "exact"
                        },
                        configured_name.or_else(|| Some(hostname.clone())),
                        None,
                        None,
                        None,
                    )
                } else {
                    ("missing", "none", "none", None, None, None, None)
                };

            json!({
                "hostname": hostname,
                "status": status,
                "source": source,
                "coverage": coverage,
                "covered_by": covered_by,
                "issued_ms": issued_ms,
                "expires_ms": expires_ms,
                "days_remaining": days_remaining,
                "auto_managed": auto_managed,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "enabled": https_enabled,
        "http_enabled": node.cfg.ingress.http.is_some(),
        "acme_enabled": acme.is_some(),
        "acme_ready": acme_ready,
        "include_worker_hostnames": include_worker_hostnames,
        "zone": zone,
        "dns_target": node.cfg.dns.as_ref().map(|cfg| cfg.hostname.clone()),
        "certificates": certificates,
    })
}

fn valid_compatibility_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u16>().ok();
    let month = value[5..7].parse::<u8>().ok();
    let day = value[8..10].parse::<u8>().ok();
    let (Some(year @ 2021..=9999), Some(month @ 1..=12), Some(day)) = (year, month, day) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
}

fn validate_settings_map(values: &BTreeMap<String, String>, label: &str) -> ApiResult<()> {
    if values.len() > 256 {
        return Err(ApiError::bad_request(format!("{label}最多允许 256 项")));
    }
    let mut total = 0usize;
    for (key, value) in values {
        if key.is_empty()
            || key.len() > 256
            || key.as_bytes().iter().any(|byte| byte.is_ascii_control())
        {
            return Err(ApiError::bad_request(format!("{label}中包含无效名称")));
        }
        if value.len() > MAX_CONSOLE_VALUE {
            return Err(ApiError::bad_request(format!(
                "{label}中的单项值超过 1 MiB"
            )));
        }
        total = total.saturating_add(key.len()).saturating_add(value.len());
    }
    if total > MAX_CONSOLE_VALUE {
        return Err(ApiError::bad_request(format!("{label}总大小超过 1 MiB")));
    }
    Ok(())
}

fn apply_worker_settings(
    mut manifest: WorkerManifest,
    digest: [u8; 32],
    request: WorkerSettingsRequest,
) -> ApiResult<WorkerManifest> {
    let WorkerSettingsRequest {
        hostnames,
        env,
        kv_bindings,
        r2_bindings,
        d1_bindings,
        queue_bindings,
        analytics_bindings,
        pipeline_bindings,
        workflow_bindings,
        email_bindings,
        service_bindings,
        binary_bindings,
        crons,
        compatibility_date,
        compatibility_flags,
        required_tags,
    } = request;
    if hostnames.is_none()
        && env.is_none()
        && kv_bindings.is_none()
        && r2_bindings.is_none()
        && d1_bindings.is_none()
        && queue_bindings.is_none()
        && analytics_bindings.is_none()
        && pipeline_bindings.is_none()
        && workflow_bindings.is_none()
        && email_bindings.is_none()
        && service_bindings.is_none()
        && binary_bindings.is_none()
        && crons.is_none()
        && compatibility_date.is_none()
        && compatibility_flags.is_none()
        && required_tags.is_none()
    {
        return Err(ApiError::bad_request("没有需要更新的 Worker 配置"));
    }
    if let Some(hostnames) = hostnames {
        if hostnames.len() > 256 {
            return Err(ApiError::bad_request("一个 Worker 最多绑定 256 个域名"));
        }
        let mut normalized: Vec<String> = hostnames
            .into_iter()
            .map(|hostname| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|hostname| !hostname.is_empty())
            .collect();
        normalized.sort();
        normalized.dedup();
        manifest.hostnames = normalized;
    }
    if let Some(mut env) = env {
        if env.keys().any(|key| key.starts_with("__RF_")) {
            return Err(ApiError::bad_request(
                "不能修改 RandallFlare 保留的环境变量",
            ));
        }
        validate_settings_map(&env, "环境变量")?;
        if let Some(durable_objects) = manifest.env.get(deploy::DO_METADATA_ENV).cloned() {
            env.insert(deploy::DO_METADATA_ENV.into(), durable_objects);
        }
        if let Some(r2) = manifest.env.get(deploy::R2_METADATA_ENV).cloned() {
            env.insert(deploy::R2_METADATA_ENV.into(), r2);
        }
        if let Some(d1) = manifest.env.get(deploy::D1_METADATA_ENV).cloned() {
            env.insert(deploy::D1_METADATA_ENV.into(), d1);
        }
        if let Some(queues) = manifest.env.get(deploy::QUEUE_METADATA_ENV).cloned() {
            env.insert(deploy::QUEUE_METADATA_ENV.into(), queues);
        }
        if let Some(analytics) = manifest.env.get(deploy::ANALYTICS_METADATA_ENV).cloned() {
            env.insert(deploy::ANALYTICS_METADATA_ENV.into(), analytics);
        }
        if let Some(pipelines) = manifest.env.get(deploy::PIPELINE_METADATA_ENV).cloned() {
            env.insert(deploy::PIPELINE_METADATA_ENV.into(), pipelines);
        }
        if let Some(workflows) = manifest.env.get(deploy::WORKFLOW_METADATA_ENV).cloned() {
            env.insert(deploy::WORKFLOW_METADATA_ENV.into(), workflows);
        }
        if let Some(email) = manifest.env.get(deploy::EMAIL_METADATA_ENV).cloned() {
            env.insert(deploy::EMAIL_METADATA_ENV.into(), email);
        }
        if let Some(services) = manifest.env.get(deploy::SERVICE_METADATA_ENV).cloned() {
            env.insert(deploy::SERVICE_METADATA_ENV.into(), services);
        }
        if let Some(binaries) = manifest.env.get(deploy::BINARY_METADATA_ENV).cloned() {
            env.insert(deploy::BINARY_METADATA_ENV.into(), binaries);
        }
        if let Some(secrets) = manifest.env.get(deploy::SECRET_METADATA_ENV).cloned() {
            env.insert(deploy::SECRET_METADATA_ENV.into(), secrets);
        }
        if let Some(flags) = manifest
            .env
            .get(deploy::COMPATIBILITY_FLAGS_METADATA_ENV)
            .cloned()
        {
            env.insert(deploy::COMPATIBILITY_FLAGS_METADATA_ENV.into(), flags);
        }
        if let Some(required_tags) = manifest
            .env
            .get(crate::placement::REQUIRED_TAGS_METADATA_ENV)
            .cloned()
        {
            env.insert(
                crate::placement::REQUIRED_TAGS_METADATA_ENV.into(),
                required_tags,
            );
        }
        manifest.env = env;
    }
    if let Some(required_tags) = required_tags {
        let required_tags = crate::placement::normalize_tags(required_tags)
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        if required_tags.is_empty() {
            manifest
                .env
                .remove(crate::placement::REQUIRED_TAGS_METADATA_ENV);
        } else {
            manifest.env.insert(
                crate::placement::REQUIRED_TAGS_METADATA_ENV.into(),
                serde_json::to_string(&required_tags)?,
            );
        }
    }
    if let Some(kv_bindings) = kv_bindings {
        validate_settings_map(&kv_bindings, "KV 绑定")?;
        manifest.kv_bindings = kv_bindings;
    }
    if let Some(r2_bindings) = r2_bindings {
        validate_settings_map(&r2_bindings, "R2 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, bucket) in &r2_bindings {
            if !identifier(binding) || !valid_name(bucket) {
                return Err(ApiError::bad_request(format!(
                    "R2 绑定 {binding} 或 bucket 名称无效"
                )));
            }
        }
        if r2_bindings.is_empty() {
            manifest.env.remove(deploy::R2_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::R2_METADATA_ENV.into(),
                serde_json::to_string(&r2_bindings)?,
            );
        }
    }
    if let Some(d1_bindings) = d1_bindings {
        validate_settings_map(&d1_bindings, "D1 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, database) in &d1_bindings {
            if !identifier(binding)
                || !valid_name(database)
                || database.starts_with("r2-")
                || database.starts_with("rfdo-")
            {
                return Err(ApiError::bad_request(format!(
                    "D1 绑定 {binding} 或数据库名称无效"
                )));
            }
        }
        if d1_bindings.is_empty() {
            manifest.env.remove(deploy::D1_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::D1_METADATA_ENV.into(),
                serde_json::to_string(&d1_bindings)?,
            );
        }
    }
    if let Some(queue_bindings) = queue_bindings {
        validate_settings_map(&queue_bindings, "Queue 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, queue) in &queue_bindings {
            if !identifier(binding) || !valid_name(queue) {
                return Err(ApiError::bad_request(format!(
                    "Queue 绑定 {binding} 或队列名称无效"
                )));
            }
        }
        if queue_bindings.is_empty() {
            manifest.env.remove(deploy::QUEUE_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::QUEUE_METADATA_ENV.into(),
                serde_json::to_string(&queue_bindings)?,
            );
        }
    }
    if let Some(analytics_bindings) = analytics_bindings {
        validate_settings_map(&analytics_bindings, "Analytics 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, dataset) in &analytics_bindings {
            if !identifier(binding) || !valid_name(dataset) {
                return Err(ApiError::bad_request(format!(
                    "Analytics 绑定 {binding} 或数据集名称无效"
                )));
            }
        }
        if analytics_bindings.is_empty() {
            manifest.env.remove(deploy::ANALYTICS_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::ANALYTICS_METADATA_ENV.into(),
                serde_json::to_string(&analytics_bindings)?,
            );
        }
    }
    if let Some(pipeline_bindings) = pipeline_bindings {
        validate_settings_map(&pipeline_bindings, "Pipeline 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, pipeline) in &pipeline_bindings {
            if !identifier(binding) || !valid_name(pipeline) {
                return Err(ApiError::bad_request(format!(
                    "Pipeline 绑定 {binding} 或 Pipeline 名称无效"
                )));
            }
        }
        if pipeline_bindings.is_empty() {
            manifest.env.remove(deploy::PIPELINE_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::PIPELINE_METADATA_ENV.into(),
                serde_json::to_string(&pipeline_bindings)?,
            );
        }
    }
    if let Some(workflow_bindings) = workflow_bindings {
        validate_settings_map(&workflow_bindings, "Workflow 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, workflow) in &workflow_bindings {
            if !identifier(binding) || !valid_name(workflow) {
                return Err(ApiError::bad_request(format!(
                    "Workflow 绑定 {binding} 或 Workflow 名称无效"
                )));
            }
        }
        if workflow_bindings.is_empty() {
            manifest.env.remove(deploy::WORKFLOW_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::WORKFLOW_METADATA_ENV.into(),
                serde_json::to_string(&workflow_bindings)?,
            );
        }
    }
    if let Some(email_bindings) = email_bindings {
        validate_settings_map(&email_bindings, "Email 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, domain) in &email_bindings {
            if !identifier(binding) || !valid_name(domain) {
                return Err(ApiError::bad_request(format!(
                    "Email 绑定 {binding} 或邮件域资源名称无效"
                )));
            }
        }
        if email_bindings.is_empty() {
            manifest.env.remove(deploy::EMAIL_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::EMAIL_METADATA_ENV.into(),
                serde_json::to_string(&email_bindings)?,
            );
        }
    }
    if let Some(service_bindings) = service_bindings {
        validate_settings_map(&service_bindings, "Service 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, target) in &service_bindings {
            if !identifier(binding) || !valid_name(target) || target == &manifest.name {
                return Err(ApiError::bad_request(format!(
                    "Service 绑定 {binding} 或目标 Worker 名称无效，且不能绑定自身"
                )));
            }
        }
        if service_bindings.is_empty() {
            manifest.env.remove(deploy::SERVICE_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::SERVICE_METADATA_ENV.into(),
                serde_json::to_string(&service_bindings)?,
            );
        }
    }
    if let Some(binary_bindings) = binary_bindings {
        validate_settings_map(&binary_bindings, "Binary Deliver 绑定")?;
        let identifier = |value: &str| {
            let mut chars = value.chars();
            chars.next().is_some_and(|character| {
                character.is_ascii_alphabetic() || matches!(character, '_' | '$')
            }) && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        };
        for (binding, binary) in &binary_bindings {
            if !identifier(binding) || !valid_name(binary) {
                return Err(ApiError::bad_request(format!(
                    "Binary Deliver 绑定 {binding} 或 Binary 资源名称无效"
                )));
            }
        }
        if binary_bindings.is_empty() {
            manifest.env.remove(deploy::BINARY_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::BINARY_METADATA_ENV.into(),
                serde_json::to_string(&binary_bindings)?,
            );
        }
    }
    if let Some(crons) = crons {
        if crons.len() > 256 {
            return Err(ApiError::bad_request(
                "一个 Worker 最多配置 256 个定时触发器",
            ));
        }
        manifest.crons = crons
            .into_iter()
            .map(|cron| cron.trim().to_string())
            .filter(|cron| !cron.is_empty())
            .collect();
    }
    if let Some(compatibility_date) = compatibility_date {
        let compatibility_date = compatibility_date.trim().to_string();
        if !valid_compatibility_date(&compatibility_date) {
            return Err(ApiError::bad_request("兼容日期必须采用 YYYY-MM-DD 格式"));
        }
        manifest.compatibility_date = compatibility_date;
    }
    if let Some(compatibility_flags) = compatibility_flags {
        deploy::validate_compatibility_flags(&compatibility_flags)
            .map_err(|error| ApiError::bad_request(format!("兼容性标志无效：{error:#}")))?;
        if compatibility_flags.is_empty() {
            manifest
                .env
                .remove(deploy::COMPATIBILITY_FLAGS_METADATA_ENV);
        } else {
            manifest.env.insert(
                deploy::COMPATIBILITY_FLAGS_METADATA_ENV.into(),
                serde_json::to_string(&compatibility_flags)?,
            );
        }
    }
    let encrypted_secrets = crate::worker_secret::encrypted_secrets_checked(&manifest)?;
    let mut binding_names = std::collections::BTreeSet::new();
    for name in manifest
        .env
        .keys()
        .filter(|name| !name.starts_with("__RF_"))
        .chain(manifest.kv_bindings.keys())
        .chain(deploy::durable_objects(&manifest).keys())
        .chain(deploy::r2_bindings(&manifest).keys())
        .chain(deploy::d1_bindings(&manifest).keys())
        .chain(deploy::queue_bindings(&manifest).keys())
        .chain(deploy::analytics_bindings(&manifest).keys())
        .chain(deploy::pipeline_bindings(&manifest).keys())
        .chain(deploy::workflow_bindings(&manifest).keys())
        .chain(deploy::email_bindings(&manifest).keys())
        .chain(deploy::service_bindings(&manifest).keys())
        .chain(deploy::binary_bindings(&manifest).keys())
        .chain(encrypted_secrets.keys())
    {
        if !binding_names.insert(name.clone()) {
            return Err(ApiError::bad_request(format!("绑定名称 {name} 被重复使用")));
        }
    }
    manifest.version = manifest.version.saturating_add(1);
    manifest.prev = Some(digest);
    manifest.validate().map_err(|error| {
        ApiError::bad_request(format!("Worker 配置无效：{}", manifest_error_zh(error)))
    })?;
    Ok(manifest)
}

async fn worker_update(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<WorkerSettingsRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let manifest = apply_worker_settings(manifest, digest, request)?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&manifest, state.operator()?);
            state.client.post_manifest(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": manifest.name,
                "version": manifest.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "更新 Worker {} 的配置并发布 v{}",
                    manifest.name, manifest.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSecretPutRequest {
    value: String,
}

async fn worker_secret_list(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let (manifest, _) = current_manifest(&state, &name).await?;
    let secrets = crate::worker_secret::encrypted_secrets_checked(&manifest)?;
    Ok(Json(json!({
        "worker": manifest.name,
        "secrets": secrets.into_keys().collect::<Vec<_>>(),
    })))
}

async fn worker_secret_put(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, binding)): Path<(String, String)>,
    Json(mut request): Json<WorkerSecretPutRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.allows_secret_writes() {
        return Err(ApiError::forbidden(
            "公共控制台只能通过 HTTPS 写入 Worker Secret",
        ));
    }
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let manifest_result = mutate_worker_secret(
        manifest,
        digest,
        &binding,
        Some(&request.value),
        &state.secret,
    );
    request.value.zeroize();
    let manifest = manifest_result?;
    submit_secret_manifest(&state, &principal, manifest, &binding, "写入或替换").await
}

async fn worker_secret_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, binding)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let (manifest, digest) = current_manifest(&state, &name).await?;
    let manifest = mutate_worker_secret(manifest, digest, &binding, None, &state.secret)?;
    submit_secret_manifest(&state, &principal, manifest, &binding, "删除").await
}

fn mutate_worker_secret(
    manifest: WorkerManifest,
    digest: [u8; 32],
    binding: &str,
    value: Option<&str>,
    cluster_secret: &[u8; 32],
) -> ApiResult<WorkerManifest> {
    let result = if let Some(value) = value {
        crate::worker_secret::put_manifest_secret(manifest, digest, cluster_secret, binding, value)
    } else {
        crate::worker_secret::delete_manifest_secret(manifest, digest, binding)
    };
    result.map_err(|error| ApiError::bad_request(format!("Secret 配置无效：{error:#}")))
}

async fn submit_secret_manifest(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    manifest: WorkerManifest,
    binding: &str,
    action: &str,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&manifest, state.operator()?);
            state.client.post_manifest(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": manifest.name,
                "version": manifest.version,
                "secret": binding,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "{action} Worker {} 的加密 Secret {} 并发布 v{}",
                    manifest.name, binding, manifest.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "secret": binding,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn worker_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let version =
                deploy::delete_worker(&name, &state.client, &state.node, state.operator()?).await?;
            Ok(Json(
                json!({ "ok": true, "name": name, "version": version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let manifest = deploy::prepare_delete(&name, &state.client, &state.node).await?;
            let approval = node.management.create_manifest(
                principal.session_id,
                &manifest,
                format!(
                    "删除 Worker {}（生成版本 v{}）",
                    manifest.name, manifest.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": manifest.name,
                "version": manifest.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn approval_status(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let poll = node.management.poll_console(&id, principal.session_id)?;
    Ok(Json(json!({
        "state": poll.state,
        "summary": poll.summary,
        "error": poll.error,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostnameClaimRequest {
    hostname: String,
}

async fn hostname_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let claims = state
        .client
        .resource_heads(&state.node, Some(crate::hostname::HOSTNAME_CLAIM_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = crate::hostname::claim_spec(&view.resource).ok()?;
            Some(json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "hostname": spec.hostname,
                "verified": spec.verified_at_ms.is_some(),
                "verified_at_ms": spec.verified_at_ms,
                "txt_name": spec.txt_name(),
                "txt_value": spec.txt_value(),
            }))
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "claims": claims })))
}

async fn hostname_claim(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<HostnameClaimRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let hostname = request
        .hostname
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !rf_core::manifest::valid_hostname(&hostname) {
        return Err(ApiError::bad_request("请输入有效的小写 DNS 主机名"));
    }
    let head = state
        .client
        .resource_head(
            &state.node,
            crate::hostname::HOSTNAME_CLAIM_KIND,
            &crate::hostname::claim_name(&hostname),
        )
        .await?;
    if let Some(view) = head.as_ref().filter(|view| !view.resource.deleted) {
        let spec = crate::hostname::claim_spec(&view.resource)?;
        return Ok(Json(json!({
            "ok": true,
            "existing": true,
            "hostname": hostname,
            "version": view.resource.version,
            "verified": spec.verified_at_ms.is_some(),
            "txt_name": spec.txt_name(),
            "txt_value": spec.txt_value(),
        })));
    }
    let record = crate::hostname::prepare_claim_after(&hostname, None, None, false, head.as_ref())?;
    let spec = crate::hostname::claim_spec(&record)?;
    let mut response = submit_hostname_resource(
        &state,
        &principal,
        record,
        format!("创建域名 {hostname} 的 DNS 所有权声明"),
    )
    .await?
    .0;
    response["hostname"] = Value::String(hostname);
    response["verified"] = Value::Bool(false);
    response["txt_name"] = Value::String(spec.txt_name());
    response["txt_value"] = Value::String(spec.txt_value());
    Ok(Json(response))
}

async fn hostname_verify(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(hostname): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let head = state
        .client
        .resource_head(
            &state.node,
            crate::hostname::HOSTNAME_CLAIM_KIND,
            &crate::hostname::claim_name(&hostname),
        )
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("域名所有权声明不存在"))?;
    let spec = crate::hostname::claim_spec(&head.resource)?;
    if spec.verified_at_ms.is_some() {
        return Ok(Json(json!({
            "ok": true,
            "existing": true,
            "hostname": hostname,
            "verified": true,
            "version": head.resource.version,
        })));
    }
    let verification = state
        .client
        .hostname_verification(&state.node, &hostname)
        .await?;
    if !verification.verified {
        return Err(ApiError::bad_request(format!(
            "尚未查询到匹配的 TXT 记录；需要在 {} 配置 {}",
            verification.txt_name, verification.txt_value
        )));
    }
    let record = crate::hostname::prepare_claim_after(
        &hostname,
        Some(spec),
        Some(verification.checked_at_ms),
        false,
        Some(&head),
    )?;
    let mut response = submit_hostname_resource(
        &state,
        &principal,
        record,
        format!("确认域名 {hostname} 的 DNS 所有权并启用路由"),
    )
    .await?
    .0;
    response["hostname"] = Value::String(hostname);
    response["verified"] = Value::Bool(true);
    response["verification"] = serde_json::to_value(verification)?;
    Ok(Json(response))
}

async fn hostname_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(hostname): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let head = state
        .client
        .resource_head(
            &state.node,
            crate::hostname::HOSTNAME_CLAIM_KIND,
            &crate::hostname::claim_name(&hostname),
        )
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("域名所有权声明不存在"))?;
    let spec = crate::hostname::claim_spec(&head.resource)?;
    let record =
        crate::hostname::prepare_claim_after(&hostname, Some(spec), None, true, Some(&head))?;
    submit_hostname_resource(
        &state,
        &principal,
        record,
        format!("撤销域名 {hostname} 的所有权和所有公开路由"),
    )
    .await
}

async fn submit_hostname_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Deserialize)]
struct BuildQuery {
    #[serde(default)]
    worker: Option<String>,
}

async fn source_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let sources: Vec<Value> = crate::build::live_sources(node)
        .into_iter()
        .map(|record| {
            let secret = crate::build::webhook_secret(node, &record.source.worker).ok();
            json!({
                "worker": record.source.worker,
                "version": record.source.version,
                "digest": record.digest,
                "repository": record.source.repository,
                "branch": record.source.branch,
                "root": record.source.root,
                "build_command": record.source.build_command,
                "output_dir": record.source.output_dir,
                "use_github_token": record.source.use_github_token,
                "webhook": record.source.webhook,
                "preview_pull_requests": record.source.preview_pull_requests,
                "webhook_path": format!("/api/webhooks/github/{}", record.source.worker),
                "webhook_secret": secret,
            })
        })
        .collect();
    Ok(Json(json!({
        "sources": sources,
        "capabilities": {
            "enabled": node.cfg.build.enabled,
            "git": crate::build::configured_binary(node.cfg.build.git.as_deref(), "git"),
            "sandbox": crate::build::configured_binary(node.cfg.build.sandbox.as_deref(), "bwrap"),
            "github_token_configured": std::env::var_os(&node.cfg.build.github_token_env).is_some(),
            "github_token_env": node.cfg.build.github_token_env,
            "github_app_configured": crate::github::app_configured(node),
            "github_app_webhook_path": "/api/webhooks/github-app",
            "github_ssh_configured": node.cfg.build.github_ssh_key.as_deref().is_some_and(|path| path.is_file())
                && node.cfg.build.github_known_hosts.as_deref().is_some_and(|path| path.is_file()),
            "timeout_seconds": node.cfg.build.timeout_seconds,
        }
    })))
}

async fn source_connect(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(input): Json<crate::build::SourceInput>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let source = crate::build::prepare_source(node, input)?;
    let approval = node.management.create_source(
        principal.session_id,
        &source,
        format!(
            "将 Worker {} 连接至 {} 的 {} 分支",
            source.worker, source.repository, source.branch
        ),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": source.worker,
        "version": source.version,
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn source_disconnect(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let node = state.public_node()?;
    let source = crate::build::prepare_source_delete(node, &name)?;
    let approval = node.management.create_source(
        principal.session_id,
        &source,
        format!("断开 Worker {name} 与 GitHub 仓库的连接"),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": name,
        "version": source.version,
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn worker_build(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let node = state.public_node()?.clone();
    let job = crate::build::start_build(node, &name, "manual", Some(principal.session_id), None)?;
    Ok(Json(json!({ "ok": true, "job": job })))
}

async fn build_list(
    State(state): State<ConsoleState>,
    Query(query): Query<BuildQuery>,
) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    if let Some(worker) = query.worker.as_deref() {
        if !valid_name(worker) {
            return Err(ApiError::bad_request("Worker 名称无效"));
        }
    }
    Ok(Json(json!({
        "jobs": crate::build::build_jobs(node, query.worker.as_deref()),
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn build_get(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let node = state.public_node()?;
    let job =
        crate::build::build_job(node, &id).ok_or_else(|| ApiError::not_found("未找到构建任务"))?;
    Ok(Json(json!({
        "job": job,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn worker_rollback(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, version)): Path<(String, u64)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let node = state.public_node()?;
    let envelopes = node.manifest_log(&name)?;
    let chain = rf_core::manifest::verify_chain(&envelopes, &node.cfg.operator)
        .map_err(|error| ApiError::upstream(error.to_string()))?;
    let historical = chain
        .into_iter()
        .find(|manifest| manifest.version == version && !manifest.deleted)
        .ok_or_else(|| ApiError::not_found("未找到可部署的历史版本"))?;
    let manifest = crate::build::rollback_manifest(node, &historical)?;
    let approval = node.management.create_manifest(
        principal.session_id,
        &manifest,
        format!(
            "将 Worker {name} 回滚至 v{version} 的内容，并发布为 v{}",
            manifest.version
        ),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": name,
        "version": manifest.version,
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerPreviewRequest {
    version: u64,
    #[serde(default = "default_preview_ttl_days")]
    ttl_days: u16,
}

fn default_preview_ttl_days() -> u16 {
    crate::preview::DEFAULT_VERSION_TTL_DAYS
}

async fn worker_preview_list(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let node = state.public_node()?;
    let envelopes = node.manifest_log(&name)?;
    let versions = rf_core::manifest::verify_chain(&envelopes, &node.cfg.operator)
        .map_err(|error| ApiError::upstream(manifest_error_zh(error)))?
        .into_iter()
        .filter(|manifest| !manifest.deleted)
        .map(|manifest| manifest.version)
        .collect::<Vec<_>>();
    let now = now_ms();
    let scheme = state.origin_scheme();
    let previews = crate::preview::preview_records(node, Some(&name))
        .into_iter()
        .map(|(view, spec)| {
            let alias = view.resource.name;
            json!({
                "alias": alias,
                "resource_version": view.resource.version,
                "digest": view.digest,
                "worker": spec.worker,
                "hostname": spec.hostname,
                "url": format!("{scheme}://{}", spec.hostname),
                "manifest_version": spec.manifest.version,
                "source": spec.source,
                "created_at_ms": spec.created_at_ms,
                "expires_at_ms": spec.expires_at_ms,
                "active": spec.active(now),
                "running_on_this_node": node.worker_port(&alias).is_some(),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "worker": name,
        "versions": versions,
        "previews": previews,
        "default_ttl_days": crate::preview::DEFAULT_VERSION_TTL_DAYS,
        "max_ttl_days": 90,
    })))
}

async fn worker_preview_create(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<WorkerPreviewRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let node = state.public_node()?;
    let envelopes = node.manifest_log(&name)?;
    let historical = rf_core::manifest::verify_chain(&envelopes, &node.cfg.operator)
        .map_err(|error| ApiError::upstream(manifest_error_zh(error)))?
        .into_iter()
        .find(|manifest| manifest.version == request.version && !manifest.deleted)
        .ok_or_else(|| ApiError::not_found("未找到可预览的历史版本"))?;
    let record = crate::preview::prepare(
        node,
        historical,
        crate::preview::PreviewSource::Version {
            version: request.version,
        },
        request.ttl_days,
    )?;
    let spec = crate::preview::preview_spec(&record)?;
    let approval = node.management.create_resource(
        principal.session_id,
        &record,
        format!("发布 Worker {name} v{} 的隔离预览", request.version),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": record.name,
        "version": record.version,
        "url": format!("{}://{}", state.origin_scheme(), spec.hostname),
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn worker_preview_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, alias)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&name) || !valid_name(&alias) {
        return Err(ApiError::bad_request("Worker 或预览名称无效"));
    }
    let node = state.public_node()?;
    let current = crate::resource::head(node, crate::preview::PREVIEW_KIND, &alias)
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Worker 预览不存在"))?;
    let spec = crate::preview::preview_spec(&current.resource)?;
    if spec.worker != name {
        return Err(ApiError::not_found("此 Worker 不包含该预览"));
    }
    let record = crate::preview::prepare_delete(node, &alias)?;
    let approval = node.management.create_resource(
        principal.session_id,
        &record,
        format!("停止并删除 Worker {name} 的预览 {alias}"),
    )?;
    Ok(Json(json!({
        "ok": true,
        "pending_approval": true,
        "name": alias,
        "version": record.version,
        "approval": approval,
        "approve_node": node.cfg.peer_api_advertise().to_string(),
    })))
}

async fn github_webhook(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) || body.len() > 2 * 1024 * 1024 {
        return Err(ApiError::bad_request("Webhook 请求无效"));
    }
    let node = state.public_node()?.clone();
    let source = crate::build::source_head(&node, &name)
        .filter(|record| !record.source.deleted && record.source.webhook)
        .ok_or_else(|| ApiError::not_found("此 Worker 尚未启用 GitHub Webhook"))?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let secret = crate::build::webhook_secret(&node, &name)?;
    if !crate::build::verify_webhook(&secret, signature, &body) {
        return Err(ApiError::unauthorized("GitHub Webhook 签名无效"));
    }
    let event = headers
        .get("x-github-event")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if event == "ping" {
        return Ok(Json(json!({ "ok": true, "pong": true })));
    }
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("GitHub Webhook 的 JSON 数据无效"))?;
    let delivery = headers
        .get("x-github-delivery")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .unwrap_or("unknown");
    let installation_id = payload
        .pointer("/installation/id")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    let result = dispatch_github_payload(
        node,
        &name,
        source,
        event,
        &payload,
        delivery,
        installation_id,
    )?;
    Ok(Json(result))
}

async fn github_app_webhook(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    if body.len() > 2 * 1024 * 1024 {
        return Err(ApiError::bad_request("GitHub App Webhook 请求过大"));
    }
    let node = state.public_node()?.clone();
    let secret = crate::github::webhook_secret(&node)?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !crate::github::verify_webhook(secret.as_bytes(), signature, &body) {
        return Err(ApiError::unauthorized("GitHub App Webhook 签名无效"));
    }
    let event = headers
        .get("x-github-event")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if event == "ping" {
        return Ok(Json(json!({ "ok": true, "pong": true })));
    }
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("GitHub App Webhook 的 JSON 数据无效"))?;
    let delivery = headers
        .get("x-github-delivery")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .unwrap_or("unknown");
    let repository = payload
        .pointer("/repository/clone_url")
        .and_then(Value::as_str)
        .and_then(|value| crate::build::normalize_github_repository(value).ok())
        .ok_or_else(|| ApiError::bad_request("GitHub App Webhook 缺少有效的仓库身份"))?;
    let installation_id = payload
        .pointer("/installation/id")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| ApiError::bad_request("GitHub App Webhook 缺少安装 ID"))?;
    let sources = crate::build::live_sources(&node)
        .into_iter()
        .filter(|record| {
            record.source.webhook
                && crate::github::repository_slug(&record.source.repository).ok()
                    == crate::github::repository_slug(&repository).ok()
        })
        .collect::<Vec<_>>();
    if sources.is_empty() {
        return Err(ApiError::not_found(
            "此仓库尚未连接任何启用 Webhook 的 Worker",
        ));
    }
    let mut results = Vec::with_capacity(sources.len());
    for source in sources {
        let name = source.source.worker.clone();
        let result = dispatch_github_payload(
            node.clone(),
            &name,
            source,
            event,
            &payload,
            delivery,
            Some(installation_id),
        )?;
        results.push(json!({ "worker": name, "result": result }));
    }
    Ok(Json(json!({ "ok": true, "workers": results })))
}

fn dispatch_github_payload(
    node: Arc<Node>,
    name: &str,
    source: crate::build::SourceRecord,
    event: &str,
    payload: &Value,
    delivery: &str,
    installation_id: Option<u64>,
) -> ApiResult<Value> {
    let repository = payload
        .pointer("/repository/clone_url")
        .and_then(Value::as_str)
        .and_then(|value| crate::build::normalize_github_repository(value).ok())
        .ok_or_else(|| ApiError::bad_request("GitHub Webhook 缺少有效的仓库身份"))?;
    if crate::github::repository_slug(&repository)?
        != crate::github::repository_slug(&source.source.repository)?
    {
        return Err(ApiError::bad_request("Webhook 仓库与 Worker 代码源不一致"));
    }

    let (trigger, commit, requested_ref, preview_source, ttl_days) = match event {
        "push" => {
            let git_ref = payload
                .get("ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if git_ref != format!("refs/heads/{}", source.source.branch) {
                return Ok(json!({ "ok": true, "ignored": "branch" }));
            }
            if payload.get("deleted").and_then(Value::as_bool) == Some(true) {
                return Ok(json!({ "ok": true, "ignored": "deleted branch" }));
            }
            let commit =
                webhook_commit(payload, "/after", "GitHub 推送事件缺少有效的 after 提交值")?;
            (format!("github:{delivery}"), commit, None, None, 0)
        }
        "pull_request" => {
            if !source.source.preview_pull_requests {
                return Ok(json!({ "ok": true, "ignored": "pull request previews disabled" }));
            }
            let action = payload
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(action, "opened" | "reopened" | "synchronize") {
                return Ok(json!({ "ok": true, "ignored": "pull request action" }));
            }
            if payload
                .pointer("/pull_request/base/ref")
                .and_then(Value::as_str)
                != Some(source.source.branch.as_str())
            {
                return Ok(json!({ "ok": true, "ignored": "base branch" }));
            }
            let number = payload
                .get("number")
                .and_then(Value::as_u64)
                .filter(|number| *number > 0 && *number <= 1_000_000_000)
                .ok_or_else(|| ApiError::bad_request("Pull Request 编号无效"))?;
            let commit = webhook_commit(
                payload,
                "/pull_request/head/sha",
                "Pull Request 缺少有效的 head 提交值",
            )?;
            let branch = payload
                .pointer("/pull_request/head/ref")
                .and_then(Value::as_str)
                .filter(|branch| !branch.is_empty() && branch.len() <= 255)
                .ok_or_else(|| ApiError::bad_request("Pull Request 分支名称无效"))?
                .to_string();
            (
                format!("github-pr:{delivery}"),
                commit.clone(),
                Some(format!("refs/pull/{number}/head")),
                Some(crate::preview::PreviewSource::PullRequest {
                    number,
                    commit,
                    branch,
                }),
                crate::preview::DEFAULT_PULL_REQUEST_TTL_DAYS,
            )
        }
        _ => {
            return Err(ApiError::bad_request(
                "仅支持 GitHub 推送与 Pull Request Webhook",
            ))
        }
    };
    if let Some(job) = crate::build::build_jobs(&node, Some(name))
        .into_iter()
        .find(|job| job.trigger == trigger)
    {
        return Ok(json!({ "ok": true, "duplicate": true, "job": job }));
    }
    let pull_request = preview_source.as_ref().and_then(|source| match source {
        crate::preview::PreviewSource::PullRequest { number, .. } => Some(*number),
        _ => None,
    });
    let preview = if let (Some(reference), Some(preview_source)) = (requested_ref, preview_source) {
        Some(crate::build::PreviewBuildRequest {
            commit: commit.clone(),
            git_ref: reference,
            source: preview_source,
            ttl_days,
        })
    } else {
        None
    };
    let job = crate::build::start_github_build(
        node,
        name,
        trigger,
        commit,
        None,
        preview,
        crate::github::GithubContext {
            repository,
            installation_id,
            pull_request,
            check_run_id: None,
            comment_id: None,
        },
    )?;
    Ok(json!({ "ok": true, "job": job }))
}

fn webhook_commit(payload: &Value, pointer: &str, message: &'static str) -> ApiResult<String> {
    payload
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_string)
        .ok_or_else(|| ApiError::bad_request(message))
}

async fn worker_log(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let envelopes = state.client.worker_log(&state.node, &name).await?;
    let signer = if envelopes.is_empty() {
        None
    } else {
        Some(configured_operator(&state).await?)
    };
    let chain = match signer {
        Some(signer) => rf_core::manifest::verify_chain(&envelopes, &signer)
            .map_err(|error| ApiError::upstream(error.to_string()))?,
        None => Vec::new(),
    };
    let entries: Vec<Value> = chain
        .iter()
        .zip(&envelopes)
        .map(|(manifest, envelope)| manifest_log_entry(manifest, envelope))
        .collect();
    Ok(Json(json!({
        "worker": name,
        "chain_ok": true,
        "signer": signer.map(|value| value.to_string()),
        "entries": entries,
    })))
}

#[derive(Deserialize)]
struct RuntimeLogQuery {
    #[serde(default = "default_log_limit")]
    limit: usize,
}

fn default_log_limit() -> usize {
    300
}

async fn cluster_api_candidates(state: &ConsoleState) -> ApiResult<Vec<String>> {
    Ok(state.client.live_api_candidates(&state.node).await?)
}

async fn worker_runtime_log(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<RuntimeLogQuery>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let limit = query.limit.clamp(1, 1_000);
    let candidates = cluster_api_candidates(&state).await?;
    let results = futures_util::future::join_all(candidates.iter().map(|base| {
        let client = state.client.clone();
        let base = base.clone();
        let name = name.clone();
        async move {
            (
                base.clone(),
                client.worker_runtime_logs(&base, &name, limit).await,
            )
        }
    }))
    .await;
    let mut lines = Vec::new();
    let mut nodes = Vec::new();
    let mut unavailable = Vec::new();
    for (base, result) in results {
        match result {
            Ok(snapshot) => {
                nodes.push(json!({
                    "id": snapshot.node.clone(),
                    "label": snapshot.label.clone(),
                    "api": base,
                }));
                lines.extend(snapshot.lines.into_iter().map(|line| {
                    json!({
                        "at_ms": line.at_ms,
                        "version": line.version,
                        "stream": line.stream,
                        "message": line.message,
                        "node": snapshot.node,
                        "node_label": snapshot.label,
                    })
                }));
            }
            Err(_) => unavailable.push(base),
        }
    }
    if nodes.is_empty() {
        return Err(ApiError::upstream("所有存活节点的运行日志均暂时不可用"));
    }
    lines.sort_by_key(|line| line.get("at_ms").and_then(Value::as_u64).unwrap_or(0));
    if lines.len() > limit {
        lines.drain(..lines.len() - limit);
    }
    Ok(Json(json!({
        "worker": name,
        "nodes": nodes,
        "unavailable_nodes": unavailable,
        "lines": lines,
    })))
}

#[derive(Deserialize)]
struct WorkerRequestLogQuery {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    status: String,
    #[serde(default = "default_request_log_limit")]
    limit: usize,
}

fn default_request_log_limit() -> usize {
    200
}

async fn worker_request_log(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<WorkerRequestLogQuery>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    if query.hostname.len() > 253 {
        return Err(ApiError::bad_request("域名筛选条件过长"));
    }
    let status_class = match query.status.trim().trim_end_matches("xx") {
        "" | "all" => None,
        "2" => Some(2),
        "3" => Some(3),
        "4" => Some(4),
        "5" => Some(5),
        _ => return Err(ApiError::bad_request("状态筛选必须是 2xx、3xx、4xx 或 5xx")),
    };
    let hostname = (!query.hostname.is_empty()).then_some(query.hostname.as_str());
    let limit = query.limit.clamp(1, 1_000);
    let candidates = cluster_api_candidates(&state).await?;
    let results = futures_util::future::join_all(candidates.iter().map(|base| {
        let client = state.client.clone();
        let base = base.clone();
        let name = name.clone();
        let hostname = hostname.map(str::to_string);
        async move {
            (
                base.clone(),
                client
                    .worker_request_logs(&base, &name, hostname.as_deref(), status_class, limit)
                    .await,
            )
        }
    }))
    .await;

    let mut snapshots = Vec::new();
    let mut nodes = Vec::new();
    let mut unavailable = Vec::new();
    for (base, result) in results {
        match result {
            Ok(snapshot) => {
                nodes.push(json!({
                    "id": snapshot.node,
                    "label": snapshot.label,
                    "api": base,
                }));
                snapshots.push(snapshot);
            }
            Err(_) => unavailable.push(base),
        }
    }
    if nodes.is_empty() {
        return Err(ApiError::upstream("所有存活节点的请求日志均暂时不可用"));
    }
    let merged = crate::observability::merge_snapshots(&snapshots, limit);
    Ok(Json(json!({
        "worker": name,
        "nodes": nodes,
        "unavailable_nodes": unavailable,
        "hostnames": merged.hostnames,
        "hours": merged.hours,
        "entries": merged.entries,
        "privacy": "仅记录方法、无查询参数的路径、状态码与耗时；不记录请求体、请求头、Cookie、IP 或 User-Agent。",
    })))
}

#[derive(Deserialize)]
struct WorkerCronRunsQuery {
    #[serde(default)]
    dlq: bool,
    #[serde(default = "default_cron_runs_limit")]
    limit: usize,
}

fn default_cron_runs_limit() -> usize {
    100
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCronFireRequest {
    #[serde(default)]
    expression: Option<String>,
}

async fn worker_cron_runs(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<WorkerCronRunsQuery>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&name) {
        return Err(ApiError::bad_request("Worker 名称无效"));
    }
    let runs = state
        .client
        .cron_runs(&state.node, &name, query.dlq, query.limit)
        .await?;
    Ok(Json(json!({ "worker": name, "runs": runs })))
}

async fn worker_cron_fire(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<WorkerCronFireRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let run = state
        .client
        .cron_fire(&state.node, &name, request.expression.as_deref())
        .await?;
    Ok(Json(json!({ "ok": true, "run": run })))
}

async fn worker_cron_replay(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let run = state
        .client
        .cron_replay(&state.node, &name, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Cron DLQ 记录不存在"))?;
    Ok(Json(json!({ "ok": true, "run": run })))
}

async fn worker_cron_delete_dlq(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state
        .client
        .cron_delete_dlq(&state.node, &name, &id)
        .await?
    {
        return Err(ApiError::not_found("Cron DLQ 记录不存在"));
    }
    Ok(Json(json!({ "ok": true })))
}

fn manifest_log_entry(manifest: &WorkerManifest, envelope: &rf_core::envelope::Envelope) -> Value {
    json!({
        "version": manifest.version,
        "deleted": manifest.deleted,
        "digest": hex::encode(envelope.digest()),
        "previous": manifest.prev.map(hex::encode),
        "hostnames": manifest.hostnames,
        "modules": manifest.modules.len(),
        "assets": manifest.assets.len(),
    })
}

#[derive(Deserialize)]
struct KvQuery {
    namespace: String,
    #[serde(default)]
    prefix: String,
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct KvValueQuery {
    namespace: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KvWriteRequest {
    namespace: String,
    key: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    value_base64: Option<String>,
    #[serde(default)]
    expiration_ttl: Option<u64>,
    #[serde(default)]
    expiration: Option<u64>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvTransferEntry {
    key: String,
    value_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expiration: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Debug, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvTransfer {
    #[serde(default = "kv_transfer_version")]
    version: u8,
    namespace: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prefix: String,
    entries: Vec<KvTransferEntry>,
}

fn kv_transfer_version() -> u8 {
    1
}

fn validate_kv(namespace: &str, key: Option<&str>, writing: bool) -> ApiResult<()> {
    if namespace.trim().is_empty() || namespace.len() > 256 {
        return Err(ApiError::bad_request("命名空间长度必须为 1 至 256 个字符"));
    }
    if writing && namespace.starts_with("__rf") {
        return Err(ApiError::forbidden("内部 __rf 命名空间在控制台中为只读"));
    }
    if let Some(key) = key {
        if key.is_empty() || key.len() > 1024 {
            return Err(ApiError::bad_request("键名长度必须为 1 至 1024 个字符"));
        }
    }
    Ok(())
}

async fn kv_list(
    State(state): State<ConsoleState>,
    Query(query): Query<KvQuery>,
) -> ApiResult<Json<Value>> {
    validate_kv(&query.namespace, None, false)?;
    let page = state
        .client
        .kv_list_page(
            &state.node,
            &query.namespace,
            &query.prefix,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({
        "namespace": query.namespace,
        "prefix": query.prefix,
        "entries": page.entries,
        "list_complete": page.list_complete,
        "cursor": page.cursor,
    })))
}

async fn kv_get(
    State(state): State<ConsoleState>,
    Query(query): Query<KvValueQuery>,
) -> ApiResult<Json<Value>> {
    validate_kv(&query.namespace, Some(&query.key), false)?;
    let value = state
        .client
        .kv_get_with_metadata(&state.node, &query.namespace, &query.key)
        .await?
        .ok_or_else(|| ApiError::not_found("未找到该 KV 键"))?;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&value.value_base64)
        .map_err(|_| ApiError::upstream("节点返回了无效的 KV Base64 数据"))?;
    let utf8 = String::from_utf8(bytes).ok();
    Ok(Json(json!({
        "namespace": query.namespace,
        "key": query.key,
        "text": utf8,
        "base64": value.value_base64,
        "expiration": value.expires_at_ms.map(|millis| millis / 1000),
        "metadata": value.metadata,
    })))
}

async fn kv_put(
    State(state): State<ConsoleState>,
    Json(request): Json<KvWriteRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    validate_kv(&request.namespace, Some(&request.key), true)?;
    let value = decode_kv_write_value(request.value, request.value_base64)?;
    validate_kv_value_and_metadata(&value, request.metadata.as_ref())?;
    let expires_at_ms = kv_expiration_ms(request.expiration_ttl, request.expiration)?;
    state
        .client
        .kv_put_with_metadata(
            &state.node,
            &request.namespace,
            &request.key,
            value,
            expires_at_ms,
            request.metadata.as_ref(),
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

async fn kv_delete(
    State(state): State<ConsoleState>,
    Query(query): Query<KvValueQuery>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    validate_kv(&query.namespace, Some(&query.key), true)?;
    state
        .client
        .kv_delete(&state.node, &query.namespace, &query.key)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

fn decode_kv_write_value(
    value: Option<String>,
    value_base64: Option<String>,
) -> ApiResult<Vec<u8>> {
    match (value, value_base64) {
        (Some(value), None) => Ok(value.into_bytes()),
        (None, Some(encoded)) => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| ApiError::bad_request("KV 值不是有效的 Base64 数据"))
        }
        (Some(_), Some(_)) => Err(ApiError::bad_request(
            "KV 写入只能提供 value 或 value_base64 之一",
        )),
        (None, None) => Err(ApiError::bad_request("KV 写入缺少值")),
    }
}

fn validate_kv_value_and_metadata(value: &[u8], metadata: Option<&Value>) -> ApiResult<()> {
    if value.len() > MAX_KV_VALUE {
        return Err(ApiError::bad_request("KV 单个值最大为 25 MiB"));
    }
    if metadata.is_some_and(|metadata| {
        serde_json::to_vec(metadata)
            .map(|raw| raw.len() > 1024)
            .unwrap_or(true)
    }) {
        return Err(ApiError::bad_request("KV metadata 最大为 1,024 字节"));
    }
    Ok(())
}

fn kv_expiration_ms(
    ttl_seconds: Option<u64>,
    expiration_seconds: Option<u64>,
) -> ApiResult<Option<u64>> {
    if ttl_seconds.is_some() && expiration_seconds.is_some() {
        return Err(ApiError::bad_request(
            "expirationTtl 与 expiration 不能同时设置",
        ));
    }
    let now = crate::node::now_ms();
    if let Some(ttl) = ttl_seconds {
        if ttl < 60 {
            return Err(ApiError::bad_request("KV TTL 至少为 60 秒"));
        }
        return Ok(Some(now.saturating_add(ttl.saturating_mul(1000))));
    }
    if let Some(expiration) = expiration_seconds {
        let expiration = expiration.saturating_mul(1000);
        if expiration < now.saturating_add(60_000) {
            return Err(ApiError::bad_request("KV 绝对过期时间至少在 60 秒之后"));
        }
        return Ok(Some(expiration));
    }
    Ok(None)
}

async fn kv_export(
    State(state): State<ConsoleState>,
    Query(query): Query<KvQuery>,
) -> ApiResult<Response> {
    validate_kv(&query.namespace, None, false)?;
    let mut entries = Vec::new();
    let mut cursor = None;
    let mut total = 0usize;
    loop {
        let page = state
            .client
            .kv_list_page(
                &state.node,
                &query.namespace,
                &query.prefix,
                cursor.as_deref(),
                1_000,
            )
            .await?;
        for item in page.entries {
            if entries.len() >= MAX_KV_TRANSFER_ENTRIES {
                return Err(ApiError::bad_request("KV 导出最多包含 10,000 个键"));
            }
            let Some(value) = state
                .client
                .kv_get_with_metadata(&state.node, &query.namespace, &item.key)
                .await?
            else {
                continue;
            };
            use base64::Engine as _;
            let raw_len = base64::engine::general_purpose::STANDARD
                .decode(&value.value_base64)
                .map_err(|_| ApiError::upstream("节点返回了无效的 KV Base64 数据"))?
                .len();
            total = total.saturating_add(raw_len);
            if total > MAX_KV_TRANSFER {
                return Err(ApiError::bad_request("KV 导出值总量最大为 64 MiB"));
            }
            entries.push(KvTransferEntry {
                key: item.key,
                value_base64: value.value_base64,
                expiration: value.expires_at_ms.map(|millis| millis / 1000),
                metadata: value.metadata,
            });
        }
        if page.list_complete {
            break;
        }
        let next = page
            .cursor
            .filter(|next| cursor.as_ref() != Some(next))
            .ok_or_else(|| ApiError::upstream("KV 节点返回了无进展游标"))?;
        cursor = Some(next);
    }
    let transfer = KvTransfer {
        version: kv_transfer_version(),
        namespace: query.namespace,
        prefix: query.prefix,
        entries,
    };
    let bytes = serde_json::to_vec_pretty(&transfer)?;
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=randallflare-kv.json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn kv_import(
    State(state): State<ConsoleState>,
    Json(transfer): Json<KvTransfer>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    validate_kv(&transfer.namespace, None, true)?;
    if transfer.version != kv_transfer_version() {
        return Err(ApiError::bad_request("不支持此 KV 导入文件版本"));
    }
    if transfer.entries.is_empty() || transfer.entries.len() > MAX_KV_TRANSFER_ENTRIES {
        return Err(ApiError::bad_request("KV 导入必须包含 1 至 10,000 个键"));
    }
    use base64::Engine as _;
    let now = crate::node::now_ms();
    let mut decoded = Vec::with_capacity(transfer.entries.len());
    let mut keys = std::collections::BTreeSet::new();
    let mut total = 0usize;
    let mut expired = 0usize;
    for entry in transfer.entries {
        validate_kv(&transfer.namespace, Some(&entry.key), true)?;
        if !keys.insert(entry.key.clone()) {
            return Err(ApiError::bad_request(format!(
                "KV 导入包含重复键：{}",
                entry.key
            )));
        }
        let value = base64::engine::general_purpose::STANDARD
            .decode(&entry.value_base64)
            .map_err(|_| {
                ApiError::bad_request(format!("KV 键 {} 的值不是有效 Base64", entry.key))
            })?;
        validate_kv_value_and_metadata(&value, entry.metadata.as_ref())?;
        total = total.saturating_add(value.len());
        if total > MAX_KV_TRANSFER {
            return Err(ApiError::bad_request("KV 导入值总量最大为 64 MiB"));
        }
        let expires_at_ms = entry.expiration.map(|seconds| seconds.saturating_mul(1000));
        if expires_at_ms.is_some_and(|expires| expires <= now) {
            expired += 1;
            continue;
        }
        if expires_at_ms.is_some_and(|expires| expires < now.saturating_add(60_000)) {
            return Err(ApiError::bad_request(format!(
                "KV 键 {} 的过期时间不足 60 秒",
                entry.key
            )));
        }
        decoded.push((entry.key, value, expires_at_ms, entry.metadata));
    }
    for (key, value, expires_at_ms, metadata) in &decoded {
        state
            .client
            .kv_put_with_metadata(
                &state.node,
                &transfer.namespace,
                key,
                value.clone(),
                *expires_at_ms,
                metadata.as_ref(),
            )
            .await?;
    }
    Ok(Json(json!({
        "ok": true,
        "namespace": transfer.namespace,
        "imported": decoded.len(),
        "expired_skipped": expired,
        "bytes": total,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct D1CreateRequest {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct D1ExecRequest {
    name: String,
    sql: String,
    #[serde(default = "empty_array")]
    params: Value,
}

#[derive(Deserialize)]
struct D1InfoQuery {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct D1BatchRequest {
    name: String,
    statements: Vec<crate::d1::Statement>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct D1ImportRequest {
    name: String,
    sql: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct D1BackupRequest {
    name: String,
    bucket: String,
    #[serde(default = "console_default_d1_backup_prefix")]
    prefix: String,
}

fn console_default_d1_backup_prefix() -> String {
    "d1-backups".into()
}

fn empty_array() -> Value {
    json!([])
}

async fn d1_create(
    State(state): State<ConsoleState>,
    Json(request): Json<D1CreateRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&request.name) {
        return Err(ApiError::bad_request(
            "数据库名称须由 1 至 63 个小写字母、数字或连字符组成",
        ));
    }
    let raw = state
        .client
        .post(
            &state.node,
            "/v1/d1/create",
            json!({ "name": request.name }).to_string().into_bytes(),
        )
        .await?;
    Ok(Json(serde_json::from_slice(&raw)?))
}

async fn d1_backup(
    State(state): State<ConsoleState>,
    Json(request): Json<D1BackupRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let backup = state
        .client
        .d1_backup(&state.node, &request.name, &request.bucket, &request.prefix)
        .await?;
    Ok(Json(serde_json::to_value(backup)?))
}

async fn d1_exec(
    State(state): State<ConsoleState>,
    Json(request): Json<D1ExecRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&request.name) {
        return Err(ApiError::bad_request("数据库名称无效"));
    }
    if request.sql.trim().is_empty() || request.sql.len() > MAX_CONSOLE_VALUE {
        return Err(ApiError::bad_request(
            "SQL 长度必须介于 1 字节与 1 MiB 之间",
        ));
    }
    if !request.params.is_array() {
        return Err(ApiError::bad_request("参数必须是 JSON 数组"));
    }
    let result = state
        .client
        .d1_exec(&state.node, &request.name, &request.sql, request.params)
        .await?;
    Ok(Json(result))
}

async fn d1_batch(
    State(state): State<ConsoleState>,
    Json(request): Json<D1BatchRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    validate_d1_batch(&request.name, &request.statements)?;
    let result = state
        .client
        .d1_batch(&state.node, &request.name, &request.statements)
        .await?;
    Ok(Json(result))
}

async fn d1_info(
    State(state): State<ConsoleState>,
    Query(query): Query<D1InfoQuery>,
) -> ApiResult<Json<Value>> {
    if !valid_name(&query.name) {
        return Err(ApiError::bad_request("数据库名称无效"));
    }
    let tables_result = state
        .client
        .d1_exec(
            &state.node,
            &query.name,
            "SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != '_rf_applied' ORDER BY name COLLATE NOCASE LIMIT 201",
            json!([]),
        )
        .await?;
    let table_rows = tables_result["rows"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if table_rows.len() > 200 {
        return Err(ApiError::bad_request("D1 schema 浏览最多显示 200 张表"));
    }
    let mut statements = Vec::with_capacity(table_rows.len() * 3);
    let mut names = Vec::with_capacity(table_rows.len());
    for row in &table_rows {
        let name = row
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::upstream("D1 schema 返回了无效表名"))?
            .to_string();
        if name.len() > 1000 || name.as_bytes().contains(&0) {
            return Err(ApiError::upstream("D1 schema 包含无效表名"));
        }
        let quoted = quote_sql_identifier(&name);
        names.push(name);
        statements.push(crate::d1::Statement {
            sql: "SELECT cid, name, type, \"notnull\" AS not_null, dflt_value, pk FROM pragma_table_info(?1) ORDER BY cid".into(),
            params: vec![names.last().cloned().unwrap_or_default().into()],
        });
        statements.push(crate::d1::Statement {
            sql: format!("SELECT COUNT(*) AS count FROM {quoted}"),
            params: vec![],
        });
        statements.push(crate::d1::Statement {
            sql: format!("SELECT * FROM {quoted} LIMIT 50"),
            params: vec![],
        });
    }
    let mut details = Vec::with_capacity(names.len());
    let mut cursor = 0usize;
    let mut flat_results = Vec::with_capacity(statements.len());
    for chunk in statements.chunks(99) {
        let output = state
            .client
            .d1_batch(&state.node, &query.name, chunk)
            .await?;
        let results = output["batch"]
            .as_array()
            .ok_or_else(|| ApiError::upstream("D1 schema 批处理缺少结果"))?;
        flat_results.extend(results.iter().cloned());
    }
    let mut total_rows = 0u64;
    for (index, name) in names.into_iter().enumerate() {
        let columns = flat_results
            .get(cursor)
            .and_then(|result| result["rows"].as_array())
            .cloned()
            .unwrap_or_default();
        let count = flat_results
            .get(cursor + 1)
            .and_then(|result| result["rows"].as_array())
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let sample = flat_results
            .get(cursor + 2)
            .and_then(|result| result["rows"].as_array())
            .cloned()
            .unwrap_or_default();
        cursor += 3;
        total_rows = total_rows.saturating_add(count);
        details.push(json!({
            "name": name,
            "sql": table_rows.get(index).and_then(|row| row.get("sql")).cloned(),
            "columns": columns,
            "row_count": count,
            "sample": sample,
        }));
    }
    let metric_statements = [
        "PRAGMA page_count",
        "PRAGMA page_size",
        "PRAGMA freelist_count",
        "PRAGMA journal_mode",
        "PRAGMA user_version",
    ]
    .into_iter()
    .map(|sql| crate::d1::Statement {
        sql: sql.into(),
        params: vec![],
    })
    .collect::<Vec<_>>();
    let metric_output = state
        .client
        .d1_batch(&state.node, &query.name, &metric_statements)
        .await?;
    let metrics = metric_output["batch"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let metric = |index: usize, field: &str| {
        metrics
            .get(index)
            .and_then(|result| result["rows"].as_array())
            .and_then(|rows| rows.first())
            .and_then(|row| row.get(field))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let page_count = metric(0, "page_count").as_u64().unwrap_or(0);
    let page_size = metric(1, "page_size").as_u64().unwrap_or(0);
    let table_count = details.len();
    Ok(Json(json!({
        "name": query.name,
        "tables": details,
        "summary": {
            "table_count": table_count,
            "row_count": total_rows,
            "page_count": page_count,
            "page_size": page_size,
            "size_bytes": page_count.saturating_mul(page_size),
            "freelist_count": metric(2, "freelist_count"),
            "journal_mode": metric(3, "journal_mode"),
            "user_version": metric(4, "user_version"),
        }
    })))
}

fn quote_sql_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

async fn d1_import(
    State(state): State<ConsoleState>,
    Json(request): Json<D1ImportRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !valid_name(&request.name) {
        return Err(ApiError::bad_request("数据库名称无效"));
    }
    if request.sql.trim().is_empty() || request.sql.len() > MAX_D1_IMPORT {
        return Err(ApiError::bad_request(
            "D1 SQL 导入必须介于 1 字节和 64 MiB 之间",
        ));
    }
    let mut statements = crate::d1bind::import_statements(&request.sql)
        .map_err(|error| ApiError::bad_request(format!("无法解析 D1 SQL：{error}")))?;
    if statements.is_empty() || statements.len() > MAX_D1_IMPORT_STATEMENTS {
        return Err(ApiError::bad_request(
            "D1 导入必须包含 1 至 10,000 条非事务控制语句",
        ));
    }
    for statement in &statements {
        if statement.sql.len() > MAX_CONSOLE_VALUE {
            return Err(ApiError::bad_request("D1 导入的单条 SQL 最大为 1 MiB"));
        }
    }
    let started = Instant::now();
    let mut changes = 0u64;
    let batch_count = statements.len().div_ceil(100);
    for chunk in statements.chunks_mut(100) {
        let output = state
            .client
            .d1_batch(&state.node, &request.name, chunk)
            .await?;
        changes = changes.saturating_add(output["rows_affected"].as_u64().unwrap_or(0));
    }
    Ok(Json(json!({
        "ok": true,
        "name": request.name,
        "statements": statements.len(),
        "batches": batch_count,
        "changes": changes,
        "duration_ms": started.elapsed().as_millis(),
    })))
}

async fn d1_export(
    State(state): State<ConsoleState>,
    Query(query): Query<D1InfoQuery>,
) -> ApiResult<Response> {
    if !valid_name(&query.name) {
        return Err(ApiError::bad_request("数据库名称无效"));
    }
    let bytes = state.client.d1_export(&state.node, &query.name).await?;
    if !bytes.starts_with(b"SQLite format 3\0") {
        return Err(ApiError::upstream("D1 主节点返回的快照不是 SQLite 3 文件"));
    }
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.sqlite3"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}.sqlite\"", query.name))
            .map_err(|_| ApiError::upstream("D1 导出文件名无效"))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct R2BucketRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    public_access: bool,
    #[serde(default = "default_storage_backend")]
    storage_backend: String,
    #[serde(default)]
    rclone_remote: String,
    #[serde(default)]
    rclone_prefix: String,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    max_objects: Option<u64>,
    #[serde(default)]
    expire_objects_after_days: Option<u32>,
    #[serde(default)]
    cors_origins: Vec<String>,
    #[serde(default)]
    hostnames: Vec<String>,
}

fn default_storage_backend() -> String {
    "local".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoragePolicyRequest {
    new_bucket_backend: crate::storage_policy::NewBucketBackend,
    #[serde(default)]
    shard_remotes: Vec<String>,
    #[serde(default)]
    shard_prefix: String,
    #[serde(default)]
    d1_backups: Vec<crate::storage_policy::D1BackupPolicy>,
}

async fn storage_get(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    Ok(Json(state.client.storage_status(&state.node).await?))
}

async fn storage_probe(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let status = state.client.status(&state.node).await?;
    let mut targets: Vec<(String, String, String)> = vec![(
        status["node"].as_str().unwrap_or("current").to_string(),
        status["label"].as_str().unwrap_or("当前节点").to_string(),
        state.node.to_string(),
    )];
    for peer in status["peers"].as_array().into_iter().flatten() {
        if let (Some(id), Some(api)) = (
            peer.get("id").and_then(Value::as_str),
            peer.get("api").and_then(Value::as_str),
        ) {
            targets.push((
                id.to_string(),
                peer.get("label")
                    .and_then(Value::as_str)
                    .unwrap_or(id)
                    .to_string(),
                api.to_string(),
            ));
        }
    }
    targets.sort_by(|left, right| left.0.cmp(&right.0));
    targets.dedup_by(|left, right| left.0 == right.0);
    let mut nodes: Vec<(String, Value)> =
        futures_util::stream::iter(targets.into_iter().map(|(id, label, api)| {
            let client = state.client.clone();
            async move {
                let value = match client.storage_probe(&api).await {
                    Ok(probes) => json!({
                        "node": id,
                        "label": label,
                        "api": api,
                        "probes": probes,
                    }),
                    Err(error) => json!({
                        "node": id,
                        "label": label,
                        "api": api,
                        "probes": [],
                        "error": console_error_brief(&error),
                    }),
                };
                (id, value)
            }
        }))
        .buffer_unordered(8)
        .collect()
        .await;
    nodes.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Json(json!({
        "nodes": nodes.into_iter().map(|(_, value)| value).collect::<Vec<_>>()
    })))
}

fn console_error_brief(error: &anyhow::Error) -> String {
    let rendered = format!("{error:#}");
    let mut chars = rendered.chars();
    let brief: String = chars.by_ref().take(1_024).collect();
    if chars.next().is_some() {
        format!("{brief}…")
    } else {
        brief
    }
}

async fn storage_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<StoragePolicyRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let policy = crate::storage_policy::StoragePolicy {
        schema: crate::storage_policy::STORAGE_POLICY_SCHEMA,
        new_bucket_backend: request.new_bucket_backend,
        shard_remotes: request.shard_remotes,
        shard_prefix: request.shard_prefix,
        d1_backups: request.d1_backups,
    };
    let head = state
        .client
        .resource_head(
            &state.node,
            crate::storage_policy::STORAGE_POLICY_KIND,
            crate::storage_policy::DEFAULT_POLICY_NAME,
        )
        .await?;
    let record = crate::storage_policy::prepare_after(policy, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "version": record.version })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("更新全局存储策略至 v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Deserialize)]
struct R2ObjectListQuery {
    #[serde(default)]
    prefix: String,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn r2_bucket_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let buckets = state
        .client
        .resource_heads(&state.node, Some(crate::r2::BUCKET_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .map(|view| {
            let spec = crate::r2::bucket_spec(&view.resource)?;
            Ok(json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let status = state.client.status(&state.node).await?;
    let storage_policy = state
        .client
        .resource_head(
            &state.node,
            crate::storage_policy::STORAGE_POLICY_KIND,
            crate::storage_policy::DEFAULT_POLICY_NAME,
        )
        .await?
        .filter(|view| !view.resource.deleted)
        .map(|view| crate::storage_policy::policy_spec(&view.resource))
        .transpose()?
        .unwrap_or_default();
    Ok(Json(json!({
        "buckets": buckets,
        "capabilities": status.get("storage").cloned().unwrap_or_else(|| json!({
            "local": true,
            "rclone": false,
        })),
        "storage_policy": storage_policy,
    })))
}

async fn r2_bucket_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<R2BucketRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let (storage, storage_policy) = match request.storage_backend.as_str() {
        "local" if request.rclone_remote.is_empty() && request.rclone_prefix.is_empty() => {
            (crate::objectstore::StorageLocation::Local, None)
        }
        "rclone" if !request.rclone_remote.is_empty() => (
            crate::objectstore::StorageLocation::Rclone {
                remote: request.rclone_remote,
                prefix: request.rclone_prefix,
            },
            None,
        ),
        "policy" if request.rclone_remote.is_empty() && request.rclone_prefix.is_empty() => (
            crate::objectstore::StorageLocation::Local,
            Some(crate::storage_policy::DEFAULT_POLICY_NAME.to_string()),
        ),
        "local" => {
            return Err(ApiError::bad_request(
                "本地存储不能同时填写 rclone remote 或前缀",
            ))
        }
        "rclone" => return Err(ApiError::bad_request("请选择 rclone remote")),
        "policy" => {
            return Err(ApiError::bad_request(
                "存储策略模式不能同时填写固定 rclone remote 或前缀",
            ))
        }
        _ => {
            return Err(ApiError::bad_request(
                "存储后端必须是 local、rclone 或 policy",
            ))
        }
    };
    let spec = crate::r2::BucketSpec {
        description: request.description,
        public_access: request.public_access,
        storage,
        storage_policy,
        max_bytes: request.max_bytes,
        max_objects: request.max_objects,
        expire_objects_after_days: request.expire_objects_after_days,
        cors_origins: request.cors_origins,
        hostnames: request.hostnames,
    };
    let head = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &request.name)
        .await?;
    let record = crate::r2::prepare_bucket_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("创建或更新 R2 bucket {} v{}", record.name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn r2_bucket_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &name)
        .await?
        .ok_or_else(|| ApiError::not_found("R2 bucket 不存在"))?;
    if head.resource.deleted {
        return Err(ApiError::not_found("R2 bucket 已删除"));
    }
    let spec = crate::r2::bucket_spec(&head.resource)?;
    let record = crate::r2::prepare_bucket_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "删除 R2 bucket {}（生成 v{} 墓碑）",
                    record.name, record.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryBlobQuery {
    #[serde(default = "default_storage_backend")]
    storage_backend: String,
    #[serde(default)]
    rclone_remote: String,
    #[serde(default)]
    rclone_prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryRequest {
    name: String,
    #[serde(default)]
    description: String,
    sha256: String,
    size_bytes: u64,
    storage: crate::objectstore::StorageLocation,
    #[serde(default = "default_binary_os_arch")]
    os_arch: String,
    #[serde(default = "default_binary_timeout")]
    default_timeout_ms: u64,
    #[serde(default = "default_binary_io_limit")]
    max_stdin_bytes: u64,
    #[serde(default = "default_binary_io_limit")]
    max_output_bytes: u64,
    #[serde(default)]
    allow_network: bool,
    #[serde(default)]
    allow_r2: bool,
    #[serde(default)]
    required_tags: Vec<String>,
    #[serde(default)]
    suspended: bool,
}

fn default_binary_os_arch() -> String {
    crate::binary::current_os_arch().into()
}

fn default_binary_timeout() -> u64 {
    30_000
}

fn default_binary_io_limit() -> u64 {
    10 * 1024 * 1024
}

fn binary_storage(query: BinaryBlobQuery) -> ApiResult<crate::objectstore::StorageLocation> {
    match query.storage_backend.as_str() {
        "local" if query.rclone_remote.is_empty() && query.rclone_prefix.is_empty() => {
            Ok(crate::objectstore::StorageLocation::Local)
        }
        "rclone" if !query.rclone_remote.is_empty() => {
            Ok(crate::objectstore::StorageLocation::Rclone {
                remote: query.rclone_remote,
                prefix: query.rclone_prefix,
            })
        }
        "local" => Err(ApiError::bad_request(
            "本地存储不能同时填写 rclone remote 或前缀",
        )),
        "rclone" => Err(ApiError::bad_request("请选择 rclone remote")),
        _ => Err(ApiError::bad_request("存储后端必须是 local 或 rclone")),
    }
}

async fn binary_blob_upload(
    State(state): State<ConsoleState>,
    Query(query): Query<BinaryBlobQuery>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let storage = binary_storage(query)?;
    if body.is_empty() || body.len() > crate::binary::MAX_BINARY_BYTES {
        return Err(ApiError::bad_request(
            "Binary 文件必须介于 1 字节和 200 MiB 之间",
        ));
    }
    let (sha256, size_bytes, storage) = match &state.mode {
        ConsoleMode::Local { .. } => {
            state
                .client
                .binary_put_blob(&state.node, &body, &storage)
                .await?
        }
        ConsoleMode::Public { node, .. } => {
            let (sha256, size_bytes) = crate::binary::store_bytes(node, &storage, &body).await?;
            (sha256, size_bytes, storage)
        }
    };
    Ok(Json(json!({
        "ok": true,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "storage": storage,
    })))
}

async fn binary_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let binaries = state
        .client
        .resource_heads(&state.node, Some(crate::binary::BINARY_KIND))
        .await?
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .map(|view| {
            let spec = crate::binary::binary_spec(&view.resource)?;
            Ok(json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let status = state.client.status(&state.node).await?;
    Ok(Json(json!({
        "binaries": binaries,
        "capabilities": status.get("storage").cloned().unwrap_or_else(|| json!({
            "local": true,
            "rclone": false,
        })),
        "current_os_arch": crate::binary::current_os_arch(),
    })))
}

async fn binary_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<BinaryRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let approval_size = request.size_bytes;
    let approval_sha_prefix = request.sha256[..request.sha256.len().min(12)].to_string();
    let spec = crate::binary::BinarySpec {
        schema: crate::binary::BINARY_SCHEMA,
        description: request.description,
        sha256: request.sha256,
        size_bytes: request.size_bytes,
        storage: request.storage,
        os_arch: request.os_arch,
        default_timeout_ms: request.default_timeout_ms,
        max_stdin_bytes: request.max_stdin_bytes,
        max_output_bytes: request.max_output_bytes,
        allow_network: request.allow_network,
        allow_r2: request.allow_r2,
        required_tags: request.required_tags,
        suspended: request.suspended,
    };
    let head = state
        .client
        .resource_head(&state.node, crate::binary::BINARY_KIND, &request.name)
        .await?;
    let record = crate::binary::prepare_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "创建或更新 Binary Deliver {} v{}（{} 字节，SHA-256 {}...）",
                    record.name, record.version, approval_size, approval_sha_prefix
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn binary_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::binary::BINARY_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Binary Deliver 定义不存在"))?;
    let spec = crate::binary::binary_spec(&head.resource)?;
    let record = crate::binary::prepare_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "version": record.version })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("Binary Deliver {} 删除墓碑 v{}", name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    consumer_worker: Option<String>,
    #[serde(default = "queue_default_batch_size")]
    batch_size: u16,
    #[serde(default = "queue_default_wait_ms")]
    max_wait_ms: u64,
    #[serde(default = "queue_default_retries")]
    max_retries: u16,
    #[serde(default = "queue_default_visibility_ms")]
    visibility_timeout_ms: u64,
    #[serde(default = "queue_default_retention_seconds")]
    retention_seconds: u64,
    #[serde(default)]
    dead_letter_queue: Option<String>,
    #[serde(default)]
    suspended: bool,
}

fn queue_default_batch_size() -> u16 {
    10
}
fn queue_default_wait_ms() -> u64 {
    5_000
}
fn queue_default_retries() -> u16 {
    3
}
fn queue_default_visibility_ms() -> u64 {
    120_000
}
fn queue_default_retention_seconds() -> u64 {
    7 * 24 * 60 * 60
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueSendRequest {
    messages: Vec<crate::queue::SendMessage>,
}

#[derive(Debug, Deserialize)]
struct QueueDeadQuery {
    limit: Option<usize>,
}

async fn queue_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::queue::QUEUE_KIND))
        .await?;
    let mut queues = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::queue::queue_spec(&view.resource)?;
        let stats = state
            .client
            .queue_stats(&state.node, &view.resource.name)
            .await;
        queues.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": spec,
            "stats": stats.ok(),
        }));
    }
    Ok(Json(json!({ "queues": queues })))
}

async fn queue_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<QueueRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let spec = crate::queue::QueueSpec {
        description: request.description,
        consumer_worker: request
            .consumer_worker
            .filter(|worker| !worker.trim().is_empty()),
        batch_size: request.batch_size,
        max_wait_ms: request.max_wait_ms,
        max_retries: request.max_retries,
        visibility_timeout_ms: request.visibility_timeout_ms,
        retention_seconds: request.retention_seconds,
        dead_letter_queue: request
            .dead_letter_queue
            .filter(|queue| !queue.trim().is_empty()),
        suspended: request.suspended,
    };
    let head = state
        .client
        .resource_head(&state.node, crate::queue::QUEUE_KIND, &request.name)
        .await?;
    let record = crate::queue::prepare_queue_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("创建或更新队列 {} v{}", record.name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn queue_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::queue::QUEUE_KIND, &name)
        .await?
        .ok_or_else(|| ApiError::not_found("队列不存在"))?;
    if head.resource.deleted {
        return Err(ApiError::not_found("队列已删除"));
    }
    let spec = crate::queue::queue_spec(&head.resource)?;
    let record = crate::queue::prepare_queue_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "name": name })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("删除队列 {}（生成 v{} 墓碑）", name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn queue_send(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<QueueSendRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let ids = state
        .client
        .queue_send(&state.node, &name, &request.messages)
        .await?;
    Ok(Json(json!({ "ok": true, "message_ids": ids })))
}

async fn queue_dead_letters(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<QueueDeadQuery>,
) -> ApiResult<Json<Value>> {
    let dead_letters = state
        .client
        .queue_dead_letters(&state.node, &name, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "dead_letters": dead_letters })))
}

async fn queue_redrive(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.client.queue_redrive(&state.node, &name, &id).await? {
        return Err(ApiError::not_found("死信不存在"));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsDatasetRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    retention_days: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsWriteRequest {
    points: Vec<crate::analytics::DataPoint>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsSqlRequest {
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
    #[serde(default = "analytics_default_query_limit")]
    limit: usize,
}

fn analytics_default_query_limit() -> usize {
    1_000
}

#[derive(Debug, Deserialize)]
struct AnalyticsRecentQuery {
    before: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AnalyticsGroupQuery {
    #[serde(default = "analytics_default_dimension")]
    dimension: String,
    #[serde(default)]
    dimension_index: usize,
    double_index: Option<usize>,
    since: Option<u64>,
    limit: Option<usize>,
}

fn analytics_default_dimension() -> String {
    "blob".into()
}

async fn analytics_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::analytics::DATASET_KIND))
        .await?;
    let mut datasets = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::analytics::dataset_spec(&view.resource)?;
        let stats = state
            .client
            .analytics_stats(&state.node, &view.resource.name)
            .await
            .ok();
        datasets.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": spec,
            "stats": stats,
        }));
    }
    Ok(Json(json!({ "datasets": datasets })))
}

async fn analytics_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<AnalyticsDatasetRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let spec = crate::analytics::DatasetSpec {
        description: request.description,
        retention_days: request.retention_days,
    };
    let head = state
        .client
        .resource_head(&state.node, crate::analytics::DATASET_KIND, &request.name)
        .await?;
    let record =
        crate::analytics::prepare_dataset_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(
                json!({ "ok": true, "name": record.name, "version": record.version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "创建或更新 Analytics 数据集 {} v{}",
                    record.name, record.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn analytics_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::analytics::DATASET_KIND, &name)
        .await?
        .ok_or_else(|| ApiError::not_found("Analytics 数据集不存在"))?;
    if head.resource.deleted {
        return Err(ApiError::not_found("Analytics 数据集已删除"));
    }
    let spec = crate::analytics::dataset_spec(&head.resource)?;
    let record = crate::analytics::prepare_dataset_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "name": name })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!(
                    "删除 Analytics 数据集 {}（生成 v{} 墓碑）",
                    name, record.version
                ),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn analytics_write(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<AnalyticsWriteRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let written = state
        .client
        .analytics_write(&state.node, &name, &request.points)
        .await?;
    Ok(Json(json!({ "ok": true, "written": written })))
}

async fn analytics_recent(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<AnalyticsRecentQuery>,
) -> ApiResult<Json<Value>> {
    let events = state
        .client
        .analytics_recent(&state.node, &name, query.before, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "events": events })))
}

async fn analytics_stats(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::to_value(
        state.client.analytics_stats(&state.node, &name).await?,
    )?))
}

async fn analytics_group(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<AnalyticsGroupQuery>,
) -> ApiResult<Json<Value>> {
    let groups = state
        .client
        .analytics_group(
            &state.node,
            &name,
            &query.dimension,
            query.dimension_index,
            query.double_index,
            query.since.unwrap_or(0),
            query.limit.unwrap_or(20),
        )
        .await?;
    Ok(Json(json!({ "groups": groups })))
}

async fn analytics_query(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<AnalyticsSqlRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::to_value(
        state
            .client
            .analytics_query(
                &state.node,
                &name,
                &request.sql,
                request.params,
                request.limit,
            )
            .await?,
    )?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineRequest {
    name: String,
    #[serde(default)]
    description: String,
    output_bucket: String,
    #[serde(default = "pipeline_default_key_template")]
    output_key_template: String,
    #[serde(default = "pipeline_default_batch_bytes")]
    batch_max_bytes: u64,
    #[serde(default = "pipeline_default_batch_seconds")]
    batch_max_seconds: u64,
    #[serde(default)]
    schema: Option<Value>,
    #[serde(default)]
    transform_sql: Option<String>,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
    #[serde(default)]
    hostnames: Vec<String>,
}

fn pipeline_default_key_template() -> String {
    "{pipeline}/year={yyyy}/month={mm}/day={dd}/hour={hh}/{agent}-{batchId}.jsonl.gz".into()
}

fn pipeline_default_batch_bytes() -> u64 {
    crate::pipeline::DEFAULT_BATCH_BYTES
}

fn pipeline_default_batch_seconds() -> u64 {
    crate::pipeline::DEFAULT_BATCH_SECONDS
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineTokenRequest {
    #[serde(default)]
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineIngestRequest {
    events: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct PipelineBatchQuery {
    limit: Option<usize>,
}

fn pipeline_spec_view(spec: &crate::pipeline::PipelineSpec) -> Value {
    json!({
        "description": spec.description,
        "output_bucket": spec.output_bucket,
        "output_key_template": spec.output_key_template,
        "batch_max_bytes": spec.batch_max_bytes,
        "batch_max_seconds": spec.batch_max_seconds,
        "schema": spec.schema,
        "transform_sql": spec.transform_sql,
        "suspended": spec.suspended,
        "suspend_reason": spec.suspend_reason,
        "hostnames": spec.hostnames,
        "tokens": spec.tokens.iter().map(|token| json!({
            "id": token.id,
            "label": token.label,
            "last_four": token.last_four,
            "created_at_ms": token.created_at_ms,
        })).collect::<Vec<_>>(),
    })
}

async fn pipeline_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::pipeline::PIPELINE_KIND))
        .await?;
    let mut pipelines = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::pipeline::pipeline_spec(&view.resource)?;
        let status = state
            .client
            .pipeline_status(&state.node, &view.resource.name)
            .await
            .ok();
        let default_hostname = match &state.mode {
            ConsoleMode::Public { node, .. } => node.default_pipeline_hostname(&view.resource.name),
            ConsoleMode::Local { .. } => None,
        };
        let hostnames = match &state.mode {
            ConsoleMode::Public { node, .. } => {
                node.effective_pipeline_hostnames(&view.resource.name, &spec)
            }
            ConsoleMode::Local { .. } => spec.hostnames.clone(),
        };
        pipelines.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": pipeline_spec_view(&spec),
            "status": status,
            "default_hostname": default_hostname,
            "hostnames": hostnames,
        }));
    }
    Ok(Json(json!({ "pipelines": pipelines })))
}

async fn pipeline_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<PipelineRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let bucket = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &request.output_bucket)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::bad_request("Pipeline 输出 R2 bucket 不存在"))?;
    crate::r2::bucket_spec(&bucket.resource)?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &request.name)
        .await?;
    let tokens = head
        .as_ref()
        .filter(|view| !view.resource.deleted)
        .map(|view| crate::pipeline::pipeline_spec(&view.resource))
        .transpose()?
        .map(|spec| spec.tokens)
        .unwrap_or_default();
    let mut hostnames: Vec<String> = request
        .hostnames
        .into_iter()
        .map(|hostname| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|hostname| !hostname.is_empty())
        .collect();
    hostnames.sort();
    hostnames.dedup();
    let spec = crate::pipeline::PipelineSpec {
        description: request.description,
        output_bucket: request.output_bucket,
        output_key_template: request.output_key_template,
        batch_max_bytes: request.batch_max_bytes,
        batch_max_seconds: request.batch_max_seconds,
        schema: request.schema,
        transform_sql: request.transform_sql,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
        hostnames,
        tokens,
    };
    let record =
        crate::pipeline::prepare_pipeline_after(&request.name, spec, false, head.as_ref())?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(
                json!({ "ok": true, "name": record.name, "version": record.version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("创建或更新 Pipeline {} v{}", record.name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Pipeline 不存在"))?;
    let spec = crate::pipeline::pipeline_spec(&head.resource)?;
    let record = crate::pipeline::prepare_pipeline_after(&name, spec, true, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({ "ok": true, "name": name })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("删除 Pipeline {}（生成 v{} 墓碑）", name, record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_token_mint(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<PipelineTokenRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Pipeline 不存在"))?;
    let mut spec = crate::pipeline::pipeline_spec(&head.resource)?;
    let (token, plaintext) = crate::pipeline::mint_token(request.label)?;
    spec.tokens.push(token.clone());
    let record = crate::pipeline::prepare_pipeline_after(&name, spec, false, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": name,
                "version": record.version,
                "token": plaintext,
                "token_id": token.id,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("为 Pipeline {} 创建接收令牌 {}", name, token.label),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "token": plaintext,
                "token_id": token.id,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_token_revoke(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::pipeline::PIPELINE_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Pipeline 不存在"))?;
    let mut spec = crate::pipeline::pipeline_spec(&head.resource)?;
    let before = spec.tokens.len();
    spec.tokens.retain(|token| token.id != id);
    if spec.tokens.len() == before {
        return Err(ApiError::not_found("Pipeline 令牌不存在"));
    }
    let record = crate::pipeline::prepare_pipeline_after(&name, spec, false, Some(&head))?;
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(
                json!({ "ok": true, "name": name, "version": record.version }),
            ))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("撤销 Pipeline {} 接收令牌 {}", name, id),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn pipeline_ingest(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<PipelineIngestRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let accepted = state
        .client
        .pipeline_ingest(&state.node, &name, &request.events)
        .await?;
    Ok(Json(json!({ "ok": true, "accepted": accepted })))
}

async fn pipeline_status(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::to_value(
        state.client.pipeline_status(&state.node, &name).await?,
    )?))
}

async fn pipeline_batches(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<PipelineBatchQuery>,
) -> ApiResult<Json<Value>> {
    let batches = state
        .client
        .pipeline_batches(&state.node, &name, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "batches": batches })))
}

async fn pipeline_flush(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let batch = state.client.pipeline_flush(&state.node, &name).await?;
    Ok(Json(json!({ "ok": true, "batch": batch })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowRequest {
    name: String,
    worker: String,
    #[serde(default = "workflow_default_entrypoint")]
    entrypoint: String,
    #[serde(default)]
    description: String,
    #[serde(default = "workflow_default_retention_days")]
    retention_days: u16,
    #[serde(default = "workflow_default_retries")]
    instance_retries: u16,
    #[serde(default = "workflow_default_timeout")]
    instance_timeout_seconds: u64,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
    #[serde(default)]
    cron: Option<String>,
    #[serde(default)]
    webhook_enabled: bool,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default = "workflow_default_concurrency")]
    max_concurrent_instances: u16,
    #[serde(default = "workflow_default_group_concurrency")]
    max_concurrent_instances_per_group: u16,
}

fn workflow_default_entrypoint() -> String {
    "MyWorkflow".into()
}

fn workflow_default_retention_days() -> u16 {
    30
}

fn workflow_default_retries() -> u16 {
    3
}

fn workflow_default_timeout() -> u64 {
    25 * 60
}

fn workflow_default_concurrency() -> u16 {
    32
}

fn workflow_default_group_concurrency() -> u16 {
    1
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowTokenRequest {
    #[serde(default)]
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowTriggerRequest {
    instance_key: Option<String>,
    #[serde(default)]
    concurrency_group: Option<String>,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
struct WorkflowInstancesQuery {
    status: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowSignalRequest {
    name: String,
    #[serde(default)]
    payload: Value,
}

async fn workflow_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::workflow::WORKFLOW_KIND))
        .await?;
    let mut workflows = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::workflow::workflow_spec(&view.resource)?;
        let stats = state
            .client
            .workflow_stats(&state.node, &view.resource.name)
            .await
            .ok();
        let default_hostname = match &state.mode {
            ConsoleMode::Public { node, .. } => node.default_workflow_hostname(&view.resource.name),
            ConsoleMode::Local { .. } => None,
        };
        workflows.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": public_workflow_spec(&spec),
            "stats": stats,
            "default_hostname": default_hostname,
        }));
    }
    Ok(Json(json!({ "workflows": workflows })))
}

async fn workflow_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<WorkflowRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    current_manifest(&state, &request.worker)
        .await
        .map_err(|_| ApiError::bad_request("Workflow 执行 Worker 不存在或部署链无效"))?;
    let head = state
        .client
        .resource_head(&state.node, crate::workflow::WORKFLOW_KIND, &request.name)
        .await?;
    let tokens = head
        .as_ref()
        .and_then(|head| crate::workflow::workflow_spec(&head.resource).ok())
        .map(|spec| spec.tokens)
        .unwrap_or_default();
    let spec = crate::workflow::WorkflowSpec {
        description: request.description,
        worker: request.worker,
        entrypoint: request.entrypoint,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
        retention_days: request.retention_days,
        instance_retries: request.instance_retries,
        instance_timeout_seconds: request.instance_timeout_seconds,
        cron: request.cron,
        webhook_enabled: request.webhook_enabled,
        hostnames: request.hostnames,
        tokens,
        max_concurrent_instances: request.max_concurrent_instances,
        max_concurrent_instances_per_group: request.max_concurrent_instances_per_group,
    };
    let record =
        crate::workflow::prepare_workflow_after(&request.name, spec, false, head.as_ref())?;
    submit_workflow_resource(
        &state,
        &principal,
        record,
        format!("创建或更新 Workflow {}", request.name),
    )
    .await
}

async fn workflow_token_mint(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<WorkflowTokenRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::workflow::WORKFLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Workflow 不存在"))?;
    let mut spec = crate::workflow::workflow_spec(&head.resource)?;
    let (token, plaintext) = crate::workflow::mint_token(request.label)?;
    let token_id = token.id.clone();
    spec.tokens.push(token);
    let record = crate::workflow::prepare_workflow_after(&name, spec, false, Some(&head))?;
    let mut response = submit_workflow_resource(
        &state,
        &principal,
        record,
        format!("为 Workflow {name} 签发 Webhook 令牌"),
    )
    .await?
    .0;
    response["token"] = Value::String(plaintext);
    response["token_id"] = Value::String(token_id);
    Ok(Json(response))
}

async fn workflow_token_revoke(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::workflow::WORKFLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Workflow 不存在"))?;
    let mut spec = crate::workflow::workflow_spec(&head.resource)?;
    let before = spec.tokens.len();
    spec.tokens.retain(|token| token.id != id);
    if before == spec.tokens.len() {
        return Err(ApiError::not_found("Workflow Webhook 令牌不存在"));
    }
    if spec.webhook_enabled && spec.tokens.is_empty() {
        spec.webhook_enabled = false;
    }
    let record = crate::workflow::prepare_workflow_after(&name, spec, false, Some(&head))?;
    submit_workflow_resource(
        &state,
        &principal,
        record,
        format!("撤销 Workflow {name} 的 Webhook 令牌 {id}"),
    )
    .await
}

async fn workflow_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::workflow::WORKFLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Workflow 不存在"))?;
    let spec = crate::workflow::workflow_spec(&head.resource)?;
    let record = crate::workflow::prepare_workflow_after(&name, spec, true, Some(&head))?;
    submit_workflow_resource(&state, &principal, record, format!("删除 Workflow {name}")).await
}

async fn submit_workflow_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn workflow_trigger(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<WorkflowTriggerRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let instance = state
        .client
        .workflow_create(
            &state.node,
            &name,
            request.instance_key.as_deref(),
            request.concurrency_group.as_deref(),
            request.input,
        )
        .await?;
    Ok(Json(json!({ "ok": true, "instance": instance })))
}

async fn workflow_instances(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<WorkflowInstancesQuery>,
) -> ApiResult<Json<Value>> {
    let instances = state
        .client
        .workflow_instances(
            &state.node,
            &name,
            query.status.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({ "instances": instances })))
}

async fn workflow_instance(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .client
            .workflow_instance(&state.node, &name, &id)
            .await?,
    ))
}

async fn workflow_signal(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
    Json(request): Json<WorkflowSignalRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let signal_id = state
        .client
        .workflow_signal(&state.node, &name, &id, &request.name, request.payload)
        .await?;
    Ok(Json(json!({ "ok": true, "signal_id": signal_id })))
}

async fn workflow_action(
    State(state): State<ConsoleState>,
    Path((name, id, action)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    state
        .client
        .workflow_action(&state.node, &name, &id, &action)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowRequest {
    name: String,
    #[serde(default)]
    description: String,
    graph: crate::flow::FlowGraph,
    #[serde(default)]
    trigger: crate::flow::FlowTrigger,
    #[serde(default)]
    cron: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
    #[serde(default = "flow_default_retention_days")]
    retention_days: u16,
    #[serde(default = "flow_default_max_concurrent_runs")]
    max_concurrent_runs: u16,
    #[serde(default)]
    alert_webhook_env: Option<String>,
    /// When present, mint a first/extra Webhook token in the same signed edit.
    #[serde(default)]
    webhook_token_label: Option<String>,
}

fn flow_default_retention_days() -> u16 {
    30
}

fn flow_default_max_concurrent_runs() -> u16 {
    32
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowTokenRequest {
    #[serde(default)]
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowTriggerRequest {
    #[serde(default)]
    run_key: Option<String>,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
struct FlowRunsQuery {
    status: Option<String>,
    limit: Option<usize>,
}

async fn flow_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::flow::FLOW_KIND))
        .await?;
    let status = state.client.status(&state.node).await.ok();
    let default_domain = status
        .as_ref()
        .and_then(|status| status.get("default_worker_domain"))
        .and_then(Value::as_str);
    let mut flows = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::flow::flow_spec(&view.resource)?;
        let stats = state
            .client
            .flow_stats(&state.node, &view.resource.name)
            .await
            .ok();
        let default_hostname =
            default_domain.map(|domain| format!("flow-{}.{domain}", view.resource.name));
        let mut hostnames = default_hostname.iter().cloned().collect::<Vec<_>>();
        for hostname in &spec.hostnames {
            if !hostnames.contains(hostname) {
                hostnames.push(hostname.clone());
            }
        }
        flows.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "default_hostname": default_hostname,
            "hostnames": hostnames,
            "spec": public_flow_spec(&spec),
            "stats": stats,
        }));
    }
    Ok(Json(json!({ "flows": flows })))
}

async fn flow_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<FlowRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &request.name)
        .await?;
    let mut tokens = head
        .as_ref()
        .and_then(|head| crate::flow::flow_spec(&head.resource).ok())
        .map(|spec| spec.tokens)
        .unwrap_or_default();
    let minted = if let Some(label) = request.webhook_token_label {
        let (token, plaintext) = crate::flow::mint_token(label)?;
        let id = token.id.clone();
        tokens.push(token);
        Some((id, plaintext))
    } else {
        None
    };
    let spec = crate::flow::FlowSpec {
        description: request.description,
        graph: request.graph,
        trigger: request.trigger,
        cron: request.cron,
        hostnames: request.hostnames,
        tokens,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
        retention_days: request.retention_days,
        max_concurrent_runs: request.max_concurrent_runs,
        alert_webhook_env: request.alert_webhook_env,
    };
    let record = crate::flow::prepare_flow_after(&request.name, spec, false, head.as_ref())?;
    let mut response = submit_flow_resource(
        &state,
        &principal,
        record,
        format!("创建或更新 Flow {}", request.name),
    )
    .await?
    .0;
    if let Some((id, plaintext)) = minted {
        response["token"] = Value::String(plaintext);
        response["token_id"] = Value::String(id);
    }
    Ok(Json(response))
}

async fn flow_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Flow 不存在"))?;
    let spec = crate::flow::flow_spec(&head.resource)?;
    let record = crate::flow::prepare_flow_after(&name, spec, true, Some(&head))?;
    submit_flow_resource(&state, &principal, record, format!("删除 Flow {name}")).await
}

async fn flow_token_mint(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
    Json(request): Json<FlowTokenRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Flow 不存在"))?;
    let mut spec = crate::flow::flow_spec(&head.resource)?;
    let (token, plaintext) = crate::flow::mint_token(request.label)?;
    let token_id = token.id.clone();
    spec.tokens.push(token);
    let record = crate::flow::prepare_flow_after(&name, spec, false, Some(&head))?;
    let mut response = submit_flow_resource(
        &state,
        &principal,
        record,
        format!("为 Flow {name} 签发 Webhook 令牌"),
    )
    .await?
    .0;
    response["token"] = Value::String(plaintext);
    response["token_id"] = Value::String(token_id);
    Ok(Json(response))
}

async fn flow_token_revoke(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::flow::FLOW_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("Flow 不存在"))?;
    let mut spec = crate::flow::flow_spec(&head.resource)?;
    let before = spec.tokens.len();
    spec.tokens.retain(|token| token.id != id);
    if before == spec.tokens.len() {
        return Err(ApiError::not_found("Flow Webhook 令牌不存在"));
    }
    let record = crate::flow::prepare_flow_after(&name, spec, false, Some(&head))?;
    submit_flow_resource(
        &state,
        &principal,
        record,
        format!("撤销 Flow {name} 的 Webhook 令牌 {id}"),
    )
    .await
}

async fn submit_flow_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn flow_trigger(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<FlowTriggerRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let run = state
        .client
        .flow_create(
            &state.node,
            &name,
            request.run_key.as_deref(),
            request.input,
        )
        .await?;
    Ok(Json(json!({ "ok": true, "run": run })))
}

async fn flow_runs(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<FlowRunsQuery>,
) -> ApiResult<Json<Value>> {
    let runs = state
        .client
        .flow_runs(
            &state.node,
            &name,
            query.status.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({ "runs": runs })))
}

async fn flow_run(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(state.client.flow_run(&state.node, &name, &id).await?))
}

async fn flow_action(
    State(state): State<ConsoleState>,
    Path((name, id, action)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let result = state
        .client
        .flow_action(&state.node, &name, &id, &action)
        .await?;
    Ok(Json(json!({ "ok": true, "result": result })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailDomainRequest {
    name: String,
    #[serde(default)]
    description: String,
    domain: String,
    mx_hostname: String,
    bucket: String,
    #[serde(default = "email_default_object_prefix")]
    object_prefix: String,
    #[serde(default)]
    routes: Vec<crate::email::EmailRoute>,
    #[serde(default = "email_default_max_message_bytes")]
    max_message_bytes: u64,
    #[serde(default = "email_default_per_minute")]
    inbound_per_minute: u32,
    #[serde(default = "email_default_per_minute")]
    outbound_per_minute: u32,
    #[serde(default = "email_default_retention_days")]
    retention_days: u16,
    #[serde(default = "email_default_dkim_selector")]
    dkim_selector: String,
    #[serde(default)]
    dkim_public_key: String,
    #[serde(default)]
    dkim_private_key_env: String,
    #[serde(default)]
    rotate_verification: bool,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    suspend_reason: String,
}

fn email_default_object_prefix() -> String {
    "mail".into()
}

fn email_default_max_message_bytes() -> u64 {
    25 * 1024 * 1024
}

fn email_default_per_minute() -> u32 {
    1_000
}

fn email_default_retention_days() -> u16 {
    30
}

fn email_default_dkim_selector() -> String {
    "rf".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailSendRequest {
    mail_from: String,
    recipients: Vec<String>,
    raw_base64: String,
}

#[derive(Debug, Deserialize)]
struct EmailMessagesQuery {
    limit: Option<usize>,
}

async fn email_list(State(state): State<ConsoleState>) -> ApiResult<Json<Value>> {
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::email::EMAIL_DOMAIN_KIND))
        .await?;
    let mut domains = Vec::new();
    for view in records.into_iter().filter(|view| !view.resource.deleted) {
        let spec = crate::email::email_domain_spec(&view.resource)?;
        let verification = state
            .client
            .email_verification(&state.node, &view.resource.name)
            .await
            .ok()
            .flatten();
        domains.push(json!({
            "name": view.resource.name,
            "version": view.resource.version,
            "digest": view.digest,
            "spec": spec,
            "verification": verification,
        }));
    }
    let status = state.client.status(&state.node).await.ok();
    Ok(Json(json!({
        "domains": domains,
        "email_node": status.as_ref().and_then(|value| value.get("email_node")).cloned(),
        "buckets": status.as_ref().and_then(|value| value.get("r2_buckets")).cloned().unwrap_or_else(|| json!([])),
        "workers": status.as_ref().and_then(|value| value.get("workers")).cloned().unwrap_or_else(|| json!([])),
    })))
}

async fn email_apply(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Json(request): Json<EmailDomainRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let bucket = state
        .client
        .resource_head(&state.node, crate::r2::BUCKET_KIND, &request.bucket)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::bad_request("邮件原文 R2 bucket 不存在"))?;
    crate::r2::bucket_spec(&bucket.resource)?;
    let records = state
        .client
        .resource_heads(&state.node, Some(crate::email::EMAIL_DOMAIN_KIND))
        .await?;
    for view in records
        .into_iter()
        .filter(|view| !view.resource.deleted && view.resource.name != request.name)
    {
        let existing = crate::email::email_domain_spec(&view.resource)?;
        if existing.domain.eq_ignore_ascii_case(&request.domain) {
            return Err(ApiError::bad_request(format!(
                "邮件域 {} 已由资源 {} 管理",
                request.domain, view.resource.name
            )));
        }
    }
    let head = state
        .client
        .resource_head(&state.node, crate::email::EMAIL_DOMAIN_KIND, &request.name)
        .await?;
    let previous = head
        .as_ref()
        .and_then(|view| crate::email::email_domain_spec(&view.resource).ok());
    let verification_challenge = if request.rotate_verification {
        crate::email::generate_verification_challenge()
    } else {
        previous
            .as_ref()
            .map(|spec| spec.verification_challenge.clone())
            .unwrap_or_else(crate::email::generate_verification_challenge)
    };
    let spec = crate::email::EmailDomainSpec {
        description: request.description,
        domain: request.domain,
        verification_challenge,
        mx_hostname: request.mx_hostname,
        bucket: request.bucket,
        object_prefix: request.object_prefix,
        routes: request.routes,
        max_message_bytes: request.max_message_bytes,
        inbound_per_minute: request.inbound_per_minute,
        outbound_per_minute: request.outbound_per_minute,
        retention_days: request.retention_days,
        dkim_selector: request.dkim_selector,
        dkim_public_key: request.dkim_public_key,
        dkim_private_key_env: request.dkim_private_key_env,
        suspended: request.suspended,
        suspend_reason: request.suspend_reason,
    };
    let dns = json!({
        "ownership_name": spec.ownership_txt_name(),
        "ownership_value": spec.ownership_txt_value(),
        "mx_name": spec.domain,
        "mx_value": spec.mx_hostname,
        "dkim_name": spec.dkim_txt_name(),
        "dkim_value": spec.dkim_public_key,
    });
    let record =
        crate::email::prepare_email_domain_after(&request.name, spec, false, head.as_ref())?;
    let mut response = submit_email_resource(
        &state,
        &principal,
        record,
        format!("创建或更新邮件域 {}", request.name),
    )
    .await?
    .0;
    response["dns"] = dns;
    Ok(Json(response))
}

async fn email_delete(
    State(state): State<ConsoleState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let head = state
        .client
        .resource_head(&state.node, crate::email::EMAIL_DOMAIN_KIND, &name)
        .await?
        .filter(|view| !view.resource.deleted)
        .ok_or_else(|| ApiError::not_found("邮件域不存在"))?;
    let spec = crate::email::email_domain_spec(&head.resource)?;
    let record = crate::email::prepare_email_domain_after(&name, spec, true, Some(&head))?;
    submit_email_resource(&state, &principal, record, format!("删除邮件域 {name}")).await
}

async fn submit_email_resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    record: crate::resource::ResourceRecord,
    description: String,
) -> ApiResult<Json<Value>> {
    match &state.mode {
        ConsoleMode::Local { .. } => {
            let envelope = rf_core::envelope::Envelope::seal_any(&record, state.operator()?);
            state.client.post_resource(&state.node, &envelope).await?;
            Ok(Json(json!({
                "ok": true,
                "name": record.name,
                "version": record.version,
            })))
        }
        ConsoleMode::Public { node, .. } => {
            let approval = node.management.create_resource(
                principal.session_id,
                &record,
                format!("{description} v{}", record.version),
            )?;
            Ok(Json(json!({
                "ok": true,
                "pending_approval": true,
                "name": record.name,
                "version": record.version,
                "approval": approval,
                "approve_node": node.cfg.peer_api_advertise().to_string(),
            })))
        }
    }
}

async fn email_verification(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let verification = state.client.email_verification(&state.node, &name).await?;
    Ok(Json(json!({ "verification": verification })))
}

async fn email_verify(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    let verification = state.client.email_verify(&state.node, &name).await?;
    Ok(Json(json!({ "ok": true, "verification": verification })))
}

async fn email_messages(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Query(query): Query<EmailMessagesQuery>,
) -> ApiResult<Json<Value>> {
    let messages = state
        .client
        .email_messages(&state.node, &name, query.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({ "messages": messages })))
}

async fn email_message(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let message = state.client.email_message(&state.node, &name, &id).await?;
    Ok(Json(json!({ "message": message })))
}

async fn email_message_raw(
    State(state): State<ConsoleState>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let raw = state
        .client
        .email_message_raw(&state.node, &name, &id)
        .await?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("message/rfc822"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{id}.eml\""))
                    .map_err(|_| ApiError::bad_request("邮件 ID 无效"))?,
            ),
        ],
        raw,
    )
        .into_response())
}

async fn email_send(
    State(state): State<ConsoleState>,
    Path(name): Path<String>,
    Json(request): Json<EmailSendRequest>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(request.raw_base64)
        .map_err(|_| ApiError::bad_request("RFC 822 原文不是有效 Base64"))?;
    let metadata = crate::email::EmailSendMetadata {
        mail_from: request.mail_from,
        recipients: request.recipients,
    };
    let queued = state
        .client
        .email_send(&state.node, &name, &metadata, &raw)
        .await?;
    Ok(Json(json!({ "ok": true, "queued": queued })))
}

async fn r2_object_list(
    State(state): State<ConsoleState>,
    Path(bucket): Path<String>,
    Query(query): Query<R2ObjectListQuery>,
) -> ApiResult<Json<Value>> {
    let objects = state
        .client
        .r2_list(
            &state.node,
            &bucket,
            &query.prefix,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({
        "bucket": bucket,
        "objects": objects.objects,
        "truncated": objects.truncated,
        "cursor": objects.cursor,
    })))
}

async fn r2_multipart_list(
    State(state): State<ConsoleState>,
    Path(bucket): Path<String>,
    Query(query): Query<R2ObjectListQuery>,
) -> ApiResult<Json<Value>> {
    let uploads = state
        .client
        .r2_multipart_list(
            &state.node,
            &bucket,
            &query.prefix,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(json!({
        "bucket": bucket,
        "uploads": uploads.uploads,
        "truncated": uploads.truncated,
        "cursor": uploads.cursor,
    })))
}

async fn r2_multipart_detail(
    State(state): State<ConsoleState>,
    Path((bucket, upload_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(serde_json::to_value(
        state
            .client
            .r2_multipart_detail(&state.node, &bucket, &upload_id)
            .await?,
    )?))
}

async fn r2_multipart_abort(
    State(state): State<ConsoleState>,
    Path((bucket, upload_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    state
        .client
        .r2_multipart_abort(&state.node, &bucket, &upload_id)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

async fn r2_object_get(
    State(state): State<ConsoleState>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (metadata, bytes) = state
        .client
        .r2_get(&state.node, &bucket, &key)
        .await?
        .ok_or_else(|| ApiError::not_found("R2 对象不存在"))?;
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(
            metadata
                .content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
        )
        .map_err(|_| ApiError::upstream("R2 对象 Content-Type 无效"))?,
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", metadata.etag))
            .map_err(|_| ApiError::upstream("R2 对象 ETag 无效"))?,
    );
    Ok(response)
}

async fn r2_object_put(
    State(state): State<ConsoleState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if body.len() > crate::r2::MAX_BUFFERED_OBJECT_BYTES {
        return Err(ApiError::bad_request(
            "控制台单次上传最大为 63 MiB；更大的对象请使用分片上传",
        ));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| *value != "application/octet-stream")
        .map(str::to_string);
    let metadata = state
        .client
        .r2_put(
            &state.node,
            &bucket,
            &key,
            &body,
            &crate::r2::PutOptions {
                content_type,
                ..Default::default()
            },
        )
        .await?;
    Ok(Json(json!({ "ok": true, "object": metadata })))
}

async fn r2_object_delete(
    State(state): State<ConsoleState>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    state.require_mutation()?;
    if !state.client.r2_delete(&state.node, &bucket, &key).await? {
        return Err(ApiError::not_found("R2 对象不存在"));
    }
    Ok(Json(json!({ "ok": true })))
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn upstream(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }

    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::upstream(error.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::upstream(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use rf_core::identity::Keypair;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[test]
    fn same_origin_supports_http2_authority_and_rejects_cross_origin() {
        let http2 = Request::builder()
            .uri("https://Console.Example/api/auth/challenge")
            .header(header::ORIGIN, "https://console.example")
            .body(Body::empty())
            .unwrap();
        assert!(same_origin(&http2, "https"));

        let http1 = Request::builder()
            .uri("/api/auth/challenge")
            .header(header::HOST, "127.0.0.1:18080")
            .header(header::ORIGIN, "http://127.0.0.1:18080")
            .body(Body::empty())
            .unwrap();
        assert!(same_origin(&http1, "http"));

        let wrong_host = Request::builder()
            .uri("https://console.example/api/auth/challenge")
            .header(header::ORIGIN, "https://attacker.example")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&wrong_host, "https"));

        let wrong_scheme = Request::builder()
            .uri("https://console.example/api/auth/challenge")
            .header(header::ORIGIN, "http://console.example")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&wrong_scheme, "https"));

        let origin_with_path = Request::builder()
            .uri("https://console.example/api/auth/challenge")
            .header(header::ORIGIN, "https://console.example/not-an-origin")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&origin_with_path, "https"));
    }

    #[test]
    fn editor_paths_are_strict_relative_paths() {
        for path in ["index.js", "src/worker.mjs", "public/中文.txt"] {
            assert!(validate_editor_path(path).is_ok(), "{path}");
        }
        for path in [
            "",
            "/index.js",
            "../secret",
            "src/../secret",
            "src//worker.js",
            "src\\worker.js",
            "./index.js",
            "index.js\nignored",
        ] {
            assert!(validate_editor_path(path).is_err(), "{path:?}");
        }
    }

    fn state() -> ConsoleState {
        ConsoleState::new("127.0.0.1:9".into(), [7u8; 32], None)
    }

    fn operator_state() -> ConsoleState {
        ConsoleState::new(
            "127.0.0.1:9".into(),
            [7u8; 32],
            Some(AnyKeypair::Ed(Keypair::from_seed([9u8; 32]))),
        )
    }

    #[test]
    fn worker_settings_create_a_linked_manifest_and_preserve_internal_metadata() {
        assert!(valid_compatibility_date("2028-02-29"));
        assert!(!valid_compatibility_date("2027-02-29"));
        assert!(!valid_compatibility_date("2026-十三-01"));
        let mut env = BTreeMap::from([("GREETING".into(), "hello".into())]);
        env.insert(
            deploy::DO_METADATA_ENV.into(),
            r#"{"COUNTER":{"class_name":"Counter","unique_key":"counter","enable_sql":true}}"#
                .into(),
        );
        env.insert(
            deploy::R2_METADATA_ENV.into(),
            r#"{"OLD":"archive"}"#.into(),
        );
        env.insert(
            deploy::D1_METADATA_ENV.into(),
            r#"{"OLD_DB":"archive"}"#.into(),
        );
        env.insert(
            deploy::QUEUE_METADATA_ENV.into(),
            r#"{"OLD_QUEUE":"archive"}"#.into(),
        );
        env.insert(
            deploy::ANALYTICS_METADATA_ENV.into(),
            r#"{"OLD_METRICS":"archive"}"#.into(),
        );
        env.insert(
            deploy::PIPELINE_METADATA_ENV.into(),
            r#"{"OLD_PIPE":"archive"}"#.into(),
        );
        let encrypted = crate::worker_secret::encrypt(
            &[7; 32],
            "demo",
            "API_TOKEN",
            "console-must-never-return-this",
        )
        .unwrap();
        env.insert(
            deploy::SECRET_METADATA_ENV.into(),
            serde_json::to_string(&BTreeMap::from([("API_TOKEN", encrypted)])).unwrap(),
        );
        let manifest = WorkerManifest {
            name: "demo".into(),
            version: 4,
            prev: Some([3; 32]),
            deleted: false,
            main: String::new(),
            modules: vec![],
            assets: vec![],
            hostnames: vec!["old.example".into()],
            env,
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-08-01".into(),
        };
        let updated = apply_worker_settings(
            manifest,
            [9; 32],
            WorkerSettingsRequest {
                hostnames: Some(vec!["API.Example.com.".into(), "api.example.com".into()]),
                env: Some(BTreeMap::from([("MODE".into(), "production".into())])),
                kv_bindings: Some(BTreeMap::from([("CACHE".into(), "shared".into())])),
                r2_bindings: Some(BTreeMap::from([("ASSETS".into(), "assets".into())])),
                d1_bindings: Some(BTreeMap::from([("DB".into(), "primary".into())])),
                queue_bindings: Some(BTreeMap::from([("JOBS".into(), "jobs".into())])),
                analytics_bindings: Some(BTreeMap::from([(
                    "METRICS".into(),
                    "web-metrics".into(),
                )])),
                pipeline_bindings: Some(BTreeMap::from([("ARCHIVE".into(), "event-pipe".into())])),
                workflow_bindings: Some(BTreeMap::from([(
                    "ORDER_FLOW".into(),
                    "order-flow".into(),
                )])),
                email_bindings: Some(BTreeMap::from([(
                    "SUPPORT_MAIL".into(),
                    "support-mail".into(),
                )])),
                service_bindings: Some(BTreeMap::from([("BACKEND".into(), "backend".into())])),
                binary_bindings: Some(BTreeMap::from([("FFMPEG".into(), "ffmpeg".into())])),
                crons: Some(vec!["*/5 * * * *".into()]),
                compatibility_date: Some("2026-08-04".into()),
                compatibility_flags: Some(vec!["nodejs_compat".into()]),
                required_tags: Some(vec![" GPU ".into(), "region-eu".into(), "gpu".into()]),
            },
        )
        .unwrap();
        assert_eq!(updated.version, 5);
        assert_eq!(updated.prev, Some([9; 32]));
        assert_eq!(updated.hostnames, vec!["api.example.com"]);
        assert_eq!(updated.env["MODE"], "production");
        assert!(updated.env.contains_key(deploy::DO_METADATA_ENV));
        assert_eq!(deploy::r2_bindings(&updated)["ASSETS"], "assets");
        assert_eq!(deploy::d1_bindings(&updated)["DB"], "primary");
        assert_eq!(
            deploy::email_bindings(&updated)["SUPPORT_MAIL"],
            "support-mail"
        );
        assert_eq!(deploy::queue_bindings(&updated)["JOBS"], "jobs");
        assert_eq!(
            deploy::analytics_bindings(&updated)["METRICS"],
            "web-metrics"
        );
        assert_eq!(deploy::pipeline_bindings(&updated)["ARCHIVE"], "event-pipe");
        assert_eq!(
            deploy::workflow_bindings(&updated)["ORDER_FLOW"],
            "order-flow"
        );
        assert_eq!(deploy::service_bindings(&updated)["BACKEND"], "backend");
        assert_eq!(deploy::binary_bindings(&updated)["FFMPEG"], "ffmpeg");
        assert_eq!(updated.kv_bindings["CACHE"], "shared");
        assert_eq!(updated.crons, vec!["*/5 * * * *"]);
        assert_eq!(deploy::compatibility_flags(&updated), ["nodejs_compat"]);
        assert_eq!(
            crate::placement::required_tags(&updated),
            ["gpu", "region-eu"]
        );
        assert!(updated.env.contains_key(deploy::SECRET_METADATA_ENV));
        let exposed = worker_console_environment(&updated);
        let exposed_json = serde_json::to_string(&exposed).unwrap();
        assert!(!exposed.contains_key(deploy::SECRET_METADATA_ENV));
        assert!(!exposed_json.contains("console-must-never-return-this"));
        assert_eq!(
            crate::worker_secret::encrypted_secrets(&updated)
                .into_keys()
                .collect::<Vec<_>>(),
            vec!["API_TOKEN"]
        );
    }

    #[test]
    fn pipeline_console_view_never_exposes_token_hashes() {
        let (token, plaintext) = crate::pipeline::mint_token("生产采集器").unwrap();
        let digest = token.sha256.clone();
        let spec = crate::pipeline::PipelineSpec {
            description: String::new(),
            output_bucket: "archive".into(),
            output_key_template: "events/{batchId}.jsonl.gz".into(),
            batch_max_bytes: crate::pipeline::DEFAULT_BATCH_BYTES,
            batch_max_seconds: crate::pipeline::DEFAULT_BATCH_SECONDS,
            schema: None,
            transform_sql: None,
            suspended: false,
            suspend_reason: String::new(),
            hostnames: vec![],
            tokens: vec![token],
        };
        let view = pipeline_spec_view(&spec).to_string();
        assert!(!view.contains(&digest));
        assert!(!view.contains(&plaintext));
        assert!(view.contains("生产采集器"));
    }

    fn public_state(secure: bool) -> (ConsoleState, Arc<Node>, AnyKeypair) {
        let operator = AnyKeypair::Ed(Keypair::from_seed([19u8; 32]));
        let data_dir = std::env::temp_dir().join(format!(
            "rf-console-public-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let config: crate::config::NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {data_dir:?}
            cluster_id = "console-test"
            label = "console-node"
            operator = "{operator}"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            public = true
            [gossip]
            listen = "127.0.0.1:17381"
            advertise = "127.0.0.1:17381"
            [peer_api]
            listen = "127.0.0.1:17382"
            advertise = "127.0.0.1:17382"
            [ingress]
            http = "127.0.0.1:18080"
            https = "127.0.0.1:18443"
            default_domain = "example.com"
            [acme]
            email = "ops@example.com"
            hostnames = ["*.example.com"]
            include_worker_hostnames = true
            zone = "example.com"
            "#,
            data_dir = data_dir.display(),
            operator = operator.signer_id(),
        ))
        .unwrap();
        let node = Arc::new(Node::open(config, Keypair::from_seed([20u8; 32])).unwrap());
        let state = ConsoleState::public(node.clone(), secure).unwrap();
        (state, node, operator)
    }

    #[test]
    fn worker_tls_view_reports_certificate_without_exposing_key_material() {
        let (_, node, _) = public_state(false);
        let now = now_ms();
        let record = crate::acme::CertRecord {
            hostname: "*.example.com".into(),
            cert_pem: "CERTIFICATE-MATERIAL".into(),
            key_pem: "PRIVATE-KEY-MATERIAL".into(),
            issued_ms: now,
            expires_ms: now + 60 * 24 * 60 * 60 * 1000,
        };
        node.kv_put(
            crate::acme::NS,
            &crate::acme::cert_kv_key("*.example.com"),
            Some(serde_json::to_vec(&record).unwrap()),
            None,
        )
        .unwrap();

        let view = worker_tls_view(&node, &["api.example.com".into()]);
        assert_eq!(view["enabled"], true);
        assert_eq!(view["include_worker_hostnames"], true);
        assert_eq!(view["certificates"][0]["status"], "active");
        assert_eq!(view["certificates"][0]["coverage"], "wildcard");
        assert_eq!(view["certificates"][0]["covered_by"], "*.example.com");
        let encoded = view.to_string();
        assert!(!encoded.contains("CERTIFICATE-MATERIAL"));
        assert!(!encoded.contains("PRIVATE-KEY-MATERIAL"));
    }

    #[tokio::test]
    async fn static_page_embeds_token_and_security_headers() {
        let state = state();
        let response = router(state.clone())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("RandallFlare 管理控制台"));
        assert!(body.contains(r#"<html lang="zh-CN">"#));
        assert!(body.contains("一次构建，一次验证，处处运行。"));
        assert!(body.contains("尚未选择目录"));
        assert!(!body.contains(">Overview<"));
        assert!(!body.contains(">Sign out<"));
        assert!(body.contains(state.local_token()));
        assert!(!body.contains("__RF_TOKEN__"));
    }

    #[tokio::test]
    async fn api_requires_token_and_session_never_contains_secret() {
        let state = state();
        let app = router(state.clone());
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header(TOKEN_HEADER, state.local_token())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let body = to_bytes(allowed.into_body(), 1024 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("RandallFlare"));
        assert!(!text.contains(&hex::encode([7u8; 32])));
    }

    #[test]
    fn internal_kv_writes_are_rejected() {
        assert!(validate_kv("__rf", Some("d1/test"), true).is_err());
        assert!(validate_kv("public", Some("key"), true).is_ok());
    }

    #[test]
    fn kv_console_preserves_binary_metadata_and_expiration_contract() {
        use base64::Engine as _;
        let binary = vec![0, 159, 255, 10];
        assert_eq!(
            decode_kv_write_value(
                None,
                Some(base64::engine::general_purpose::STANDARD.encode(&binary)),
            )
            .unwrap(),
            binary
        );
        assert!(decode_kv_write_value(Some("text".into()), Some("dGV4dA==".into())).is_err());
        assert!(validate_kv_value_and_metadata(
            b"value",
            Some(&json!({ "contentType": "application/octet-stream" }))
        )
        .is_ok());
        assert!(
            validate_kv_value_and_metadata(b"value", Some(&Value::String("x".repeat(1025))))
                .is_err()
        );
        assert!(kv_expiration_ms(Some(59), None).is_err());
        assert!(kv_expiration_ms(Some(60), None).unwrap().is_some());
        assert!(kv_expiration_ms(Some(60), Some(crate::node::now_ms() / 1000 + 3600)).is_err());

        let transfer = KvTransfer {
            version: 1,
            namespace: "assets".into(),
            prefix: "images/".into(),
            entries: vec![KvTransferEntry {
                key: "images/logo".into(),
                value_base64: base64::engine::general_purpose::STANDARD.encode(&binary),
                expiration: Some(2_000_000_000),
                metadata: Some(json!({ "kind": "logo" })),
            }],
        };
        let encoded = serde_json::to_vec(&transfer).unwrap();
        let decoded: KvTransfer = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.namespace, "assets");
        assert_eq!(decoded.entries[0].metadata, Some(json!({ "kind": "logo" })));
    }

    #[test]
    fn public_d1_read_scope_rejects_mutating_sql_and_pragmas() {
        for sql in [
            "SELECT * FROM events",
            "WITH recent AS (SELECT * FROM events) SELECT * FROM recent",
            "EXPLAIN QUERY PLAN SELECT * FROM events",
            "PRAGMA table_info(events)",
            "PRAGMA main.index_list(events)",
            "-- comment\nPRAGMA user_version",
        ] {
            assert!(public_sql_is_read_only(sql), "expected read-only: {sql}");
        }
        for sql in [
            "PRAGMA user_version=7",
            "PRAGMA user_version(7)",
            "PRAGMA journal_mode=WAL",
            "SELECT 1; PRAGMA user_version=7",
            "WITH changed AS (DELETE FROM events RETURNING *) SELECT * FROM changed",
            "EXPLAIN DELETE FROM events",
            "INSERT INTO events VALUES (1)",
        ] {
            assert!(!public_sql_is_read_only(sql), "expected rejected: {sql}");
        }
    }

    #[test]
    fn d1_import_strips_only_transaction_wrappers_and_quotes_schema_names() {
        for sql in [
            "BEGIN;",
            "BEGIN TRANSACTION;",
            "BEGIN IMMEDIATE;",
            "COMMIT;",
            "END TRANSACTION;",
            "ROLLBACK;",
        ] {
            assert!(crate::d1bind::transaction_control(sql), "{sql}");
        }
        for sql in [
            "CREATE TABLE begin (id INTEGER);",
            "ROLLBACK TO savepoint_name;",
            "SELECT 'COMMIT';",
        ] {
            assert!(!crate::d1bind::transaction_control(sql), "{sql}");
        }
        assert_eq!(quote_sql_identifier("odd\"table"), "\"odd\"\"table\"");
    }

    #[test]
    fn github_dispatch_binds_repository_and_ignores_unconfigured_branches() {
        let (_, node, _) = public_state(true);
        let source = crate::build::SourceRecord {
            source: crate::build::WorkerSource {
                schema: 1,
                worker: "demo".into(),
                version: 1,
                prev: None,
                deleted: false,
                repository: "https://github.com/example/demo.git".into(),
                branch: "main".into(),
                root: ".".into(),
                build_command: String::new(),
                output_dir: ".".into(),
                use_github_token: false,
                webhook: true,
                preview_pull_requests: true,
            },
            digest: hex::encode([3; 32]),
        };
        let payload = json!({
            "repository": { "clone_url": "https://github.com/example/demo.git" },
            "ref": "refs/heads/not-main",
            "after": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        });
        let result = dispatch_github_payload(
            node.clone(),
            "demo",
            source.clone(),
            "push",
            &payload,
            "delivery",
            Some(42),
        )
        .unwrap();
        assert_eq!(result["ignored"], "branch");

        let wrong = json!({
            "repository": { "clone_url": "https://github.com/example/other.git" },
            "ref": "refs/heads/main",
            "after": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        });
        assert!(dispatch_github_payload(
            node,
            "demo",
            source,
            "push",
            &wrong,
            "delivery",
            Some(42),
        )
        .is_err());
    }

    #[tokio::test]
    async fn bearer_api_enforces_authentication_and_exact_scopes() {
        let (state, node, operator) = public_state(false);
        let (kv_record, kv_raw) =
            crate::access::mint(&node, "KV 写入".into(), vec!["kv:write".into()], None).unwrap();
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&kv_record, &operator),
        )
        .unwrap();
        let app = router(state.clone());

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let wrong_scope = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header(header::AUTHORIZATION, format!("Bearer {kv_raw}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

        let internal_write = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/v1/kv/__rf/cluster-policy")
                    .header(header::AUTHORIZATION, format!("Bearer {kv_raw}"))
                    .body(Body::from("forbidden"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(internal_write.status(), StatusCode::FORBIDDEN);

        let (node_record, node_raw) =
            crate::access::mint(&node, "节点读取".into(), vec!["node:read".into()], None).unwrap();
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&node_record, &operator),
        )
        .unwrap();
        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header(header::AUTHORIZATION, format!("Bearer {node_raw}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn device_config_requires_its_one_way_token_and_never_exposes_digest() {
        let (state, node, operator) = public_state(true);
        let rule = crate::resource::prepare_after(
            crate::exit::EXIT_RULE_KIND,
            "default-route",
            serde_json::json!({
                "schema": 1,
                "description": "测试",
                "enabled": true,
                "priority": 0,
                "format": "surge",
                "config": "FINAL,DIRECT",
                "providers": {},
                "policy_exits": {},
            }),
            false,
            None,
        )
        .unwrap();
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&rule, &operator),
        )
        .unwrap();
        let (record, raw) = crate::exit::mint_device(
            &node,
            "phone",
            "测试手机".into(),
            vec!["default-route".into()],
            None,
        )
        .unwrap();
        let digest = crate::exit::device_spec(&record).unwrap().token_sha256;
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&record, &operator),
        )
        .unwrap();
        let (access_record, access_token) = crate::access::mint(
            &node,
            "设备目录读取".into(),
            vec!["network:read".into()],
            None,
        )
        .unwrap();
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&access_record, &operator),
        )
        .unwrap();
        let app = router(state);

        for authorization in [None, Some("Bearer rfd_invalid")] {
            let mut request = Request::builder().uri("/device/v1/config/phone");
            if let Some(authorization) = authorization {
                request = request.header(header::AUTHORIZATION, authorization);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/device/v1/config/phone")
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("测试手机"));
        assert!(!text.contains(&raw));
        assert!(!text.contains(&digest));
        assert!(!text.contains("token_sha256"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("default-route"));
        assert!(text.contains("测试手机"));
        assert!(!text.contains(&raw));
        assert!(!text.contains(&digest));
        assert!(!text.contains("token_sha256"));
    }

    #[test]
    fn console_only_accepts_loopback_listeners() {
        assert!(validate_listen("127.0.0.1:7390".parse().unwrap()).is_ok());
        assert!(validate_listen("[::1]:7390".parse().unwrap()).is_ok());
        assert!(validate_listen("0.0.0.0:7390".parse().unwrap()).is_err());
        assert!(validate_listen("192.0.2.10:7390".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn observer_mode_rejects_mutations() {
        let state = state();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/kv/value")
                    .header(TOKEN_HEADER, state.local_token())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"namespace":"public","key":"key","value":"value"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn internal_namespace_write_is_rejected_before_network_access() {
        let state = operator_state();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/kv/value")
                    .header(TOKEN_HEADER, state.local_token())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"namespace":"__rf","key":"d1/test","value":"value"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn public_console_requires_operator_signed_stateless_session() {
        use base64::Engine as _;

        let (state, node, operator) = public_state(true);
        let app = router(state.clone());
        let page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "console.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let page = to_bytes(page.into_body(), 1024 * 1024).await.unwrap();
        let page = String::from_utf8(page.to_vec()).unwrap();
        assert!(page.contains("content=\"public\""));
        assert!(!page.contains(&node.cfg.cluster_secret));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header(header::HOST, "console.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let cross_origin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://console.test/api/auth/challenge")
                    .header(header::ORIGIN, "https://attacker.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);

        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://console.test/api/auth/challenge")
                    .header(header::ORIGIN, "https://console.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge = to_bytes(challenge.into_body(), 1024 * 1024).await.unwrap();
        let challenge: Value = serde_json::from_slice(&challenge).unwrap();
        let id = challenge["id"].as_str().unwrap();
        let code = challenge["code"].as_str().unwrap();
        let approval = node.management.view_by_code(code).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(approval.payload_base64)
            .unwrap();
        node.management
            .approve(
                code,
                operator.signer_id(),
                operator.sign(&payload),
                &operator.signer_id(),
            )
            .unwrap();

        let approved = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/auth/challenge/{id}"))
                    .header(header::HOST, "console.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);
        let set_cookie = approved.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));
        assert!(set_cookie.contains("Secure"));
        let cookie = set_cookie.split(';').next().unwrap();

        let session = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header(header::HOST, "console.test")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        let session = to_bytes(session.into_body(), 1024 * 1024).await.unwrap();
        let session: Value = serde_json::from_slice(&session).unwrap();
        assert_eq!(session["auth_mode"], "operator_grant");
        let csrf = session["csrf"].as_str().unwrap();

        let missing_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/logout")
                    .header(header::HOST, "console.test")
                    .header(header::ORIGIN, "https://console.test")
                    .header(header::COOKIE, cookie)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

        let logout = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/logout")
                    .header(header::HOST, "console.test")
                    .header(header::ORIGIN, "https://console.test")
                    .header(header::COOKIE, cookie)
                    .header(CSRF_HEADER, csrf)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(logout.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
    }
}
