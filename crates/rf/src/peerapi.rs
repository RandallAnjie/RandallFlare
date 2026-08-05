//! The peer API: one HTTP surface serving three callers — peer nodes
//! (anti-entropy sync, blob fetch), the operator CLI (deploy, kv,
//! status) and local workerd processes (KV bindings, loopback only).

use crate::auth;
use crate::node::{now_ms, Node};
use crate::peers::encode_envelopes;
use crate::r2;
use crate::transport;
use anyhow::Result;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use rf_core::envelope::Envelope;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

const MAX_PEER_PAYLOAD: usize = crate::binary::MAX_BINARY_BYTES + 1024 * 1024;

#[derive(Clone)]
pub struct Api {
    pub node: Arc<Node>,
    pub d1: crate::d1::Registry,
    pub durable: crate::durable::Coordinator,
    worker_http: reqwest::Client,
    secret: [u8; 32],
    seen_nonces: Arc<Mutex<HashMap<String, u64>>>,
}

pub async fn serve(
    node: Arc<Node>,
    d1: crate::d1::Registry,
    durable: crate::durable::Coordinator,
) -> Result<SocketAddr> {
    let (address, _server) = serve_managed(node, d1, durable).await?;
    Ok(address)
}

/// Start the peer API and retain a handle for tests or supervised embedders.
/// Dropping the handle detaches the server, matching [`serve`].
pub async fn serve_managed(
    node: Arc<Node>,
    d1: crate::d1::Registry,
    durable: crate::durable::Coordinator,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let secret = node.cfg.cluster_secret_bytes()?;
    let api = Api {
        node: node.clone(),
        d1,
        durable,
        worker_http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?,
        secret,
        seen_nonces: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = router(api);
    let listener = tokio::net::TcpListener::bind(node.cfg.peer_api.listen).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("peer api server died: {e}");
        }
    });
    Ok((addr, server))
}

pub fn router(api: Api) -> Router {
    let routes = Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/status", get(status))
        .route("/v1/storage/status", get(storage_status))
        .route("/v1/storage/probe", post(storage_probe))
        .route("/v1/sync/manifests", get(sync_manifests))
        .route("/v1/sync/claims", get(sync_claims))
        .route("/v1/sync/kv", get(sync_kv_digests))
        .route("/v1/sync/kv/{ns}", get(sync_kv_dump))
        .route("/v1/blob/{sha}", get(blob_get))
        .route("/v1/blob", post(blob_put))
        .route("/v1/manifest", post(manifest_post))
        .route("/v1/resources", get(resource_list))
        .route("/v1/resource", post(resource_post))
        .route("/v1/resource/{kind}/{name}", get(resource_get))
        .route(
            "/v1/authorize/{code}",
            get(authorization_get).post(authorization_post),
        )
        .route("/v1/worker/{name}", get(worker_get))
        .route("/v1/worker-dispatch", post(worker_dispatch))
        .route("/v1/log/{name}", get(log_get))
        .route(
            "/v1/observability/{worker}/requests",
            get(worker_request_logs),
        )
        .route(
            "/v1/observability/{worker}/runtime",
            get(worker_runtime_logs),
        )
        .route("/v1/kv/{ns}", get(kv_list))
        .route(
            "/v1/kv/{ns}/{*key}",
            get(kv_get).post(kv_put).delete(kv_delete),
        )
        .route("/v1/quorum/{db}", post(quorum_msg))
        .route("/v1/d1/create", post(d1_create))
        .route("/v1/d1/{db}/exec", post(d1_exec))
        .route("/v1/queue/{queue}/messages", post(queue_send))
        .route("/v1/queue/{queue}/stats", get(queue_stats))
        .route("/v1/queue/{queue}/dead", get(queue_dead_letters))
        .route("/v1/queue/{queue}/dead/{id}/redrive", post(queue_redrive))
        .route("/v1/cron/{worker}/runs", get(cron_runs))
        .route("/v1/cron/{worker}/fire", post(cron_fire))
        .route("/v1/cron/{worker}/runs/{id}", delete(cron_delete_dlq))
        .route("/v1/cron/{worker}/runs/{id}/replay", post(cron_replay))
        .route(
            "/v1/analytics/{dataset}/events",
            post(analytics_write).get(analytics_recent),
        )
        .route("/v1/analytics/{dataset}/stats", get(analytics_stats))
        .route("/v1/analytics/{dataset}/group", get(analytics_group))
        .route("/v1/pipeline/{pipeline}/events", post(pipeline_ingest))
        .route("/v1/pipeline/{pipeline}/status", get(pipeline_status))
        .route("/v1/pipeline/{pipeline}/batches", get(pipeline_batches))
        .route("/v1/pipeline/{pipeline}/flush", post(pipeline_flush))
        .route(
            "/v1/workflow/{workflow}/instances",
            post(workflow_create).get(workflow_instances),
        )
        .route(
            "/v1/workflow/{workflow}/instances/{id}",
            get(workflow_instance),
        )
        .route(
            "/v1/workflow/{workflow}/instances/{id}/signal",
            post(workflow_signal),
        )
        .route(
            "/v1/workflow/{workflow}/instances/{id}/{action}",
            post(workflow_action),
        )
        .route("/v1/workflow/{workflow}/stats", get(workflow_stats))
        .route("/v1/flow/{flow}/runs", post(flow_create).get(flow_runs))
        .route("/v1/flow/{flow}/runs/{id}", get(flow_run))
        .route("/v1/flow/{flow}/runs/{id}/{action}", post(flow_action))
        .route("/v1/flow/{flow}/stats", get(flow_stats))
        .route(
            "/v1/email/{domain}/verification",
            get(email_verification).post(email_verify),
        )
        .route("/v1/email/{domain}/messages", get(email_messages))
        .route("/v1/email/{domain}/messages/{id}", get(email_message))
        .route(
            "/v1/email/{domain}/messages/{id}/raw",
            get(email_message_raw),
        )
        .route("/v1/email/{domain}/send", post(email_send))
        .route("/v1/do/{worker}/proxy", post(do_proxy))
        .route("/v1/r2/{bucket}", get(r2_list))
        .route("/v1/r2-blob/{sha}", get(r2_blob_get))
        .route("/v1/r2-blob", post(r2_blob_put))
        .route("/v1/binary-blob", post(binary_blob_put))
        .route("/v1/r2/{bucket}/meta/{*key}", get(r2_head))
        .route(
            "/v1/r2/{bucket}/multipart/{upload_id}/part/{part}/{*key}",
            post(r2_multipart_part),
        )
        .route(
            "/v1/r2/{bucket}/multipart/{upload_id}/complete/{*key}",
            post(r2_multipart_complete),
        )
        .route(
            "/v1/r2/{bucket}/object/{*key}",
            get(r2_get).post(r2_put).delete(r2_delete),
        );
    routes
        .layer(middleware::from_fn_with_state(
            api.clone(),
            encrypted_transport,
        ))
        .layer(DefaultBodyLimit::max(MAX_PEER_PAYLOAD + 16))
        .with_state(api)
}

/// Decrypt encrypted peer/CLI requests before handlers see them and
/// encrypt the complete response on the way out. Loopback callers may
/// stay plaintext (workerd bindings); encrypted loopback is accepted
/// so the same PeerClient path is exercised by local tests and CLIs.
async fn encrypted_transport(
    State(api): State<Api>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let encrypted = request
        .headers()
        .get(transport::ENC_HEADER)
        .and_then(|v| v.to_str().ok())
        == Some(transport::VERSION);
    let remote = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let loopback = remote.map(|a| a.ip().is_loopback()).unwrap_or(true);

    // Ping is intentionally public and contains no cluster data.
    if !encrypted {
        if !loopback && request.uri().path() != "/v1/ping" {
            return (
                StatusCode::UPGRADE_REQUIRED,
                "encrypted peer transport required",
            )
                .into_response();
        }
        return next.run(request).await;
    }

    let ts = request
        .headers()
        .get(auth::TS_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let nonce = request
        .headers()
        .get(transport::NONCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let target = request
        .headers()
        .get(transport::TARGET_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if target != api.node.id_hex() {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "encrypted request targets another node",
        )
            .into_response();
    }
    let method = request.method().to_string();
    let path = request_target(request.uri()).to_string();
    let (parts, body) = request.into_parts();
    let ciphertext = match to_bytes(body, MAX_PEER_PAYLOAD + 16).await {
        Ok(v) => v,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "peer payload too large").into_response(),
    };
    let plaintext = match transport::open(
        &api.secret,
        &nonce,
        &transport::request_aad(&ts, &method, &path, &target),
        &ciphertext,
    ) {
        Ok(v) => v,
        Err(_) => return (StatusCode::UNAUTHORIZED, "bad encrypted peer payload").into_response(),
    };

    // Reject exact ciphertext replays inside the otherwise-valid HMAC
    // clock window. The bounded cache is process-local by design: a
    // replay sent to another node still has to represent an operation
    // that the cluster protocols make idempotent.
    let now = now_ms();
    let replayed = {
        let mut seen = api.seen_nonces.lock().unwrap();
        seen.retain(|_, at| now.saturating_sub(*at) <= auth::MAX_SKEW_MS);
        if seen.contains_key(&nonce) {
            true
        } else {
            if seen.len() >= 8192 {
                if let Some(oldest) = seen
                    .iter()
                    .min_by_key(|(_, at)| *at)
                    .map(|(n, _)| n.clone())
                {
                    seen.remove(&oldest);
                }
            }
            seen.insert(nonce.clone(), now);
            false
        }
    };

    let response = if replayed {
        (StatusCode::CONFLICT, "replayed encrypted peer request").into_response()
    } else {
        next.run(Request::from_parts(parts, Body::from(plaintext)))
            .await
    };
    let status = response.status();
    let (mut parts, body) = response.into_parts();
    let plaintext = match to_bytes(body, MAX_PEER_PAYLOAD).await {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode response",
            )
                .into_response()
        }
    };
    let (nonce, ciphertext) = match transport::seal(
        &api.secret,
        &transport::response_aad(&nonce, status.as_u16()),
        &plaintext,
    ) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encrypt response",
            )
                .into_response()
        }
    };
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    parts.headers.insert(
        transport::ENC_HEADER,
        axum::http::HeaderValue::from_static(transport::VERSION),
    );
    parts.headers.insert(
        transport::NONCE_HEADER,
        axum::http::HeaderValue::from_str(&nonce).expect("hex nonce is a header value"),
    );
    Response::from_parts(parts, Body::from(ciphertext))
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
) -> std::result::Result<(), (StatusCode, &'static str)> {
    if remote.ip().is_loopback() {
        return Ok(());
    }
    let ts = headers
        .get(auth::TS_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mac = headers
        .get(auth::MAC_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth::verify(
        &api.secret,
        now_ms(),
        ts,
        mac,
        method.as_str(),
        request_target(uri),
        body,
    ) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "bad or missing cluster MAC"))
    }
}

fn request_target(uri: &Uri) -> &str {
    uri.path_and_query()
        .map(|target| target.as_str())
        .unwrap_or_else(|| uri.path())
}

async fn ping(State(api): State<Api>) -> String {
    format!("rf {}\n", api.node.id_hex())
}

async fn status(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r.into_response();
    }
    let node = &api.node;
    let peer_views = node.peers();
    let local_deployments = node.deployment_statuses();
    let peers: Vec<serde_json::Value> = peer_views
        .clone()
        .into_iter()
        .map(|(id, v)| {
            serde_json::json!({
                "id": id,
                "label": v.label,
                "public": v.public,
                "api": v.api_addr.map(|a| a.to_string()),
                "ip4": v.ipv4,
                "capabilities": v.capabilities,
                "deployments": v.deployments,
            })
        })
        .collect();
    let workers: Vec<serde_json::Value> = node
        .live_manifests()
        .into_iter()
        .map(|m| {
            let default_hostname = node.default_worker_hostname(&m.name);
            let effective_hostnames = node.effective_worker_hostnames(&m);
            let has_do = !crate::deploy::durable_objects(&m).is_empty();
            let do_owner = if has_do {
                api.durable
                    .leader(&m.name)
                    .map(|id| id.to_string())
                    .or_else(|| {
                        peer_views.iter().find_map(|(id, peer)| {
                            peer.deployments
                                .get(&m.name)
                                .filter(|status| {
                                    status.version == m.version && status.state == "running"
                                })
                                .map(|_| id.clone())
                        })
                    })
            } else {
                None
            };
            let durable_owned_here = has_do && do_owner.as_deref() == Some(&node.id_hex());
            let mut deployments = vec![serde_json::json!({
                "node": node.id_hex(),
                "label": node.cfg.label,
                "local": true,
                "status": local_deployments.get(&m.name),
            })];
            for (id, peer) in &peer_views {
                deployments.push(serde_json::json!({
                    "node": id,
                    "label": peer.label,
                    "local": false,
                    "status": peer.deployments.get(&m.name),
                }));
            }
            let ready_nodes = deployments
                .iter()
                .filter(|deployment| {
                    let status = &deployment["status"];
                    status["version"].as_u64() == Some(m.version)
                        && matches!(
                            status["state"].as_str(),
                            Some("ready" | "running" | "standby")
                        )
                })
                .count();
            serde_json::json!({
                "name": m.name,
                "version": m.version,
                "hostnames": effective_hostnames,
                "custom_hostnames": m.hostnames,
                "default_hostname": default_hostname,
                "modules": m.modules.len(),
                "assets": m.assets.len(),
                "crons": m.crons,
                "durable_objects": has_do,
                "durable_owner": do_owner,
                "durable_owned_here": durable_owned_here,
                "distribution": {
                    "ready": ready_nodes,
                    "total": deployments.len(),
                    "nodes": deployments,
                },
            })
        })
        .collect();
    let kv_namespaces: Vec<String> = node
        .kv_digests()
        .into_keys()
        .filter(|namespace| !namespace.starts_with("__rf"))
        .collect();
    let databases: Vec<String> = node
        .kv_list(crate::acme::NS, "d1/", 10_000)
        .into_iter()
        .filter_map(|key| key.strip_prefix("d1/").map(str::to_string))
        .filter(|name| {
            !name.starts_with("r2-")
                && !name.starts_with("rfdo-")
                && !name.starts_with("queue-")
                && !name.starts_with("analytics-")
                && !name.starts_with("pipeline-")
                && !name.starts_with("workflow-")
                && !name.starts_with("flow-")
                && !name.starts_with("email-")
        })
        .collect();
    let buckets: Vec<serde_json::Value> = crate::r2::bucket_records(node)
        .into_iter()
        .map(|(view, spec)| {
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect();
    let queues: Vec<serde_json::Value> = crate::queue::queue_records(node)
        .into_iter()
        .map(|(view, spec)| {
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect();
    let analytics_datasets: Vec<serde_json::Value> = crate::analytics::dataset_records(node)
        .into_iter()
        .map(|(view, spec)| {
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect();
    let pipelines: Vec<serde_json::Value> = crate::pipeline::pipeline_records(node)
        .into_iter()
        .map(|(view, spec)| {
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect();
    let workflows: Vec<serde_json::Value> = crate::workflow::workflow_records(node)
        .into_iter()
        .map(|(view, spec)| {
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect();
    let flows: Vec<serde_json::Value> = crate::flow::flow_records(node)
        .into_iter()
        .map(|(view, spec)| {
            let hostnames = node.effective_flow_hostnames(&view.resource.name, &spec);
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "default_hostname": node.default_flow_hostname(&view.resource.name),
                "hostnames": hostnames,
                "spec": spec,
            })
        })
        .collect();
    let email_domains: Vec<serde_json::Value> = crate::email::email_domain_records(node)
        .into_iter()
        .map(|(view, spec)| {
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect();
    let binaries: Vec<serde_json::Value> = crate::binary::records(node)
        .into_iter()
        .map(|(view, spec)| {
            serde_json::json!({
                "name": view.resource.name,
                "version": view.resource.version,
                "digest": view.digest,
                "spec": spec,
            })
        })
        .collect();
    let storage_policy = crate::storage_policy::current(node)
        .ok()
        .map(|(_, policy)| policy)
        .unwrap_or_default();
    axum::Json(serde_json::json!({
        "node": node.id_hex(),
        "label": node.cfg.label,
        "cluster_id": node.cfg.cluster_id,
        "operator": node.cfg.operator.to_string(),
        "public": node.cfg.public,
        "capabilities": crate::placement::system_tags(node, &node.id_hex()),
        "deployments": local_deployments,
        "default_worker_domain": node.cfg.default_worker_domain(),
        "version": env!("CARGO_PKG_VERSION"),
        "peers": peers,
        "workers": workers,
        "databases": databases,
        "r2_buckets": buckets,
        "queues": queues,
        "analytics_datasets": analytics_datasets,
        "pipelines": pipelines,
        "workflows": workflows,
        "flows": flows,
        "email_domains": email_domains,
        "binaries": binaries,
        "email_node": {
            "enabled": node.cfg.email.enabled,
            "outbound": node.cfg.email.outbound,
            "mx_hostname": node.cfg.email.mx_hostname,
            "smtp_listen": node.cfg.email.smtp_listen.map(|address| address.to_string()),
        },
        "storage": {
            "local": true,
            "rclone": node.cfg.storage.rclone_binary.is_some(),
            "policy": storage_policy,
        },
        "kv_namespaces": kv_namespaces,
        "manifest_digest": node.manifest_digest_hex(),
        "routes": node.routes(),
        "missing_blobs": node.missing_blobs().len(),
    }))
    .into_response()
}

async fn storage_status(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    let operation = async {
        let (view, policy) = crate::storage_policy::current(&api.node)?;
        let distribution = crate::r2::storage_distribution(&api.node).await?;
        Result::<_>::Ok(serde_json::json!({
            "policy": policy,
            "version": view.as_ref().map(|view| view.resource.version),
            "digest": view.as_ref().map(|view| view.digest.clone()),
            "distribution": distribution,
        }))
    }
    .await;
    match operation {
        Ok(value) => axum::Json(value).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, format!("{error:#}")).into_response(),
    }
}

async fn storage_probe(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::storage_policy::current(&api.node) {
        Ok((_, policy)) => {
            axum::Json(crate::storage_policy::probe_remotes(&api.node, &policy).await)
                .into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, format!("{error:#}")).into_response(),
    }
}

async fn sync_manifests(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r.into_response();
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
        return r.into_response();
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
        return r.into_response();
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
        return r.into_response();
    }
    let dump = api.node.kv_dump(&ns);
    postcard::to_stdvec(&dump)
        .map(|b| b.into_response())
        .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
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
        return r.into_response();
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
        return r.into_response();
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
        return r.into_response();
    }
    let Ok(env) = Envelope::from_bytes(&body) else {
        return (StatusCode::BAD_REQUEST, "bad envelope").into_response();
    };
    match ingest_manifest_envelope(&api, &env) {
        Ok(changed) => axum::Json(serde_json::json!({ "changed": changed })).into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response(),
    }
}

async fn authorization_get(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(code): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match api.node.management.view_by_code(&code) {
        Ok(view) => axum::Json(view).into_response(),
        Err(error) => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
    }
}

async fn authorization_post(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(code): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    use base64::Engine as _;

    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let request: crate::management::ApprovalSignature = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid approval: {error}"),
            )
                .into_response();
        }
    };
    let signature =
        match base64::engine::general_purpose::STANDARD.decode(&request.signature_base64) {
            Ok(signature) => signature,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid approval signature: {error}"),
                )
                    .into_response();
            }
        };
    let approved =
        match api
            .node
            .management
            .approve(&code, request.signer, signature, &api.node.cfg.operator)
        {
            Ok(approved) => approved,
            Err(error) => return (StatusCode::FORBIDDEN, error.to_string()).into_response(),
        };

    if approved.kind != crate::management::ApprovalKind::Login {
        let result = match approved.kind {
            crate::management::ApprovalKind::Manifest => {
                ingest_manifest_envelope(&api, &approved.envelope).map(|_| ())
            }
            crate::management::ApprovalKind::Source => {
                crate::build::ingest_source(&api.node, &approved.envelope).map(|_| ())
            }
            crate::management::ApprovalKind::Resource => {
                ingest_resource_envelope(&api, &approved.envelope)
                    .await
                    .map(|_| ())
            }
            crate::management::ApprovalKind::Login => unreachable!(),
        };
        match result {
            Ok(()) => api.node.management.complete(&approved.id, Ok(())),
            Err(error) => {
                let message = error.to_string();
                api.node
                    .management
                    .complete(&approved.id, Err(anyhow::anyhow!(message.clone())));
                return (StatusCode::UNPROCESSABLE_ENTITY, message).into_response();
            }
        }
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "kind": approved.kind,
    }))
    .into_response()
}

fn ingest_manifest_envelope(api: &Api, envelope: &Envelope) -> Result<bool> {
    let manifest: rf_core::manifest::WorkerManifest =
        envelope
            .open(Some(&api.node.cfg.operator))
            .map_err(|error| anyhow::anyhow!("approved manifest could not be decoded: {error}"))?;
    crate::quota::validate_manifest_admission(&api.node, &manifest)?;
    let changed = api.node.ingest_manifest(envelope)?;
    if !crate::deploy::durable_objects(&manifest).is_empty() {
        api.durable.ensure_worker(&manifest.name)?;
    }
    Ok(changed)
}

async fn ingest_resource_envelope(
    api: &Api,
    envelope: &Envelope,
) -> Result<crate::resource::ResourceRecord> {
    let record: crate::resource::ResourceRecord = envelope
        .open(Some(&api.node.cfg.operator))
        .map_err(|error| anyhow::anyhow!("平台资源签名无效：{error}"))?;
    record.validate()?;
    crate::binary::validate_admission(&api.node, &record)?;
    crate::storage_policy::validate_transition(&api.node, &record).await?;
    crate::quota::validate_resource_admission(&api.node, &record)?;
    crate::resource::ingest(&api.node, envelope)
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
        return r.into_response();
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
        return r.into_response();
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

#[derive(Deserialize)]
struct KvListQuery {
    #[serde(default)]
    prefix: String,
    limit: Option<usize>,
}

async fn kv_list(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(ns): Path<String>,
    Query(q): Query<KvListQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, b"") {
        return r.into_response();
    }
    let keys = api
        .node
        .kv_list(&ns, &q.prefix, q.limit.unwrap_or(1000).clamp(1, 10_000));
    axum::Json(serde_json::json!({ "keys": keys })).into_response()
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
        return r.into_response();
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
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_PEER_PAYLOAD).await {
        Ok(body) => body,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "kv payload too large").into_response(),
    };
    if let Err(r) = check(
        &api,
        &remote,
        &parts.headers,
        &parts.method,
        &parts.uri,
        &body,
    ) {
        return r.into_response();
    }
    let expires = q.expires_at_ms.or_else(|| q.ttl_ms.map(|t| now_ms() + t));
    match api.node.kv_put(&ns, &key, Some(body.to_vec()), expires) {
        // Encrypted transport needs to carry an AEAD tag in the body;
        // HTTP forbids bodies on 204 responses.
        Ok(()) => StatusCode::OK.into_response(),
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
        return r.into_response();
    }
    let Ok(wire) = postcard::from_bytes::<crate::d1::WireMsg>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad quorum message").into_response();
    };
    let tx = api.d1.lock().unwrap().get(&db).cloned();
    match tx {
        Some(tx) => {
            let _ = tx.send(crate::d1::DriverCmd::Net(wire)).await;
            StatusCode::OK.into_response()
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
        return r.into_response();
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
    let group = match crate::d1::ensure_database(&api.node, &req.name) {
        Ok(group) => group,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    axum::Json(serde_json::json!({
        "name": req.name,
        "group": group.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn worker_dispatch(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let Ok(dispatch) = postcard::from_bytes::<crate::ingress::WorkerDispatchRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad Worker dispatch request").into_response();
    };
    let manifest = if dispatch.preview {
        crate::preview::active_previews(&api.node)
            .into_iter()
            .find(|(view, spec)| {
                view.resource.name == dispatch.runtime_id
                    && view.resource.version == dispatch.revision
                    && spec.worker == dispatch.worker
                    && spec.manifest.version == dispatch.manifest_version
            })
            .map(|(_, spec)| spec.manifest)
    } else {
        api.node.manifest(&dispatch.worker).filter(|manifest| {
            dispatch.runtime_id == dispatch.worker
                && dispatch.revision == manifest.version
                && dispatch.manifest_version == manifest.version
        })
    };
    let Some(manifest) = manifest else {
        return (StatusCode::CONFLICT, "Worker revision changed").into_response();
    };
    if !crate::placement::eligible(&api.node, &api.node.id_hex(), &manifest) {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "Worker is not placed on this node",
        )
            .into_response();
    }
    if !crate::deploy::durable_objects(&manifest).is_empty() {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "Durable Object Workers require their fenced owner route",
        )
            .into_response();
    }
    if manifest.blob_refs().any(|sha| !api.node.blobs.has(&sha))
        || (!manifest.main.is_empty() && api.node.worker_port(&dispatch.runtime_id).is_none())
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Worker runtime is not ready",
        )
            .into_response();
    }
    let request = match crate::ingress::wire_to_request(dispatch.request) {
        Ok(request) => request,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let path = request.uri().path().to_string();
    let response = crate::ingress::serve_direct_worker(
        &api.node,
        &api.worker_http,
        request,
        &manifest,
        &path,
        &dispatch.runtime_id,
    )
    .await;
    match crate::ingress::response_to_wire(response).await {
        Ok(response) => postcard::to_stdvec(&response)
            .map(|raw| raw.into_response())
            .unwrap_or_else(|error| {
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
            }),
        Err(error) => (StatusCode::BAD_GATEWAY, error).into_response(),
    }
}

async fn do_proxy(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(worker): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check(&api, &remote, &headers, &method, &uri, &body) {
        return r.into_response();
    }
    let Ok(request) = postcard::from_bytes::<crate::durable::ProxyRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad DO proxy request").into_response();
    };
    match api.durable.proxy_on_owner(&worker, request).await {
        Ok(response) => postcard::to_stdvec(&response)
            .map(|raw| raw.into_response())
            .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()),
        Err(e) => (StatusCode::MISDIRECTED_REQUEST, e.to_string()).into_response(),
    }
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
        return r.into_response();
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
                    peers
                        .get(&g.to_string())
                        .and_then(|p| p.api_addr)
                        .map(|a| a.to_string())
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
        .send(crate::d1::DriverCmd::Exec {
            sql: req.sql,
            params: req.params,
            resp: resp_tx,
        })
        .await
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "driver gone").into_response();
    }
    match tokio::time::timeout(std::time::Duration::from_secs(15), resp_rx).await {
        Ok(Ok(Ok(result))) => {
            if result.leader_hint.is_some()
                || (result.rows.is_none() && result.rows_affected.is_none())
            {
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueSendReq {
    messages: Vec<crate::queue::SendMessage>,
}

#[derive(serde::Deserialize)]
struct QueueDeadQuery {
    limit: Option<usize>,
}

async fn queue_send(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(queue): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let Ok(request) = serde_json::from_slice::<QueueSendReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad queue send request").into_response();
    };
    match crate::queue::enqueue(&api.node, &queue, request.messages).await {
        Ok(ids) => axum::Json(serde_json::json!({ "message_ids": ids })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn queue_stats(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(queue): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::queue::stats(&api.node, &queue).await {
        Ok(stats) => axum::Json(stats).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn queue_dead_letters(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(queue): Path<String>,
    Query(query): Query<QueueDeadQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::queue::list_dead_letters(&api.node, &queue, query.limit.unwrap_or(100)).await {
        Ok(dead_letters) => {
            axum::Json(serde_json::json!({ "dead_letters": dead_letters })).into_response()
        }
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn queue_redrive(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((queue, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    match crate::queue::redrive_dead_letter(&api.node, &queue, &id).await {
        Ok(true) => axum::Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "dead letter not found").into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct WorkerRequestLogsQuery {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    limit: Option<usize>,
}

async fn worker_request_logs(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(worker): Path<String>,
    Query(query): Query<WorkerRequestLogsQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    if !rf_core::manifest::valid_name(&worker) {
        return (StatusCode::BAD_REQUEST, "invalid worker name").into_response();
    }
    if query
        .status
        .is_some_and(|status| !(2..=5).contains(&status))
    {
        return (
            StatusCode::BAD_REQUEST,
            "status must be a class from 2 to 5",
        )
            .into_response();
    }
    match crate::observability::snapshot(
        &api.node,
        &worker,
        query.hostname.as_deref().filter(|value| !value.is_empty()),
        query.status,
        query.limit.unwrap_or(200),
    ) {
        Ok(snapshot) => axum::Json(snapshot).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct WorkerRuntimeLogsQuery {
    limit: Option<usize>,
}

async fn worker_runtime_logs(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(worker): Path<String>,
    Query(query): Query<WorkerRuntimeLogsQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    if !rf_core::manifest::valid_name(&worker) {
        return (StatusCode::BAD_REQUEST, "invalid worker name").into_response();
    }
    axum::Json(crate::observability::RuntimeLogSnapshot {
        node: api.node.id_hex(),
        label: api.node.cfg.label.clone(),
        lines: api
            .node
            .runtime_logs(&worker, query.limit.unwrap_or(300).clamp(1, 1_000)),
    })
    .into_response()
}

#[derive(serde::Deserialize)]
struct CronRunsQuery {
    #[serde(default)]
    dlq: bool,
    limit: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CronFireRequest {
    #[serde(default)]
    expression: Option<String>,
}

async fn cron_runs(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(worker): Path<String>,
    Query(query): Query<CronRunsQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::cron_driver::list_runs(&api.node, &worker, query.dlq, query.limit.unwrap_or(100))
        .await
    {
        Ok(runs) => axum::Json(serde_json::json!({ "runs": runs })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn cron_fire(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(worker): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let request = if body.is_empty() {
        CronFireRequest { expression: None }
    } else {
        match serde_json::from_slice::<CronFireRequest>(&body) {
            Ok(request) => request,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad Cron fire request").into_response(),
        }
    };
    match crate::cron_driver::fire_now(&api.node, &worker, request.expression.as_deref()).await {
        Ok(run) => axum::Json(run).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn cron_replay(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((worker, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    match crate::cron_driver::replay_dlq(&api.node, &worker, &id).await {
        Ok(Some(run)) => axum::Json(run).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Cron DLQ run not found").into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn cron_delete_dlq(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((worker, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::cron_driver::delete_dlq(&api.node, &worker, &id).await {
        Ok(true) => axum::Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "Cron DLQ run not found").into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsWriteReq {
    points: Vec<crate::analytics::DataPoint>,
}

#[derive(serde::Deserialize)]
struct AnalyticsRecentQuery {
    before: Option<u64>,
    limit: Option<usize>,
}

#[derive(serde::Deserialize)]
struct AnalyticsGroupQuery {
    #[serde(default = "default_analytics_dimension")]
    dimension: String,
    #[serde(default)]
    dimension_index: usize,
    double_index: Option<usize>,
    #[serde(default)]
    since: u64,
    limit: Option<usize>,
}

fn default_analytics_dimension() -> String {
    "blob".into()
}

async fn analytics_write(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(dataset): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let Ok(request) = serde_json::from_slice::<AnalyticsWriteReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad Analytics write request").into_response();
    };
    match crate::analytics::write(&api.node, &dataset, request.points).await {
        Ok(written) => axum::Json(serde_json::json!({ "written": written })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn analytics_recent(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(dataset): Path<String>,
    Query(query): Query<AnalyticsRecentQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::analytics::recent(
        &api.node,
        &dataset,
        query.before,
        query.limit.unwrap_or(100),
    )
    .await
    {
        Ok(events) => axum::Json(serde_json::json!({ "events": events })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn analytics_stats(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(dataset): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::analytics::stats(&api.node, &dataset).await {
        Ok(stats) => axum::Json(stats).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn analytics_group(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(dataset): Path<String>,
    Query(query): Query<AnalyticsGroupQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::analytics::group_by(
        &api.node,
        &dataset,
        &query.dimension,
        query.dimension_index,
        query.double_index,
        query.since,
        query.limit.unwrap_or(20),
    )
    .await
    {
        Ok(groups) => axum::Json(serde_json::json!({ "groups": groups })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineIngestReq {
    events: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct PipelineBatchQuery {
    limit: Option<usize>,
}

async fn pipeline_ingest(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(pipeline): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let Ok(request) = serde_json::from_slice::<PipelineIngestReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad Pipeline ingest request").into_response();
    };
    match crate::pipeline::ingest(&api.node, &pipeline, request.events).await {
        Ok(accepted) => axum::Json(serde_json::json!({ "accepted": accepted })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn pipeline_status(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(pipeline): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::pipeline::status(&api.node, &pipeline).await {
        Ok(status) => axum::Json(status).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn pipeline_batches(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(pipeline): Path<String>,
    Query(query): Query<PipelineBatchQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::pipeline::batches(&api.node, &pipeline, query.limit.unwrap_or(100)).await {
        Ok(batches) => axum::Json(serde_json::json!({ "batches": batches })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn pipeline_flush(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(pipeline): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    match crate::pipeline::flush_once(&api.node, &pipeline, true).await {
        Ok(batch) => axum::Json(serde_json::json!({ "batch": batch })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowCreateReq {
    instance_key: Option<String>,
    #[serde(default)]
    input: serde_json::Value,
}

async fn workflow_create(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(workflow): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let Ok(request) = serde_json::from_slice::<WorkflowCreateReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "Workflow 创建请求无效").into_response();
    };
    match crate::workflow::create_instance(
        &api.node,
        &workflow,
        request.instance_key.as_deref(),
        request.input,
    )
    .await
    {
        Ok(instance) => axum::Json(instance).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct WorkflowListQuery {
    status: Option<String>,
    limit: Option<usize>,
}

async fn workflow_instances(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(workflow): Path<String>,
    Query(query): Query<WorkflowListQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::workflow::instances(
        &api.node,
        &workflow,
        query.status.as_deref(),
        query.limit.unwrap_or(100),
    )
    .await
    {
        Ok(instances) => axum::Json(serde_json::json!({ "instances": instances })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn workflow_instance(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((workflow, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    let instance = match crate::workflow::instance(&api.node, &workflow, &id).await {
        Ok(Some(instance)) => instance,
        Ok(None) => return (StatusCode::NOT_FOUND, "Workflow 实例不存在").into_response(),
        Err(error) => return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    };
    let (steps, signals, events) = tokio::join!(
        crate::workflow::steps(&api.node, &workflow, &id),
        crate::workflow::signals(&api.node, &workflow, &id),
        crate::workflow::events(&api.node, &workflow, &id, 500),
    );
    match (steps, signals, events) {
        (Ok(steps), Ok(signals), Ok(events)) => axum::Json(serde_json::json!({
            "instance": instance,
            "steps": steps,
            "signals": signals,
            "events": events,
        }))
        .into_response(),
        (steps, signals, events) => {
            let error = steps
                .err()
                .or_else(|| signals.err())
                .or_else(|| events.err())
                .expect("one branch failed");
            (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowSignalReq {
    name: String,
    #[serde(default)]
    payload: serde_json::Value,
}

async fn workflow_signal(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((workflow, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let Ok(request) = serde_json::from_slice::<WorkflowSignalReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "Workflow 信号请求无效").into_response();
    };
    match crate::workflow::send_signal(&api.node, &workflow, &id, &request.name, request.payload)
        .await
    {
        Ok(signal_id) => axum::Json(serde_json::json!({ "signal_id": signal_id })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn workflow_action(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((workflow, id, action)): Path<(String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let changed = match action.as_str() {
        "pause" => crate::workflow::pause(&api.node, &workflow, &id).await,
        "resume" => crate::workflow::resume(&api.node, &workflow, &id).await,
        "terminate" => crate::workflow::terminate(&api.node, &workflow, &id).await,
        "restart" => crate::workflow::restart(&api.node, &workflow, &id).await,
        _ => return (StatusCode::NOT_FOUND, "Workflow 操作不存在").into_response(),
    };
    match changed {
        Ok(true) => axum::Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            "Workflow 实例不存在或当前状态不允许此操作",
        )
            .into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn workflow_stats(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(workflow): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::workflow::stats(&api.node, &workflow).await {
        Ok(stats) => axum::Json(stats).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowCreateReq {
    #[serde(default)]
    run_key: Option<String>,
    #[serde(default)]
    input: serde_json::Value,
}

async fn flow_create(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(flow): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let Ok(request) = serde_json::from_slice::<FlowCreateReq>(&body) else {
        return (StatusCode::BAD_REQUEST, "Flow 触发请求无效").into_response();
    };
    match crate::flow::create_run(
        &api.node,
        &flow,
        request.run_key.as_deref(),
        "manual",
        request.input,
    )
    .await
    {
        Ok(run) => (StatusCode::ACCEPTED, axum::Json(run)).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct FlowRunsQuery {
    status: Option<String>,
    limit: Option<usize>,
}

async fn flow_runs(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(flow): Path<String>,
    Query(query): Query<FlowRunsQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::flow::runs(
        &api.node,
        &flow,
        query.status.as_deref(),
        query.limit.unwrap_or(100),
    )
    .await
    {
        Ok(runs) => axum::Json(runs).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn flow_run(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((flow, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    let run = match crate::flow::run(&api.node, &flow, &id).await {
        Ok(Some(run)) => run,
        Ok(None) => return (StatusCode::NOT_FOUND, "Flow 运行不存在").into_response(),
        Err(error) => return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    };
    let (steps, events) = tokio::join!(
        crate::flow::run_steps(&api.node, &flow, &id),
        crate::flow::run_events(&api.node, &flow, &id, 500),
    );
    match (steps, events) {
        (Ok(steps), Ok(events)) => axum::Json(serde_json::json!({
            "run": run,
            "steps": steps,
            "events": events,
        }))
        .into_response(),
        (steps, events) => {
            let error = steps
                .err()
                .or_else(|| events.err())
                .expect("one branch failed");
            (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response()
        }
    }
}

async fn flow_action(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((flow, id, action)): Path<(String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    match action.as_str() {
        "cancel" => match crate::flow::cancel(&api.node, &flow, &id).await {
            Ok(true) => axum::Json(serde_json::json!({ "ok": true })).into_response(),
            Ok(false) => (StatusCode::CONFLICT, "Flow 运行不存在或已进入终态").into_response(),
            Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
        },
        "retry" => match crate::flow::retry(&api.node, &flow, &id).await {
            Ok(run) => (StatusCode::ACCEPTED, axum::Json(run)).into_response(),
            Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
        },
        _ => (StatusCode::NOT_FOUND, "Flow 操作不存在").into_response(),
    }
}

async fn flow_stats(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(flow): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::flow::stats(&api.node, &flow).await {
        Ok(stats) => axum::Json(stats).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct EmailMessagesQuery {
    limit: Option<usize>,
}

async fn email_verification(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(domain): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    if crate::email::email_domain_record(&api.node, &domain).is_none() {
        return (StatusCode::NOT_FOUND, "邮件域不存在").into_response();
    }
    match crate::email::latest_verification(&api.node, &domain).await {
        Ok(verification) => axum::Json(serde_json::json!({
            "verification": verification,
        }))
        .into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn email_verify(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(domain): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    match crate::email::verify_domain(&api.node, &domain).await {
        Ok(verification) => axum::Json(verification).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn email_messages(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(domain): Path<String>,
    Query(query): Query<EmailMessagesQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    if crate::email::email_domain_record(&api.node, &domain).is_none() {
        return (StatusCode::NOT_FOUND, "邮件域不存在").into_response();
    }
    match crate::email::list_messages(&api.node, &domain, query.limit.unwrap_or(100)).await {
        Ok(messages) => axum::Json(serde_json::json!({ "messages": messages })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn email_message(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((domain, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::email::get_message(&api.node, &domain, &id).await {
        Ok(Some(message)) => axum::Json(message).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "邮件记录不存在").into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn email_message_raw(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((domain, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    let Some(message) = (match crate::email::get_message(&api.node, &domain, &id).await {
        Ok(message) => message,
        Err(error) => {
            return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response();
        }
    }) else {
        return (StatusCode::NOT_FOUND, "邮件记录不存在").into_response();
    };
    let Some((_, spec)) = crate::email::email_domain_record(&api.node, &domain) else {
        return (StatusCode::NOT_FOUND, "邮件域不存在").into_response();
    };
    match crate::r2::get_object(&api.node, &spec.bucket, &message.object_key).await {
        Ok(Some((_metadata, raw))) => {
            ([(axum::http::header::CONTENT_TYPE, "message/rfc822")], raw).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "邮件原文对象不存在").into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn email_send(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(domain): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let (metadata, raw) = match crate::email::decode_send_request(&body) {
        Ok(request) => request,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match crate::email::queue_outbound(
        &api.node,
        &domain,
        &metadata.mail_from,
        &metadata.recipients,
        raw,
    )
    .await
    {
        Ok(queued) => (
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({
                "queued": queued,
            })),
        )
            .into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
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
        return r.into_response();
    }
    match api.node.kv_put(&ns, &key, None, None) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct R2ListQuery {
    #[serde(default)]
    prefix: String,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn r2_list(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(bucket): Path<String>,
    Query(query): Query<R2ListQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match r2::list_objects(
        &api.node,
        &bucket,
        &query.prefix,
        query.cursor.as_deref(),
        query.limit.unwrap_or(100),
    )
    .await
    {
        Ok(objects) => axum::Json(objects).into_response(),
        Err(error) => r2_error(error),
    }
}

async fn r2_head(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((bucket, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match r2::head_object(&api.node, &bucket, &key).await {
        Ok(Some(metadata)) => axum::Json(metadata).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "R2 对象不存在").into_response(),
        Err(error) => r2_error(error),
    }
}

async fn r2_get(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((bucket, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match r2::get_object(&api.node, &bucket, &key).await {
        Ok(Some((metadata, bytes))) => match r2::encode_get_response(&metadata, &bytes) {
            Ok(response) => response.into_response(),
            Err(error) => r2_error(error),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "R2 对象不存在").into_response(),
        Err(error) => r2_error(error),
    }
}

async fn r2_put(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((bucket, key)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_PEER_PAYLOAD).await {
        Ok(body) => body,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "R2 对象过大").into_response(),
    };
    if let Err(response) = check(
        &api,
        &remote,
        &parts.headers,
        &parts.method,
        &parts.uri,
        &body,
    ) {
        return response.into_response();
    }
    let (options, bytes) = match r2::decode_put_request(&body) {
        Ok(request) => request,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match r2::put_object(&api.node, &bucket, &key, bytes, options).await {
        Ok(metadata) => axum::Json(metadata).into_response(),
        Err(error) => r2_error(error),
    }
}

async fn r2_delete(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((bucket, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match r2::delete_object(&api.node, &bucket, &key).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "R2 对象不存在").into_response(),
        Err(error) => r2_error(error),
    }
}

async fn r2_multipart_part(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((bucket, upload_id, part, key)): Path<(String, String, u32, String)>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_PEER_PAYLOAD).await {
        Ok(body) => body,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "R2 multipart 分片过大").into_response(),
    };
    if let Err(response) = check(
        &api,
        &remote,
        &parts.headers,
        &parts.method,
        &parts.uri,
        &body,
    ) {
        return response.into_response();
    }
    match r2::upload_part(&api.node, &bucket, &key, &upload_id, part, &body).await {
        Ok(uploaded) => axum::Json(uploaded).into_response(),
        Err(error) => r2_error(error),
    }
}

async fn r2_multipart_complete(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((bucket, upload_id, key)): Path<(String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let published: Vec<r2::PublishedPart> = match serde_json::from_slice(&body) {
        Ok(parts) => parts,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match r2::complete_multipart_upload(&api.node, &bucket, &key, &upload_id, &published).await {
        Ok(metadata) => axum::Json(metadata).into_response(),
        Err(error) => r2_error(error),
    }
}

fn r2_error(error: anyhow::Error) -> Response {
    let message = format!("{error:#}");
    let status = if message.contains("不存在") {
        StatusCode::NOT_FOUND
    } else if message.contains("配额不足") {
        StatusCode::INSUFFICIENT_STORAGE
    } else if message.contains("不具备") || message.contains("rclone") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, message).into_response()
}

async fn r2_blob_get(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(sha): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    let digest: [u8; 32] = match hex::decode(&sha).ok().and_then(|raw| raw.try_into().ok()) {
        Some(digest) => digest,
        None => return (StatusCode::BAD_REQUEST, "R2 对象摘要无效").into_response(),
    };
    match api
        .node
        .objects
        .get(&crate::objectstore::StorageLocation::Local, &digest)
        .await
    {
        Ok(bytes) => bytes.into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "R2 对象副本不存在").into_response(),
    }
}

async fn r2_blob_put(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    if body.len() > crate::binary::MAX_BINARY_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "内容地址对象副本过大").into_response();
    }
    match api
        .node
        .objects
        .put(&crate::objectstore::StorageLocation::Local, &body)
        .await
    {
        Ok(digest) => hex::encode(digest).into_response(),
        Err(error) => r2_error(error),
    }
}

#[derive(Deserialize)]
struct BinaryBlobQuery {
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    prefix: String,
}

async fn binary_blob_put(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Query(query): Query<BinaryBlobQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let storage = match query.remote {
        Some(remote) => crate::objectstore::StorageLocation::Rclone {
            remote,
            prefix: query.prefix,
        },
        None if query.prefix.is_empty() => crate::objectstore::StorageLocation::Local,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Binary rclone prefix 必须与 remote 一起使用",
            )
                .into_response();
        }
    };
    match crate::binary::store_bytes(&api.node, &storage, &body).await {
        Ok((sha256, size_bytes)) => axum::Json(serde_json::json!({
            "sha256": sha256,
            "size_bytes": size_bytes,
            "storage": storage,
        }))
        .into_response(),
        Err(error) => r2_error(error),
    }
}

#[derive(Deserialize)]
struct ResourceListQuery {
    kind: Option<String>,
}

async fn resource_list(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Query(query): Query<ResourceListQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    axum::Json(crate::resource::heads(&api.node, query.kind.as_deref())).into_response()
}

async fn resource_get(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((kind, name)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, b"") {
        return response.into_response();
    }
    match crate::resource::head(&api.node, &kind, &name) {
        Some(resource) => axum::Json(resource).into_response(),
        None => (StatusCode::NOT_FOUND, "平台资源不存在").into_response(),
    }
}

async fn resource_post(
    State(api): State<Api>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = check(&api, &remote, &headers, &method, &uri, &body) {
        return response.into_response();
    }
    let envelope = match Envelope::from_bytes(&body) {
        Ok(envelope) => envelope,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match ingest_resource_envelope(&api, &envelope).await {
        Ok(resource) => axum::Json(resource).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_target_includes_query_string() {
        let uri: Uri = "/v1/kv/ns?prefix=a%20b&limit=5".parse().unwrap();
        assert_eq!(request_target(&uri), "/v1/kv/ns?prefix=a%20b&limit=5");
    }
}
