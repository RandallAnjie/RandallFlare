//! Ingress: the public HTTP(S) listeners. Routes by HTTP/2 `:authority`
//! or the HTTP/1.1 Host header against the manifest routing table.
//!
//! - Static assets are served natively from the
//!   blob store — no workerd involved: exact path, then
//!   `<path>/index.html`, then `404.html`, then plain 404. A worker
//!   with BOTH modules and assets gets asset-first fallthrough: asset
//!   hit wins, miss goes to the module.
//! - Module workers proxy to the local workerd port.
//! - TLS: serve_tls with the SNI cert store (<data>/certs, ACME- or
//!   certbot-fed, hot-reloaded).

use crate::node::Node;
use crate::peers::PeerClient;
use anyhow::Result;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{uri::Authority, uri::Uri, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt as _;
use rf_core::manifest::WorkerManifest;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

const MAX_FORWARDED_BODY: usize = 63 * 1024 * 1024;
const MAX_FORWARDED_HEADERS: usize = 256;
const MAX_FORWARDED_HEADER_BYTES: usize = 256 * 1024;
const MAX_FORWARDED_TARGET_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct Ingress {
    node: Arc<Node>,
    http: reqwest::Client,
    durable: crate::durable::Coordinator,
    peers: PeerClient,
    console: axum::Router,
}

fn app(
    node: Arc<Node>,
    durable: crate::durable::Coordinator,
    secure_console: bool,
) -> Result<axum::Router> {
    let console = crate::console::router(crate::console::ConsoleState::public(
        node.clone(),
        secure_console,
    )?);
    let ingress = Ingress {
        peers: PeerClient::new(node.cfg.cluster_secret_bytes()?),
        node,
        durable,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?,
        console,
    };
    Ok(axum::Router::new().fallback(handle).with_state(ingress))
}

pub async fn serve(
    node: Arc<Node>,
    durable: crate::durable::Coordinator,
    listen: SocketAddr,
) -> Result<SocketAddr> {
    let (address, _server) = serve_managed(node, durable, listen).await?;
    Ok(address)
}

pub async fn serve_managed(
    node: Arc<Node>,
    durable: crate::durable::Coordinator,
    listen: SocketAddr,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let app = app(node, durable, false)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("ingress server died: {e}");
        }
    });
    Ok((addr, server))
}

/// HTTPS ingress: SNI cert store from <data>/certs (hot-reloaded),
/// self-signed fallback for unknown hosts. Same router as HTTP.
pub async fn serve_tls(
    node: Arc<Node>,
    durable: crate::durable::Coordinator,
    listen: SocketAddr,
) -> Result<()> {
    let store = crate::tls::spawn_store(node.cfg.data_dir.join("certs"))?;
    let rustls_cfg = crate::tls::server_config(store);
    let app = app(node, durable, true)?;
    let config = axum_server::tls_rustls::RustlsConfig::from_config(rustls_cfg);
    tokio::spawn(async move {
        if let Err(e) = axum_server::bind_rustls(listen, config)
            .serve(app.into_make_service())
            .await
        {
            tracing::error!("tls ingress died: {e}");
        }
    });
    Ok(())
}

async fn handle(State(ingress): State<Ingress>, req: Request) -> Response {
    let host = request_hostname(&req);

    // A node's literal IP is its stable bootstrap/admin address and cannot be
    // shadowed by a Worker manifest. Named hosts remain Worker-first; an
    // unclaimed name falls through to the same decentralized console.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return ingress
            .console
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|never| match never {});
    }

    // Signed previews have their own deterministic host and runtime identity.
    // They never advance or shadow the production manifest chain.
    if let Some((view, preview)) = crate::preview::find_by_hostname(&ingress.node, &host) {
        return serve_observed_worker(
            &ingress,
            req,
            &preview.manifest,
            &host,
            &view.resource.name,
            false,
        )
        .await;
    }

    if let Some((workflow, spec)) = crate::workflow::workflow_records(&ingress.node)
        .into_iter()
        .find_map(|(view, spec)| {
            ingress
                .node
                .effective_workflow_hostnames(&view.resource.name, &spec)
                .iter()
                .any(|candidate| candidate == &host)
                .then_some((view.resource.name, spec))
        })
    {
        return serve_workflow_ingress(&ingress.node, req, &workflow, &spec).await;
    }

    if let Some((flow, spec)) = crate::flow::flow_records(&ingress.node)
        .into_iter()
        .find_map(|(view, spec)| {
            ingress
                .node
                .effective_flow_hostnames(&view.resource.name, &spec)
                .iter()
                .any(|candidate| candidate == &host)
                .then_some((view.resource.name, spec))
        })
    {
        return serve_flow_ingress(&ingress.node, req, &flow, &spec).await;
    }

    if let Some((pipeline, spec)) = crate::pipeline::pipeline_records(&ingress.node)
        .into_iter()
        .find_map(|(view, spec)| {
            ingress
                .node
                .effective_pipeline_hostnames(&view.resource.name, &spec)
                .iter()
                .any(|candidate| candidate == &host)
                .then_some((view.resource.name, spec))
        })
    {
        return serve_pipeline_ingress(&ingress.node, req, &pipeline, &spec).await;
    }

    if let Some((bucket, spec)) = crate::r2::bucket_records(&ingress.node)
        .into_iter()
        .find_map(|(view, spec)| {
            ingress
                .node
                .effective_r2_hostnames(&view.resource.name, &spec)
                .iter()
                .any(|candidate| candidate == &host)
                .then_some((view.resource.name, spec))
        })
    {
        return serve_public_r2(&ingress.node, req, &bucket, &spec).await;
    }

    let routes = ingress.node.routes();
    let Some(worker_name) = routes.get(&host) else {
        return ingress
            .console
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|never| match never {});
    };
    let Some(manifest) = ingress.node.manifest(worker_name) else {
        return (StatusCode::NOT_FOUND, "worker vanished\n").into_response();
    };

    let runtime_id = manifest.name.clone();
    serve_observed_worker(&ingress, req, &manifest, &host, &runtime_id, true).await
}

async fn serve_observed_worker(
    ingress: &Ingress,
    req: Request,
    manifest: &WorkerManifest,
    hostname: &str,
    runtime_id: &str,
    durable_coordinator: bool,
) -> Response {
    match ingress.node.admit_public_request() {
        Ok(true) => {}
        Ok(false) => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "已达到 RandallFlare 集群每分钟请求配额\n",
            )
                .into_response();
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("60"),
            );
            return response;
        }
        Err(error) => {
            tracing::error!("无法读取集群配额策略：{error:#}");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "集群配额策略无效，已安全拒绝请求\n",
            )
                .into_response();
        }
    }
    let method = req.method().as_str().to_string();
    // Deliberately discard the query string. Observability stores only the
    // matched path and never inspects headers or bodies.
    let path = req.uri().path().to_string();
    let started = std::time::Instant::now();
    let response = serve_worker(
        ingress,
        req,
        manifest,
        &path,
        runtime_id,
        durable_coordinator,
    )
    .await;
    crate::observability::record(
        &ingress.node,
        &crate::observability::RequestObservation {
            worker: &manifest.name,
            version: manifest.version,
            hostname,
            method: &method,
            path: &path,
            status_code: response.status().as_u16(),
            duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        },
    );
    response
}

fn is_websocket_upgrade(req: &Request) -> bool {
    req.method() == Method::GET
        && req
            .headers()
            .get(axum::http::header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        && req
            .headers()
            .get(axum::http::header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

fn websocket_request_to_wire(
    req: &Request,
) -> std::result::Result<crate::durable::ProxyRequest, Box<Response>> {
    if req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value != "0")
    {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, "WebSocket 握手不能包含请求体").into_response(),
        ));
    }
    let authority = request_authority(req)
        .map(str::as_bytes)
        .map(ToOwned::to_owned);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let mut headers = req
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    if !req.headers().contains_key(axum::http::header::HOST) {
        if let Some(authority) = authority {
            headers.push(("host".into(), authority));
        }
    }
    if path_and_query.len() > MAX_FORWARDED_TARGET_BYTES
        || headers.len() > MAX_FORWARDED_HEADERS
        || headers.iter().fold(0usize, |total, (name, value)| {
            total.saturating_add(name.len()).saturating_add(value.len())
        }) > MAX_FORWARDED_HEADER_BYTES
    {
        return Err(Box::new(
            (
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "WebSocket 请求头或请求目标过大",
            )
                .into_response(),
        ));
    }
    Ok(crate::durable::ProxyRequest {
        method: "GET".into(),
        path_and_query,
        headers,
        body: vec![],
    })
}

fn websocket_upgrade_response(headers: &axum::http::HeaderMap) -> Response {
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            crate::transport::ENC_HEADER
                | crate::transport::NONCE_HEADER
                | crate::transport::TARGET_HEADER
                | crate::auth::TS_HEADER
                | crate::auth::MAC_HEADER
                | crate::durable::TUNNEL_PROOF_HEADER
                | "content-length"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

async fn serve_worker_websocket(
    ingress: &Ingress,
    mut req: Request,
    manifest: &WorkerManifest,
    runtime_id: &str,
    durable_coordinator: bool,
) -> Response {
    let wire = match websocket_request_to_wire(&req) {
        Ok(wire) => wire,
        Err(response) => return *response,
    };
    let browser_upgrade = hyper::upgrade::on(&mut req);
    let fenced_durable = durable_coordinator
        && runtime_id == manifest.name
        && !crate::deploy::durable_objects(manifest).is_empty();

    if fenced_durable && ingress.durable.is_owner(&manifest.name) {
        let Some(port) = ingress.node.worker_port(&manifest.name) else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Durable Object 所有者运行时正在启动\n",
            )
                .into_response();
        };
        return match crate::durable::open_worker_websocket(&ingress.http, &wire, port).await {
            Ok((headers, mut upstream)) => {
                tokio::spawn(async move {
                    match browser_upgrade.await {
                        Ok(browser) => {
                            let mut browser = hyper_util::rt::TokioIo::new(browser);
                            if let Err(error) =
                                tokio::io::copy_bidirectional(&mut browser, &mut upstream).await
                            {
                                tracing::debug!("本地 Worker WebSocket 已结束：{error}");
                            }
                        }
                        Err(error) => tracing::debug!("浏览器 WebSocket 升级失败：{error}"),
                    }
                });
                websocket_upgrade_response(&headers)
            }
            Err(error) => (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
        };
    }

    let revision = if runtime_id == manifest.name {
        manifest.version
    } else {
        crate::resource::head(&ingress.node, crate::preview::PREVIEW_KIND, runtime_id)
            .map(|view| view.resource.version)
            .unwrap_or(0)
    };
    let local_eligible =
        crate::placement::eligible(&ingress.node, &ingress.node.id_hex(), manifest);
    if !fenced_durable && local_eligible && local_worker_ready(&ingress.node, manifest, runtime_id)
    {
        let port = ingress
            .node
            .worker_port(runtime_id)
            .expect("local_worker_ready checked the module runtime");
        return match crate::durable::open_worker_websocket(&ingress.http, &wire, port).await {
            Ok((headers, mut upstream)) => {
                tokio::spawn(async move {
                    match browser_upgrade.await {
                        Ok(browser) => {
                            let mut browser = hyper_util::rt::TokioIo::new(browser);
                            if let Err(error) =
                                tokio::io::copy_bidirectional(&mut browser, &mut upstream).await
                            {
                                tracing::debug!("本地 Worker WebSocket 已结束：{error}");
                            }
                        }
                        Err(error) => tracing::debug!("浏览器 WebSocket 升级失败：{error}"),
                    }
                });
                websocket_upgrade_response(&headers)
            }
            Err(error) => (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
        };
    }

    let dispatch = WorkerTunnelRequest {
        worker: manifest.name.clone(),
        runtime_id: runtime_id.to_string(),
        manifest_version: manifest.version,
        revision,
        preview: runtime_id != manifest.name,
        fenced_durable,
        request: wire,
    };
    let body = match postcard::to_stdvec(&dispatch) {
        Ok(body) => body,
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    };
    let mut candidates = if fenced_durable {
        let mut ids = Vec::new();
        if let Some(leader) = ingress.durable.leader(&manifest.name) {
            ids.push(leader);
        }
        if let Some(raw) = ingress.node.kv_get(
            crate::acme::NS,
            &crate::d1::kv_key(&crate::durable::Coordinator::db_name(&manifest.name)),
        ) {
            if let Ok(meta) = serde_json::from_slice::<crate::d1::DbMeta>(&raw) {
                ids.extend(meta.group);
            }
        }
        ids.into_iter()
            .filter(|id| *id != ingress.node.id())
            .filter_map(|id| {
                ingress
                    .node
                    .peers()
                    .get(&id.to_string())
                    .and_then(|peer| peer.api_addr)
                    .map(|api| ([0u8; 32], id.to_string(), api))
            })
            .collect::<Vec<_>>()
    } else {
        ingress
            .node
            .peers()
            .into_iter()
            .filter(|(id, peer)| {
                crate::placement::eligible(&ingress.node, id, manifest)
                    && peer.api_addr.is_some()
                    && peer.deployments.get(runtime_id).is_some_and(|status| {
                        status.version == revision
                            && matches!(status.state.as_str(), "ready" | "running")
                    })
            })
            .filter_map(|(id, peer)| {
                peer.api_addr
                    .map(|api| (placement_score(runtime_id, &id), id, api))
            })
            .collect::<Vec<_>>()
    };
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.0));
    let mut last_error = None;
    for (_, id, api) in candidates {
        match ingress
            .peers
            .open_tunnel(&api.to_string(), "/v1/worker-tunnel", body.clone())
            .await
        {
            Ok(tunnel) => {
                let headers = tunnel.headers.clone();
                let secret = match ingress.node.cfg.cluster_secret_bytes() {
                    Ok(secret) => secret,
                    Err(error) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
                            .into_response()
                    }
                };
                tokio::spawn(async move {
                    match browser_upgrade.await {
                        Ok(browser) => {
                            let browser = hyper_util::rt::TokioIo::new(browser);
                            if let Err(error) = crate::durable::relay_tunnel_ingress(
                                browser,
                                tunnel.stream,
                                secret,
                                tunnel.session,
                            )
                            .await
                            {
                                tracing::debug!("跨节点 Worker WebSocket 已结束：{error:#}");
                            }
                        }
                        Err(error) => tracing::debug!("浏览器 WebSocket 升级失败：{error}"),
                    }
                });
                return websocket_upgrade_response(&headers);
            }
            Err(error) => last_error = Some(format!("节点 {id} 不可用：{error}")),
        }
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        last_error.unwrap_or_else(|| "没有可用的 Worker WebSocket 目标节点".into()),
    )
        .into_response()
}

async fn serve_worker(
    ingress: &Ingress,
    req: Request,
    manifest: &WorkerManifest,
    path: &str,
    runtime_id: &str,
    durable_coordinator: bool,
) -> Response {
    if !manifest.main.is_empty() && is_websocket_upgrade(&req) {
        return serve_worker_websocket(ingress, req, manifest, runtime_id, durable_coordinator)
            .await;
    }
    // Durable Objects already have a fenced owner and their own encrypted
    // forwarding path. Do not send them through the stateless placement path.
    if durable_coordinator && !crate::deploy::durable_objects(manifest).is_empty() {
        let wire = match request_to_wire(req).await {
            Ok(wire) => wire,
            Err(response) => return response,
        };
        return match ingress.durable.dispatch(&manifest.name, wire).await {
            Ok(response) => wire_to_response(response),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Durable Object owner unavailable: {e}\n"),
            )
                .into_response(),
        };
    }

    let revision = if runtime_id == manifest.name {
        manifest.version
    } else {
        crate::resource::head(&ingress.node, crate::preview::PREVIEW_KIND, runtime_id)
            .map(|view| view.resource.version)
            .unwrap_or(0)
    };
    let local_eligible =
        crate::placement::eligible(&ingress.node, &ingress.node.id_hex(), manifest);
    if !local_eligible || !local_worker_ready(&ingress.node, manifest, runtime_id) {
        let wire = match request_to_wire(req).await {
            Ok(wire) => wire,
            Err(response) => return response,
        };
        return dispatch_placed_worker(
            ingress,
            manifest,
            runtime_id,
            revision,
            runtime_id != manifest.name,
            wire,
        )
        .await;
    }

    serve_direct_worker(
        &ingress.node,
        &ingress.http,
        req,
        manifest,
        path,
        runtime_id,
    )
    .await
}

fn local_worker_ready(node: &Node, manifest: &WorkerManifest, runtime_id: &str) -> bool {
    let blobs_ready = manifest.blob_refs().all(|sha| node.blobs.has(&sha));
    blobs_ready && (manifest.main.is_empty() || node.worker_port(runtime_id).is_some())
}

async fn dispatch_placed_worker(
    ingress: &Ingress,
    manifest: &WorkerManifest,
    runtime_id: &str,
    revision: u64,
    preview: bool,
    request: crate::durable::ProxyRequest,
) -> Response {
    let payload = WorkerDispatchRequest {
        worker: manifest.name.clone(),
        runtime_id: runtime_id.to_string(),
        manifest_version: manifest.version,
        revision,
        preview,
        request,
    };
    let Ok(body) = postcard::to_stdvec(&payload) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let peers = ingress.node.peers();
    let mut candidates = peers
        .iter()
        .filter(|(id, peer)| {
            crate::placement::eligible(&ingress.node, id, manifest)
                && peer.api_addr.is_some()
                && peer.deployments.get(runtime_id).is_some_and(|status| {
                    status.version == revision
                        && matches!(status.state.as_str(), "ready" | "running")
                })
        })
        .map(|(id, peer)| (placement_score(runtime_id, id), id, peer))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.0));
    let mut last_error = None;
    for (_, id, peer) in candidates {
        let Some(api) = peer.api_addr else { continue };
        match ingress
            .peers
            .post(&api.to_string(), "/v1/worker-dispatch", body.clone())
            .await
        {
            Ok(raw) => match postcard::from_bytes::<crate::durable::ProxyResponse>(&raw) {
                Ok(response) => return wire_to_response(response),
                Err(error) => last_error = Some(format!("节点 {id} 返回了无效响应：{error}")),
            },
            Err(error) => last_error = Some(format!("节点 {id} 不可用：{error}")),
        }
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!(
            "没有可用的合格 Worker 节点{}\n",
            last_error
                .map(|error| format!("：{error}"))
                .unwrap_or_default()
        ),
    )
        .into_response()
}

fn placement_score(runtime_id: &str, node_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("{runtime_id}\0{node_id}").as_bytes()).into()
}

/// A complete request forwarded over the encrypted peer transport. The target
/// independently resolves and verifies the immutable revision before serving.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerDispatchRequest {
    pub worker: String,
    pub runtime_id: String,
    pub manifest_version: u64,
    pub revision: u64,
    pub preview: bool,
    pub request: crate::durable::ProxyRequest,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerTunnelRequest {
    pub worker: String,
    pub runtime_id: String,
    pub manifest_version: u64,
    pub revision: u64,
    pub preview: bool,
    pub fenced_durable: bool,
    pub request: crate::durable::ProxyRequest,
}

pub(crate) async fn serve_direct_worker(
    node: &Node,
    http: &reqwest::Client,
    req: Request,
    manifest: &WorkerManifest,
    path: &str,
    runtime_id: &str,
) -> Response {
    // Asset tree first (assets-only workers and hybrid fallthrough).
    if !manifest.assets.is_empty() {
        if let Some(resp) = serve_asset(node, manifest, path) {
            return resp;
        }
        if manifest.main.is_empty() {
            // Pure static site: custom 404 page or plain 404.
            return not_found_page(node, manifest);
        }
    }

    if manifest.main.is_empty() {
        return not_found_page(node, manifest);
    }

    // Module worker: proxy to local workerd.
    let Some(port) = node.worker_port(runtime_id) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "worker not running on this node\n",
        )
            .into_response();
    };
    proxy(http, req, port).await
}

async fn serve_flow_ingress(
    node: &Node,
    req: Request,
    flow: &str,
    spec: &crate::flow::FlowSpec,
) -> Response {
    if spec.trigger != crate::flow::FlowTrigger::Webhook {
        return StatusCode::NOT_FOUND.into_response();
    }
    if req.method() != Method::POST || !matches!(req.uri().path(), "/" | "/hook" | "/v1/run") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !flow_token_authorized(req.headers(), spec) {
        let mut response = (StatusCode::UNAUTHORIZED, "Flow Webhook 令牌无效\n").into_response();
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"RandallFlare Flow\""),
        );
        return response;
    }
    let run_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let wait = req.uri().query().is_some_and(|query| {
        query
            .split('&')
            .any(|pair| matches!(pair, "wait=1" | "sync=1"))
    });
    let body = match axum::body::to_bytes(req.into_body(), crate::flow::MAX_RUN_INPUT_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Flow 输入不得超过 4 MiB\n").into_response()
        }
    };
    let input = if body.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(input) => input,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Flow 输入必须是 JSON：{error}\n"),
                )
                    .into_response();
            }
        }
    };
    let run = match crate::flow::create_run(node, flow, run_key.as_deref(), "webhook", input).await
    {
        Ok(run) => run,
        Err(error) => return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    };
    if !wait {
        return (
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({
                "id": run.id,
                "status": run.status,
                "createdAtMs": run.created_at_ms,
            })),
        )
            .into_response();
    }
    match crate::flow::wait_run(node, flow, &run.id, std::time::Duration::from_secs(25)).await {
        Ok(run) if run.status == "complete" => (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "ok": true,
                "id": run.id,
                "status": run.status,
                "output": run.output,
            })),
        )
            .into_response(),
        Ok(run) if run.status == "failed" => (
            StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({
                "ok": false,
                "id": run.id,
                "status": run.status,
                "error": run.error,
            })),
        )
            .into_response(),
        Ok(run) if run.status == "cancelled" => (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "ok": false,
                "id": run.id,
                "status": run.status,
                "error": "Flow 运行已取消",
            })),
        )
            .into_response(),
        Ok(run) => (
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({
                "ok": true,
                "id": run.id,
                "status": run.status,
            })),
        )
            .into_response(),
        Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
    }
}

async fn serve_workflow_ingress(
    node: &Node,
    req: Request,
    workflow: &str,
    spec: &crate::workflow::WorkflowSpec,
) -> Response {
    if !spec.webhook_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if req.method() != Method::POST || !matches!(req.uri().path(), "/" | "/hook" | "/v1/run") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            req.headers()
                .get("x-workflow-token")
                .and_then(|value| value.to_str().ok())
        });
    if !token.is_some_and(|token| crate::workflow::token_matches(spec, token.trim())) {
        let mut response =
            (StatusCode::UNAUTHORIZED, "Workflow Webhook 令牌无效\n").into_response();
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"RandallFlare Workflow\""),
        );
        return response;
    }
    let instance_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let concurrency_group = req
        .headers()
        .get("x-workflow-concurrency-group")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = match axum::body::to_bytes(req.into_body(), crate::workflow::MAX_INPUT_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Workflow 输入不得超过 4 MiB\n",
            )
                .into_response()
        }
    };
    let input = if body.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(input) => input,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Workflow 输入必须是 JSON：{error}\n"),
                )
                    .into_response()
            }
        }
    };
    match crate::workflow::create_instance_in_group(
        node,
        workflow,
        instance_key.as_deref(),
        concurrency_group.as_deref(),
        input,
    )
    .await
    {
        Ok(instance) => (
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({
                "id": instance.id,
                "status": instance.status,
                "definitionVersion": instance.definition_version,
                "concurrencyGroup": instance.concurrency_group,
                "concurrencyGroupLimit": instance.concurrency_group_limit,
                "startedAtMs": instance.started_at_ms,
            })),
        )
            .into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

fn flow_token_authorized(headers: &axum::http::HeaderMap, spec: &crate::flow::FlowSpec) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get("x-flow-token")
                .and_then(|value| value.to_str().ok())
        })
        .is_some_and(|token| crate::flow::token_matches(spec, token.trim()))
}

async fn serve_pipeline_ingress(
    node: &Node,
    req: Request,
    pipeline: &str,
    spec: &crate::pipeline::PipelineSpec,
) -> Response {
    let path = req.uri().path();
    if req.method() == Method::GET && path == "/status" {
        if !pipeline_bearer_authorized(req.headers(), spec) {
            return pipeline_unauthorized();
        }
        return match crate::pipeline::status(node, pipeline).await {
            Ok(status) => axum::Json(status).into_response(),
            Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
        };
    }
    if req.method() != Method::POST || !matches!(path, "/" | "/send" | "/v1/events") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !pipeline_bearer_authorized(req.headers(), spec) {
        return pipeline_unauthorized();
    }
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = req.into_body().into_data_stream().map(|chunk| {
        chunk.map_err(|error| std::io::Error::other(format!("Pipeline 请求体读取失败：{error}")))
    });
    let staged = match node
        .objects
        .spool_stream(crate::pipeline::MAX_INGEST_BYTES as u64, Box::pin(body))
        .await
    {
        Ok(staged) => staged,
        Err(error) => return (StatusCode::PAYLOAD_TOO_LARGE, error.to_string()).into_response(),
    };
    let events = match crate::pipeline::parse_staged_payload(content_type, &staged).await {
        Ok(events) => events,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match crate::pipeline::ingest(node, pipeline, events).await {
        Ok(accepted) => (
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({ "accepted": accepted })),
        )
            .into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

fn pipeline_bearer_authorized(
    headers: &axum::http::HeaderMap,
    spec: &crate::pipeline::PipelineSpec,
) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| crate::pipeline::token_matches(spec, token.trim()))
}

fn pipeline_unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Pipeline 接收令牌无效\n").into_response();
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"RandallFlare Pipeline\""),
    );
    response
}

async fn serve_public_r2(
    node: &Node,
    req: Request,
    bucket: &str,
    spec: &crate::r2::BucketSpec,
) -> Response {
    if !spec.public_access {
        return StatusCode::NOT_FOUND.into_response();
    }
    if req.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_r2_cors(req.headers(), spec, &mut response);
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, HEAD, OPTIONS"),
        );
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Range, If-None-Match"),
        );
        response.headers_mut().insert(
            axum::http::header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        return response;
    }
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let key = match percent_encoding::percent_decode_str(req.uri().path().trim_start_matches('/'))
        .decode_utf8()
    {
        Ok(key) if !key.is_empty() => key.into_owned(),
        _ => return (StatusCode::BAD_REQUEST, "invalid object key\n").into_response(),
    };
    let origin_headers = req.headers().clone();
    let metadata = match crate::r2::head_object(node, bucket, &key).await {
        Ok(Some(metadata)) => metadata,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::warn!("public R2 read {bucket}/{key}: {error:#}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if req
        .headers()
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|etag| {
                let etag = etag.trim().trim_start_matches("W/").trim_matches('"');
                etag == "*" || etag == metadata.etag
            })
        })
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        add_r2_object_headers(&metadata, &mut response);
        apply_r2_cors(&origin_headers, spec, &mut response);
        return response;
    }
    let range = req
        .headers()
        .get(axum::http::header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|header| public_byte_range(header, metadata.size));
    let (status, start, length, content_range) = match range {
        Some(Ok((start, end))) => (
            StatusCode::PARTIAL_CONTENT,
            start,
            end - start + 1,
            Some(format!("bytes {start}-{end}/{}", metadata.size)),
        ),
        Some(Err(())) => {
            let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            if let Ok(value) = HeaderValue::from_str(&format!("bytes */{}", metadata.size)) {
                response
                    .headers_mut()
                    .insert(axum::http::header::CONTENT_RANGE, value);
            }
            apply_r2_cors(&origin_headers, spec, &mut response);
            return response;
        }
        None => (StatusCode::OK, 0, metadata.size, None),
    };
    let mut response = if req.method() == Method::HEAD {
        status.into_response()
    } else {
        let file = match crate::r2::materialize_object(node, bucket, &key).await {
            Ok(Some((current, file))) if current.sha256 == metadata.sha256 => file,
            Ok(Some(_)) => return StatusCode::CONFLICT.into_response(),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(error) => {
                tracing::warn!("public R2 stream {bucket}/{key}: {error:#}");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        };
        let stream = match file.stream(start, length).await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!("public R2 stream range {bucket}/{key}: {error:#}");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        };
        Response::builder()
            .status(status)
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    };
    add_r2_object_headers(&metadata, &mut response);
    response.headers_mut().insert(
        axum::http::header::ACCEPT_RANGES,
        HeaderValue::from_static("bytes"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).unwrap(),
    );
    if let Some(content_range) = content_range {
        if let Ok(value) = HeaderValue::from_str(&content_range) {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_RANGE, value);
        }
    }
    apply_r2_cors(&origin_headers, spec, &mut response);
    response
}

fn add_r2_object_headers(metadata: &crate::r2::ObjectMeta, response: &mut Response) {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", metadata.etag)) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    if let Some(content_type) = &metadata.content_type {
        if let Ok(value) = HeaderValue::from_str(content_type) {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_TYPE, value);
        }
    }
    for (field, header) in [
        ("cacheControl", axum::http::header::CACHE_CONTROL),
        (
            "contentDisposition",
            axum::http::header::CONTENT_DISPOSITION,
        ),
        ("contentEncoding", axum::http::header::CONTENT_ENCODING),
        ("contentLanguage", axum::http::header::CONTENT_LANGUAGE),
    ] {
        if let Some(value) = metadata
            .http_metadata
            .get(field)
            .and_then(|value| value.as_str())
        {
            if let Ok(value) = HeaderValue::from_str(value) {
                response.headers_mut().insert(header, value);
            }
        }
    }
}

fn apply_r2_cors(
    headers: &axum::http::HeaderMap,
    spec: &crate::r2::BucketSpec,
    response: &mut Response,
) {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let allowed = if spec.cors_origins.iter().any(|value| value == "*") {
        "*"
    } else if spec.cors_origins.iter().any(|value| value == origin) {
        origin
    } else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(allowed) {
        response
            .headers_mut()
            .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("ETag, Content-Length, Content-Range"),
    );
    if allowed != "*" {
        response
            .headers_mut()
            .append(axum::http::header::VARY, HeaderValue::from_static("Origin"));
    }
}

fn public_byte_range(header: &str, size: u64) -> std::result::Result<(u64, u64), ()> {
    let value = header.strip_prefix("bytes=").ok_or(())?;
    if size == 0 || value.contains(',') {
        return Err(());
    }
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        return Ok((size.saturating_sub(suffix), size - 1));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if start >= size || start > end {
        return Err(());
    }
    Ok((start, end))
}

fn request_authority(req: &Request) -> Option<&str> {
    req.uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            req.headers()
                .get(axum::http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
}

fn request_hostname(req: &Request) -> String {
    req.uri()
        .authority()
        .map(|authority| authority.host().to_ascii_lowercase())
        .or_else(|| {
            req.headers()
                .get(axum::http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<Authority>().ok())
                .map(|authority| authority.host().to_ascii_lowercase())
        })
        .unwrap_or_default()
}

pub(crate) async fn request_to_wire(
    req: Request,
) -> std::result::Result<crate::durable::ProxyRequest, Response> {
    let authority = request_authority(&req)
        .map(str::as_bytes)
        .map(ToOwned::to_owned);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, MAX_FORWARDED_BODY)
        .await
        .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response())?;
    let mut headers: Vec<(String, Vec<u8>)> = parts
        .headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    if !parts.headers.contains_key(axum::http::header::HOST) {
        if let Some(authority) = authority {
            headers.push(("host".to_string(), authority));
        }
    }
    if path_and_query.len() > MAX_FORWARDED_TARGET_BYTES
        || headers.len() > MAX_FORWARDED_HEADERS
        || headers.iter().fold(0usize, |total, (name, value)| {
            total.saturating_add(name.len()).saturating_add(value.len())
        }) > MAX_FORWARDED_HEADER_BYTES
    {
        return Err((
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "Worker 请求头或请求目标过大",
        )
            .into_response());
    }
    Ok(crate::durable::ProxyRequest {
        method: parts.method.to_string(),
        path_and_query,
        headers,
        body: body.to_vec(),
    })
}

pub(crate) fn wire_to_response(response: crate::durable::ProxyResponse) -> Response {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(response.body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

pub(crate) fn wire_to_request(
    request: crate::durable::ProxyRequest,
) -> std::result::Result<Request, &'static str> {
    let header_bytes = request.headers.iter().fold(0usize, |total, (name, value)| {
        total.saturating_add(name.len()).saturating_add(value.len())
    });
    if request.body.len() > MAX_FORWARDED_BODY
        || request.headers.len() > MAX_FORWARDED_HEADERS
        || header_bytes > MAX_FORWARDED_HEADER_BYTES
        || request.path_and_query.len() > MAX_FORWARDED_TARGET_BYTES
    {
        return Err("forwarded Worker request is too large");
    }
    let method = Method::from_bytes(request.method.as_bytes()).map_err(|_| "invalid method")?;
    let uri = request
        .path_and_query
        .parse::<Uri>()
        .map_err(|_| "invalid request target")?;
    if uri.scheme().is_some() || uri.authority().is_some() || !uri.path().starts_with('/') {
        return Err("invalid request target");
    }
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in request.headers {
        if is_hop_header(&name) {
            continue;
        }
        let name = axum::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "invalid request header")?;
        let value = HeaderValue::from_bytes(&value).map_err(|_| "invalid request header")?;
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(request.body))
        .map_err(|_| "invalid forwarded request")
}

pub(crate) async fn response_to_wire(
    response: Response,
) -> std::result::Result<crate::durable::ProxyResponse, &'static str> {
    let status = response.status().as_u16();
    let headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .filter(|(name, _)| !is_hop_header(name.as_str()))
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    if headers.len() > MAX_FORWARDED_HEADERS
        || headers.iter().fold(0usize, |total, (name, value)| {
            total.saturating_add(name.len()).saturating_add(value.len())
        }) > MAX_FORWARDED_HEADER_BYTES
    {
        return Err("Worker response headers are too large");
    }
    let body = axum::body::to_bytes(response.into_body(), MAX_FORWARDED_BODY)
        .await
        .map_err(|_| "Worker response exceeds 64 MiB")?;
    Ok(crate::durable::ProxyResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

fn serve_asset(node: &Node, m: &WorkerManifest, path: &str) -> Option<Response> {
    let clean = path.trim_start_matches('/');
    let candidates = if clean.is_empty() {
        vec!["index.html".to_string()]
    } else {
        vec![
            clean.to_string(),
            format!("{}/index.html", clean.trim_end_matches('/')),
        ]
    };
    for cand in candidates {
        if let Some(asset) = m.assets.iter().find(|a| a.path == cand) {
            if let Ok(bytes) = node.blobs.get(&asset.sha256) {
                let mime = mime_guess::from_path(&cand).first_or_octet_stream();
                let mut resp = bytes.into_response();
                resp.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_str(mime.as_ref())
                        .unwrap_or(HeaderValue::from_static("application/octet-stream")),
                );
                return Some(resp);
            }
        }
    }
    None
}

fn not_found_page(node: &Node, m: &WorkerManifest) -> Response {
    if let Some(asset) = m.assets.iter().find(|a| a.path == "404.html") {
        if let Ok(bytes) = node.blobs.get(&asset.sha256) {
            let mut resp = (StatusCode::NOT_FOUND, bytes).into_response();
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            return resp;
        }
    }
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

async fn proxy(client: &reqwest::Client, req: Request, port: u16) -> Response {
    let original_authority = request_authority(&req).map(str::to_owned);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let url = format!("http://127.0.0.1:{port}{path_and_query}");

    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response();
        }
    };
    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    let mut builder = client.request(method, &url).body(body_bytes.to_vec());
    for (name, value) in parts.headers.iter() {
        if name == axum::http::header::HOST || is_hop_header(name.as_str()) {
            continue; // workerd sees its loopback host; original in X-Forwarded-Host
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    if let Some(authority) = original_authority {
        builder = builder.header("x-forwarded-host", authority);
    }
    match builder.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut out = Response::builder().status(status);
            for (name, value) in resp.headers().iter() {
                if !is_hop_header(name.as_str()) {
                    out = out.header(name.as_str(), value.as_bytes());
                }
            }
            out.body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream: {e}\n")).into_response(),
    }
}

pub(crate) fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

// Silence unused-import when compiled without the uri helper in play.
#[allow(unused)]
fn _uri_type_anchor(_: Uri) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_supports_http2_authority_and_http1_host() {
        let http2 = Request::builder()
            .uri("https://Worker.Example:443/path")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_authority(&http2), Some("Worker.Example:443"));
        assert_eq!(request_hostname(&http2), "worker.example");

        let http1 = Request::builder()
            .uri("/path")
            .header(axum::http::header::HOST, "[2001:db8::1]:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_hostname(&http1), "[2001:db8::1]");
    }

    #[test]
    fn public_r2_ranges_cover_open_suffix_and_invalid_requests() {
        assert_eq!(public_byte_range("bytes=2-4", 10), Ok((2, 4)));
        assert_eq!(public_byte_range("bytes=8-", 10), Ok((8, 9)));
        assert_eq!(public_byte_range("bytes=-3", 10), Ok((7, 9)));
        assert_eq!(public_byte_range("bytes=-99", 10), Ok((0, 9)));
        assert_eq!(public_byte_range("bytes=11-", 10), Err(()));
        assert_eq!(public_byte_range("bytes=1-2,4-5", 10), Err(()));
    }

    #[test]
    fn encrypted_worker_forwarding_accepts_only_bounded_origin_form_requests() {
        let request = crate::durable::ProxyRequest {
            method: "POST".into(),
            path_and_query: "/v1/items?limit=2".into(),
            headers: vec![("content-type".into(), b"application/json".to_vec())],
            body: br#"{"ok":true}"#.to_vec(),
        };
        let rebuilt = wire_to_request(request).unwrap();
        assert_eq!(rebuilt.method(), Method::POST);
        assert_eq!(
            rebuilt.uri().path_and_query().unwrap().as_str(),
            "/v1/items?limit=2"
        );

        let absolute = crate::durable::ProxyRequest {
            method: "GET".into(),
            path_and_query: "http://metadata.invalid/latest".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(wire_to_request(absolute).is_err());
        let excessive_headers = crate::durable::ProxyRequest {
            method: "GET".into(),
            path_and_query: "/".into(),
            headers: (0..=MAX_FORWARDED_HEADERS)
                .map(|index| (format!("x-test-{index}"), vec![b'x']))
                .collect(),
            body: vec![],
        };
        assert!(wire_to_request(excessive_headers).is_err());
    }

    #[test]
    fn websocket_upgrade_detection_and_wire_metadata_are_strict() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/room?name=main")
            .header(axum::http::header::HOST, "chat.example")
            .header(axum::http::header::CONNECTION, "keep-alive, Upgrade")
            .header(axum::http::header::UPGRADE, "websocket")
            .header("sec-websocket-key", "test-key")
            .body(Body::empty())
            .unwrap();
        assert!(is_websocket_upgrade(&request));
        let wire = websocket_request_to_wire(&request).unwrap();
        assert_eq!(wire.path_and_query, "/room?name=main");
        assert!(wire
            .headers
            .iter()
            .any(|(name, value)| name == "upgrade" && value == b"websocket"));

        let post = Request::builder()
            .method(Method::POST)
            .header(axum::http::header::CONNECTION, "upgrade")
            .header(axum::http::header::UPGRADE, "websocket")
            .body(Body::empty())
            .unwrap();
        assert!(!is_websocket_upgrade(&post));

        let body_claim = Request::builder()
            .method(Method::GET)
            .header(axum::http::header::CONNECTION, "upgrade")
            .header(axum::http::header::UPGRADE, "websocket")
            .header(axum::http::header::CONTENT_LENGTH, "1")
            .body(Body::empty())
            .unwrap();
        assert!(websocket_request_to_wire(&body_claim).is_err());
    }

    #[test]
    fn websocket_response_does_not_expose_peer_transport_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONNECTION,
            HeaderValue::from_static("upgrade"),
        );
        headers.insert(
            axum::http::header::UPGRADE,
            HeaderValue::from_static("websocket"),
        );
        headers.insert(
            crate::transport::NONCE_HEADER,
            HeaderValue::from_static("secret-session-metadata"),
        );
        headers.insert(
            crate::durable::TUNNEL_PROOF_HEADER,
            HeaderValue::from_static("proof"),
        );
        let response = websocket_upgrade_response(&headers);
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response.headers().get(axum::http::header::UPGRADE),
            Some(&HeaderValue::from_static("websocket"))
        );
        assert!(!response
            .headers()
            .contains_key(crate::transport::NONCE_HEADER));
        assert!(!response
            .headers()
            .contains_key(crate::durable::TUNNEL_PROOF_HEADER));
    }
}
