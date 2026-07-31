//! Ingress: the :80 listener on public nodes. Routes by Host header
//! against the manifest routing table.
//!
//! - Assets (the merged Pages product) are served natively from the
//!   blob store — no workerd involved: exact path, then
//!   `<path>/index.html`, then `404.html`, then plain 404. A worker
//!   with BOTH modules and assets gets asset-first fallthrough: asset
//!   hit wins, miss goes to the module.
//! - Module workers proxy to the local workerd port.
//! - TLS (:443, rcgen self-signed + ACME claims) is v0.2; run behind
//!   the operator's TLS terminator or plain HTTP until then.

use crate::node::Node;
use anyhow::Result;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{uri::Uri, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rf_core::manifest::WorkerManifest;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct Ingress {
    node: Arc<Node>,
    http: reqwest::Client,
}

fn app(node: Arc<Node>) -> Result<axum::Router> {
    let ingress = Ingress {
        node,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?,
    };
    Ok(axum::Router::new().fallback(handle).with_state(ingress))
}

pub async fn serve(node: Arc<Node>, listen: SocketAddr) -> Result<SocketAddr> {
    let app = app(node)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("ingress server died: {e}");
        }
    });
    Ok(addr)
}

/// HTTPS ingress: SNI cert store from <data>/certs (hot-reloaded),
/// self-signed fallback for unknown hosts. Same router as HTTP.
pub async fn serve_tls(node: Arc<Node>, listen: SocketAddr) -> Result<()> {
    let store = crate::tls::spawn_store(node.cfg.data_dir.join("certs"))?;
    let rustls_cfg = crate::tls::server_config(store);
    let app = app(node)?;
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
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
        .unwrap_or_default();

    let routes = ingress.node.routes();
    let Some(worker_name) = routes.get(&host) else {
        return (StatusCode::NOT_FOUND, format!("no worker bound to {host}\n"))
            .into_response();
    };
    let Some(manifest) = ingress.node.manifest(worker_name) else {
        return (StatusCode::NOT_FOUND, "worker vanished\n").into_response();
    };

    let path = req.uri().path().to_string();

    // Asset tree first (assets-only workers and hybrid fallthrough).
    if !manifest.assets.is_empty() {
        if let Some(resp) = serve_asset(&ingress.node, &manifest, &path) {
            return resp;
        }
        if manifest.main.is_empty() {
            // Pure static site: custom 404 page or plain 404.
            return not_found_page(&ingress.node, &manifest);
        }
    }

    if manifest.main.is_empty() {
        return not_found_page(&ingress.node, &manifest);
    }

    // Module worker: proxy to local workerd.
    let Some(port) = ingress.node.worker_port(&manifest.name) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "worker not running on this node\n",
        )
            .into_response();
    };
    proxy(&ingress.http, req, port).await
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
        if name == axum::http::header::HOST {
            continue; // workerd sees its loopback host; original in X-Forwarded-Host
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    if let Some(host) = parts.headers.get(axum::http::header::HOST) {
        builder = builder.header("x-forwarded-host", host.as_bytes());
    }
    match builder.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut out = Response::builder().status(status);
            for (name, value) in resp.headers().iter() {
                out = out.header(name.as_str(), value.as_bytes());
            }
            match resp.bytes().await {
                Ok(bytes) => out
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()),
                Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
            }
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream: {e}\n")).into_response(),
    }
}

// Silence unused-import when compiled without the uri helper in play.
#[allow(unused)]
fn _uri_type_anchor(_: Uri) {}
