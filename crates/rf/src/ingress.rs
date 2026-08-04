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
use anyhow::Result;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{uri::Authority, uri::Uri, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rf_core::manifest::WorkerManifest;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Clone)]
pub struct Ingress {
    node: Arc<Node>,
    http: reqwest::Client,
    durable: crate::durable::Coordinator,
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
    let app = app(node, durable, false)?;
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

    if !crate::deploy::durable_objects(&manifest).is_empty() {
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

async fn request_to_wire(
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
    let body = axum::body::to_bytes(body, 64 * 1024 * 1024)
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
    Ok(crate::durable::ProxyRequest {
        method: parts.method.to_string(),
        path_and_query,
        headers,
        body: body.to_vec(),
    })
}

fn wire_to_response(response: crate::durable::ProxyResponse) -> Response {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(response.body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
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

fn is_hop_header(name: &str) -> bool {
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
}
