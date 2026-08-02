//! TLS for ingress: an SNI-resolving cert store.
//!
//! Certs live as PEM pairs on disk: <data>/certs/<hostname>.crt +
//! <hostname>.key. Drop files in (certbot, your own CA, or — later —
//! the claim-driven ACME renewer) and the reload loop picks them up
//! within a minute; no restart. Unknown SNI falls back to a
//! boot-generated self-signed cert so the handshake fails loudly at
//! the certificate layer instead of silently at TCP.
//!
//! A wildcard file named `_wildcard.<domain>.crt` matches
//! `*.<domain>` (single label), mirroring certbot's file naming.

use anyhow::{Context, Result};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct SniStore {
    /// hostname (or "_wildcard.<domain>") → key
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    fallback: Arc<CertifiedKey>,
}

impl SniStore {
    pub fn hosts(&self) -> Vec<String> {
        self.certs.read().unwrap().keys().cloned().collect()
    }

    fn lookup(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let map = self.certs.read().unwrap();
        if let Some(ck) = map.get(sni) {
            return Some(ck.clone());
        }
        // single-label wildcard: a.example.com → _wildcard.example.com
        if let Some((_, rest)) = sni.split_once('.') {
            if let Some(ck) = map.get(&format!("_wildcard.{rest}")) {
                return Some(ck.clone());
            }
        }
        None
    }
}

impl ResolvesServerCert for SniStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match hello.server_name() {
            Some(sni) => Some(self.lookup(sni).unwrap_or_else(|| self.fallback.clone())),
            None => Some(self.fallback.clone()),
        }
    }
}

fn load_pem_pair(crt: &Path, key: &Path) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(crt)?))
            .collect::<std::result::Result<_, _>>()
            .context("parsing cert chain")?;
    let key_der: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))
            .context("parsing key")?
            .ok_or_else(|| anyhow::anyhow!("no private key in {}", key.display()))?;
    let signing = any_supported_type(&key_der).context("unsupported key type")?;
    Ok(CertifiedKey::new(certs, signing))
}

fn scan_dir(dir: &Path) -> HashMap<String, Arc<CertifiedKey>> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("crt") {
            continue;
        }
        let Some(host) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let key = path.with_extension("key");
        match load_pem_pair(&path, &key) {
            Ok(ck) => {
                out.insert(host.to_ascii_lowercase(), Arc::new(ck));
            }
            Err(e) => tracing::warn!("skipping cert {}: {e:#}", path.display()),
        }
    }
    out
}

fn self_signed_fallback() -> Result<CertifiedKey> {
    let cert = rcgen::generate_simple_self_signed(vec!["rf.invalid".to_string()])?;
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("self-signed key: {e}"))?;
    let signing = any_supported_type(&key_der)?;
    Ok(CertifiedKey::new(vec![cert.cert.der().clone()], signing))
}

/// Build the store + spawn the reload loop.
pub fn spawn_store(cert_dir: PathBuf) -> Result<Arc<SniStore>> {
    std::fs::create_dir_all(&cert_dir)?;
    let store = Arc::new(SniStore {
        certs: RwLock::new(scan_dir(&cert_dir)),
        fallback: Arc::new(self_signed_fallback()?),
    });
    let loaded = store.hosts();
    if loaded.is_empty() {
        tracing::warn!(
            "no certs in {} — TLS serves a self-signed fallback until you drop \
             <hostname>.crt/.key pairs in",
            cert_dir.display()
        );
    } else {
        tracing::info!("loaded TLS certs for: {}", loaded.join(", "));
    }
    let reload = store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let fresh = scan_dir(&cert_dir);
            *reload.certs.write().unwrap() = fresh;
        }
    });
    Ok(store)
}

/// rustls ServerConfig around the store (http/1.1 + h2).
pub fn server_config(store: Arc<SniStore>) -> Arc<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(store);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_self_signed(dir: &Path, host: &str) {
        let cert = rcgen::generate_simple_self_signed(vec![host.to_string()]).unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(format!("{host}.crt")), cert.cert.pem()).unwrap();
        std::fs::write(
            dir.join(format!("{host}.key")),
            cert.signing_key.serialize_pem(),
        )
        .unwrap();
    }

    #[test]
    fn scan_loads_pairs_and_lookup_matches_wildcard() {
        let dir = std::env::temp_dir().join(format!("rf-tls-{}", rand::random::<u32>()));
        write_self_signed(&dir, "site.example.com");
        write_self_signed(&dir, "_wildcard.edge.example.com");
        let store = SniStore {
            certs: RwLock::new(scan_dir(&dir)),
            fallback: Arc::new(self_signed_fallback().unwrap()),
        };
        assert!(store.lookup("site.example.com").is_some());
        assert!(store.lookup("a.edge.example.com").is_some());
        assert!(store.lookup("a.b.edge.example.com").is_none()); // single label only
        assert!(store.lookup("other.com").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn broken_pair_skipped_not_fatal() {
        let dir = std::env::temp_dir().join(format!("rf-tls-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bad.example.com.crt"), "not pem").unwrap();
        std::fs::write(dir.join("bad.example.com.key"), "not pem").unwrap();
        assert!(scan_dir(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
