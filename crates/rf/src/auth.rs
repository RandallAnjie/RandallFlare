//! Peer API auth: HMAC-SHA256 over (timestamp, method, path, body
//! hash) with the cluster secret. Keeps strangers off the API without
//! a PKI; confidentiality on the wire is v0.2 (overlay/mTLS) — nothing
//! secret travels in v0.1 requests except worker env vars, so deploy
//! from a trusted network or over the overlay until then.
//!
//! Loopback requests skip auth: workerd bindings and same-host CLI
//! calls come from 127.0.0.1 and hold no cluster secret. A node is a
//! single-tenant machine; if that assumption breaks, so does this.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const TS_HEADER: &str = "x-rf-ts";
pub const MAC_HEADER: &str = "x-rf-mac";
/// Accept clocks this far apart (ms).
pub const MAX_SKEW_MS: u64 = 120_000;

pub fn mac_hex(secret: &[u8; 32], ts_ms: u64, method: &str, path: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(ts_ms.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(method.as_bytes());
    mac.update(b"\n");
    mac.update(path.as_bytes());
    mac.update(b"\n");
    mac.update(&Sha256::digest(body));
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify(
    secret: &[u8; 32],
    now_ms: u64,
    ts_header: &str,
    mac_header: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> bool {
    let Ok(ts) = ts_header.parse::<u64>() else {
        return false;
    };
    if now_ms.abs_diff(ts) > MAX_SKEW_MS {
        return false;
    }
    let expected = mac_hex(secret, ts, method, path, body);
    // Constant-time compare via HMAC of both strings would be
    // overkill; hex strings of equal length compared byte-wise leak
    // only prefix length. Use a fold to avoid early exit anyway.
    let a = expected.as_bytes();
    let b = mac_header.as_bytes();
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_mac_verifies() {
        let secret = [7u8; 32];
        let m = mac_hex(&secret, 1000, "POST", "/v1/manifest", b"body");
        assert!(verify(&secret, 1500, "1000", &m, "POST", "/v1/manifest", b"body"));
    }

    #[test]
    fn tampered_fields_fail() {
        let secret = [7u8; 32];
        let m = mac_hex(&secret, 1000, "POST", "/v1/manifest", b"body");
        assert!(!verify(&secret, 1500, "1000", &m, "POST", "/v1/manifest", b"evil"));
        assert!(!verify(&secret, 1500, "1000", &m, "GET", "/v1/manifest", b"body"));
        assert!(!verify(&secret, 1500, "1000", &m, "POST", "/v1/other", b"body"));
        assert!(!verify(&[8u8; 32], 1500, "1000", &m, "POST", "/v1/manifest", b"body"));
    }

    #[test]
    fn stale_timestamp_fails() {
        let secret = [7u8; 32];
        let m = mac_hex(&secret, 1000, "GET", "/v1/ping", b"");
        assert!(!verify(&secret, 1000 + MAX_SKEW_MS + 1, "1000", &m, "GET", "/v1/ping", b""));
    }
}
