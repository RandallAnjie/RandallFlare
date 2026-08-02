//! Confidentiality for the peer API without a central CA.
//!
//! The cluster PSK is expanded into a dedicated XChaCha20-Poly1305
//! key. Every request and response uses a fresh 192-bit nonce and
//! binds its request metadata as associated data. The existing HMAC
//! remains the replay/time-window gate and authenticates plaintext
//! request semantics after decryption.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const ENC_HEADER: &str = "x-rf-encrypted";
pub const NONCE_HEADER: &str = "x-rf-nonce";
pub const VERSION: &str = "1";

fn cipher(secret: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut h = Sha256::new();
    h.update(b"randallflare/peer-api/xchacha20poly1305/v1\0");
    h.update(secret);
    let key: [u8; 32] = h.finalize().into();
    XChaCha20Poly1305::new(Key::from_slice(&key))
}

pub fn request_aad(ts: &str, method: &str, path: &str) -> Vec<u8> {
    format!("rf-peer-request-v1\n{ts}\n{method}\n{path}").into_bytes()
}

pub fn response_aad(request_nonce: &str, status: u16) -> Vec<u8> {
    format!("rf-peer-response-v1\n{request_nonce}\n{status}").into_bytes()
}

pub fn seal(secret: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher(secret)
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| anyhow!("peer payload encryption failed"))?;
    Ok((hex::encode(nonce), ciphertext))
}

pub fn open(secret: &[u8; 32], nonce_hex: &str, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let nonce = hex::decode(nonce_hex).context("invalid peer encryption nonce")?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| anyhow!("peer encryption nonce must be 24 bytes"))?;
    cipher(secret)
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("peer payload authentication failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_metadata_binding() {
        let secret = [9u8; 32];
        let aad = request_aad("123", "POST", "/v1/blob");
        let (nonce, ciphertext) = seal(&secret, &aad, b"top secret").unwrap();
        assert_ne!(ciphertext, b"top secret");
        assert_eq!(open(&secret, &nonce, &aad, &ciphertext).unwrap(), b"top secret");
        assert!(open(
            &secret,
            &nonce,
            &request_aad("123", "POST", "/v1/other"),
            &ciphertext
        )
        .is_err());
        assert!(open(&[8u8; 32], &nonce, &aad, &ciphertext).is_err());
    }

    #[test]
    fn every_message_gets_a_distinct_nonce() {
        let aad = request_aad("123", "GET", "/v1/status");
        let (a, _) = seal(&[1u8; 32], &aad, b"").unwrap();
        let (b, _) = seal(&[1u8; 32], &aad, b"").unwrap();
        assert_ne!(a, b);
    }
}
