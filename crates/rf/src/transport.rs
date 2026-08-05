//! Confidentiality for the peer API without a central CA.
//!
//! The cluster PSK is expanded into a dedicated XChaCha20-Poly1305
//! key. Every request and response uses a fresh 192-bit nonce and
//! binds its request metadata as associated data. The existing HMAC
//! remains the clock-window gate and authenticates plaintext request
//! semantics after decryption; the API layer owns replay tracking.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const ENC_HEADER: &str = "x-rf-encrypted";
pub const NONCE_HEADER: &str = "x-rf-nonce";
pub const TARGET_HEADER: &str = "x-rf-target";
pub const VERSION: &str = "2";
pub const STREAM_HEADER: &str = "x-rf-encrypted-stream";
pub const STREAM_VERSION: &str = "1";
pub const STREAM_PLAINTEXT_CHUNK: usize = 1024 * 1024;
pub const MAX_STREAM_FRAME: usize = 8 + 24 + STREAM_PLAINTEXT_CHUNK + 16;

fn cipher(secret: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut h = Sha256::new();
    h.update(b"randallflare/peer-api/xchacha20poly1305/v1\0");
    h.update(secret);
    let key: [u8; 32] = h.finalize().into();
    XChaCha20Poly1305::new(Key::from_slice(&key))
}

pub fn request_aad(ts: &str, method: &str, path: &str, target: &str) -> Vec<u8> {
    format!("rf-peer-request-v2\n{ts}\n{method}\n{path}\n{target}").into_bytes()
}

pub fn response_aad(request_nonce: &str, status: u16) -> Vec<u8> {
    format!("rf-peer-response-v2\n{request_nonce}\n{status}").into_bytes()
}

fn stream_response_aad(request_nonce: &str, status: u16, sequence: u64) -> Vec<u8> {
    format!("rf-peer-response-stream-v1\n{request_nonce}\n{status}\n{sequence}").into_bytes()
}

pub fn seal(secret: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = seal_raw(secret, &nonce, aad, plaintext)?;
    Ok((hex::encode(nonce), ciphertext))
}

pub fn seal_raw(
    secret: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ciphertext = cipher(secret)
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("peer payload encryption failed"))?;
    Ok(ciphertext)
}

pub fn open(secret: &[u8; 32], nonce_hex: &str, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let nonce = hex::decode(nonce_hex).context("invalid peer encryption nonce")?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| anyhow!("peer encryption nonce must be 24 bytes"))?;
    open_raw(secret, &nonce, aad, ciphertext)
}

pub fn open_raw(
    secret: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    cipher(secret)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("peer payload authentication failed"))
}

/// Encode one independently authenticated streaming-response frame. The
/// returned bytes include a big-endian frame length, strict sequence number,
/// random nonce and ciphertext. An empty plaintext is the authenticated EOF
/// marker and must therefore only be emitted once, after all data frames.
pub fn seal_stream_frame(
    secret: &[u8; 32],
    request_nonce: &str,
    status: u16,
    sequence: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > STREAM_PLAINTEXT_CHUNK {
        return Err(anyhow!("peer stream plaintext frame exceeds 1 MiB"));
    }
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = seal_raw(
        secret,
        &nonce,
        &stream_response_aad(request_nonce, status, sequence),
        plaintext,
    )?;
    let frame_len = 8usize
        .checked_add(nonce.len())
        .and_then(|length| length.checked_add(ciphertext.len()))
        .context("peer stream frame length overflow")?;
    if frame_len > MAX_STREAM_FRAME {
        return Err(anyhow!("peer stream frame exceeds its bound"));
    }
    let mut frame = Vec::with_capacity(4 + frame_len);
    frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

/// Authenticate and decode one frame excluding its four-byte length prefix.
/// Callers own framing and enforce that sequences arrive without gaps.
pub fn open_stream_frame(
    secret: &[u8; 32],
    request_nonce: &str,
    status: u16,
    expected_sequence: u64,
    frame: &[u8],
) -> Result<Vec<u8>> {
    if !(8 + 24 + 16..=MAX_STREAM_FRAME).contains(&frame.len()) {
        return Err(anyhow!("invalid peer stream frame length"));
    }
    let sequence = u64::from_be_bytes(frame[..8].try_into().expect("eight-byte slice"));
    if sequence != expected_sequence {
        return Err(anyhow!("peer stream frame sequence mismatch"));
    }
    let nonce: [u8; 24] = frame[8..32].try_into().expect("24-byte slice");
    open_raw(
        secret,
        &nonce,
        &stream_response_aad(request_nonce, status, sequence),
        &frame[32..],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_metadata_binding() {
        let secret = [9u8; 32];
        let aad = request_aad("123", "POST", "/v1/blob", "node-a");
        let (nonce, ciphertext) = seal(&secret, &aad, b"top secret").unwrap();
        assert_ne!(ciphertext, b"top secret");
        assert_eq!(
            open(&secret, &nonce, &aad, &ciphertext).unwrap(),
            b"top secret"
        );
        assert!(open(
            &secret,
            &nonce,
            &request_aad("123", "POST", "/v1/other", "node-a"),
            &ciphertext
        )
        .is_err());
        assert!(open(
            &secret,
            &nonce,
            &request_aad("123", "POST", "/v1/blob", "node-b"),
            &ciphertext
        )
        .is_err());
        assert!(open(&[8u8; 32], &nonce, &aad, &ciphertext).is_err());
    }

    #[test]
    fn every_message_gets_a_distinct_nonce() {
        let aad = request_aad("123", "GET", "/v1/status", "node-a");
        let (a, _) = seal(&[1u8; 32], &aad, b"").unwrap();
        let (b, _) = seal(&[1u8; 32], &aad, b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn streaming_frames_bind_status_session_and_sequence() {
        let secret = [7u8; 32];
        let frame = seal_stream_frame(&secret, "session-a", 200, 3, b"chunk").unwrap();
        let length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(length, frame.len() - 4);
        assert_eq!(
            open_stream_frame(&secret, "session-a", 200, 3, &frame[4..]).unwrap(),
            b"chunk"
        );
        assert!(open_stream_frame(&secret, "session-b", 200, 3, &frame[4..]).is_err());
        assert!(open_stream_frame(&secret, "session-a", 206, 3, &frame[4..]).is_err());
        assert!(open_stream_frame(&secret, "session-a", 200, 4, &frame[4..]).is_err());

        let eof = seal_stream_frame(&secret, "session-a", 200, 4, b"").unwrap();
        assert!(open_stream_frame(&secret, "session-a", 200, 4, &eof[4..])
            .unwrap()
            .is_empty());
    }
}
