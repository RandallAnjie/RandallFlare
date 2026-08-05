//! XChaCha20-Poly1305 envelope for credentials usable by every trusted node.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const KEY_CONTEXT: &[u8] = b"RandallFlare sealed platform credentials v1";
const AAD_CONTEXT: &[u8] = b"RandallFlare sealed value v1";
const MAX_VALUE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedValue {
    pub nonce_base64: String,
    pub ciphertext_base64: String,
}

pub fn seal(
    secret: &[u8; 32],
    purpose: &str,
    identity: &str,
    plaintext: &[u8],
) -> Result<SealedValue> {
    validate_context(purpose, identity)?;
    if plaintext.is_empty() || plaintext.len() > MAX_VALUE_BYTES {
        bail!("密封凭据必须为 1 至 65536 字节");
    }
    let cipher = XChaCha20Poly1305::new((&derive_key(secret)?).into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let aad = associated_data(purpose, identity);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("无法加密平台凭据"))?;
    Ok(SealedValue {
        nonce_base64: base64::engine::general_purpose::STANDARD_NO_PAD.encode(nonce),
        ciphertext_base64: base64::engine::general_purpose::STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn open(
    secret: &[u8; 32],
    purpose: &str,
    identity: &str,
    value: &SealedValue,
) -> Result<Vec<u8>> {
    validate_context(purpose, identity)?;
    let nonce: [u8; 24] = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&value.nonce_base64)
        .context("密封凭据 nonce 编码无效")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("密封凭据 nonce 长度无效"))?;
    let ciphertext = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&value.ciphertext_base64)
        .context("密封凭据密文编码无效")?;
    if ciphertext.len() > MAX_VALUE_BYTES + 16 {
        bail!("密封凭据密文过大");
    }
    let cipher = XChaCha20Poly1305::new((&derive_key(secret)?).into());
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &associated_data(purpose, identity),
            },
        )
        .map_err(|_| anyhow::anyhow!("平台凭据无法解密或身份不匹配"))
}

fn derive_key(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)?;
    mac.update(KEY_CONTEXT);
    Ok(mac.finalize().into_bytes().into())
}

fn associated_data(purpose: &str, identity: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_CONTEXT.len() + purpose.len() + identity.len() + 2);
    aad.extend_from_slice(AAD_CONTEXT);
    aad.push(0);
    aad.extend_from_slice(purpose.as_bytes());
    aad.push(0);
    aad.extend_from_slice(identity.as_bytes());
    aad
}

fn validate_context(purpose: &str, identity: &str) -> Result<()> {
    if purpose.is_empty()
        || identity.is_empty()
        || purpose.len() > 128
        || identity.len() > 256
        || purpose.contains('\0')
        || identity.contains('\0')
    {
        bail!("密封凭据上下文无效");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_authenticated() {
        let value = seal(&[9; 32], "r2-s3", "cred-a", b"secret").unwrap();
        assert_eq!(
            open(&[9; 32], "r2-s3", "cred-a", &value).unwrap(),
            b"secret"
        );
        assert!(open(&[9; 32], "r2-s3", "cred-b", &value).is_err());
    }
}
