//! Encrypted, signed Worker secret bindings.
//!
//! Ciphertexts replicate in the Worker manifest. Plaintext exists only while
//! an authenticated operator writes a value and while a node materializes its
//! local workerd configuration. The browser/API can list names but can never
//! read a stored value back.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rf_core::manifest::WorkerManifest;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_SECRETS: usize = 256;
const KEY_CONTEXT: &[u8] = b"RandallFlare Worker secrets v1";
const AAD_CONTEXT: &[u8] = b"RandallFlare Worker secret binding v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedWorkerSecret {
    pub nonce_base64: String,
    pub ciphertext_base64: String,
}

pub fn encrypted_secrets(manifest: &WorkerManifest) -> BTreeMap<String, EncryptedWorkerSecret> {
    encrypted_secrets_checked(manifest).unwrap_or_default()
}

pub fn encrypted_secrets_checked(
    manifest: &WorkerManifest,
) -> Result<BTreeMap<String, EncryptedWorkerSecret>> {
    let Some(raw) = manifest.env.get(crate::deploy::SECRET_METADATA_ENV) else {
        return Ok(BTreeMap::new());
    };
    let secrets: BTreeMap<String, EncryptedWorkerSecret> =
        serde_json::from_str(raw).context("Worker Secret 元数据无效")?;
    if secrets.len() > MAX_SECRETS {
        bail!("Worker Secret 数量超过上限");
    }
    Ok(secrets)
}

pub fn valid_binding_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(|character| {
        character.is_ascii_alphabetic() || character == '_' || character == '$'
    }) && characters
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '$')
}

pub fn encrypt(
    cluster_secret: &[u8; 32],
    worker: &str,
    binding: &str,
    plaintext: &str,
) -> Result<EncryptedWorkerSecret> {
    validate_identity(worker, binding)?;
    validate_plaintext(plaintext)?;
    let cipher = XChaCha20Poly1305::new((&derive_key(cluster_secret)?).into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let aad = associated_data(worker, binding);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("无法加密 Worker Secret"))?;
    Ok(EncryptedWorkerSecret {
        nonce_base64: base64::engine::general_purpose::STANDARD_NO_PAD.encode(nonce),
        ciphertext_base64: base64::engine::general_purpose::STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt(
    cluster_secret: &[u8; 32],
    worker: &str,
    binding: &str,
    secret: &EncryptedWorkerSecret,
) -> Result<String> {
    validate_identity(worker, binding)?;
    let nonce = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&secret.nonce_base64)
        .context("Worker Secret nonce 编码无效")?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("Worker Secret nonce 长度无效"))?;
    let ciphertext = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&secret.ciphertext_base64)
        .context("Worker Secret 密文编码无效")?;
    if ciphertext.len() > MAX_SECRET_BYTES + 16 {
        bail!("Worker Secret 密文过大");
    }
    let cipher = XChaCha20Poly1305::new((&derive_key(cluster_secret)?).into());
    let aad = associated_data(worker, binding);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Worker Secret 无法解密或身份不匹配"))?;
    let plaintext = String::from_utf8(plaintext).context("Worker Secret 不是有效 UTF-8")?;
    validate_plaintext(&plaintext)?;
    Ok(plaintext)
}

pub fn decrypt_manifest(
    cluster_secret: &[u8; 32],
    manifest: &WorkerManifest,
) -> Result<BTreeMap<String, String>> {
    let secrets = encrypted_secrets_checked(manifest)?;
    secrets
        .iter()
        .map(|(binding, value)| {
            decrypt(cluster_secret, &manifest.name, binding, value)
                .map(|plaintext| (binding.clone(), plaintext))
                .with_context(|| format!("解密 Worker Secret {binding}"))
        })
        .collect()
}

pub fn put_manifest_secret(
    mut manifest: WorkerManifest,
    digest: [u8; 32],
    cluster_secret: &[u8; 32],
    binding: &str,
    value: &str,
) -> Result<WorkerManifest> {
    validate_binding_for_manifest(binding)?;
    if binding_conflicts(&manifest, binding) {
        bail!("绑定名称 {binding} 已被环境变量或平台绑定使用");
    }
    let mut secrets = encrypted_secrets_checked(&manifest)?;
    if !secrets.contains_key(binding) && secrets.len() >= MAX_SECRETS {
        bail!("一个 Worker 最多配置 256 个 Secret");
    }
    secrets.insert(
        binding.to_string(),
        encrypt(cluster_secret, &manifest.name, binding, value)?,
    );
    manifest.env.insert(
        crate::deploy::SECRET_METADATA_ENV.into(),
        serde_json::to_string(&secrets)?,
    );
    link_manifest(manifest, digest)
}

pub fn delete_manifest_secret(
    mut manifest: WorkerManifest,
    digest: [u8; 32],
    binding: &str,
) -> Result<WorkerManifest> {
    validate_binding_for_manifest(binding)?;
    let mut secrets = encrypted_secrets_checked(&manifest)?;
    if secrets.remove(binding).is_none() {
        bail!("Secret 不存在");
    }
    if secrets.is_empty() {
        manifest.env.remove(crate::deploy::SECRET_METADATA_ENV);
    } else {
        manifest.env.insert(
            crate::deploy::SECRET_METADATA_ENV.into(),
            serde_json::to_string(&secrets)?,
        );
    }
    link_manifest(manifest, digest)
}

fn validate_binding_for_manifest(binding: &str) -> Result<()> {
    if !valid_binding_name(binding) || binding.starts_with("__RF_") {
        bail!("Secret 名称必须是合法的 JavaScript 标识符且不能使用 __RF_ 前缀");
    }
    Ok(())
}

fn binding_conflicts(manifest: &WorkerManifest, binding: &str) -> bool {
    manifest
        .env
        .keys()
        .filter(|name| !name.starts_with("__RF_"))
        .chain(manifest.kv_bindings.keys())
        .chain(crate::deploy::durable_objects(manifest).keys())
        .chain(crate::deploy::r2_bindings(manifest).keys())
        .chain(crate::deploy::d1_bindings(manifest).keys())
        .chain(crate::deploy::queue_bindings(manifest).keys())
        .chain(crate::deploy::analytics_bindings(manifest).keys())
        .chain(crate::deploy::pipeline_bindings(manifest).keys())
        .chain(crate::deploy::workflow_bindings(manifest).keys())
        .chain(crate::deploy::email_bindings(manifest).keys())
        .chain(crate::deploy::service_bindings(manifest).keys())
        .any(|name| name == binding)
}

fn link_manifest(mut manifest: WorkerManifest, digest: [u8; 32]) -> Result<WorkerManifest> {
    manifest.version = manifest
        .version
        .checked_add(1)
        .context("Worker 版本号已耗尽")?;
    manifest.prev = Some(digest);
    manifest
        .validate()
        .map_err(|error| anyhow::anyhow!("Worker 配置无效：{error}"))?;
    Ok(manifest)
}

fn derive_key(cluster_secret: &[u8; 32]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cluster_secret)
        .map_err(|_| anyhow::anyhow!("无法派生 Worker Secret 密钥"))?;
    mac.update(KEY_CONTEXT);
    Ok(mac.finalize().into_bytes().into())
}

fn associated_data(worker: &str, binding: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_CONTEXT.len() + worker.len() + binding.len() + 16);
    aad.extend_from_slice(AAD_CONTEXT);
    aad.extend_from_slice(&(worker.len() as u64).to_be_bytes());
    aad.extend_from_slice(worker.as_bytes());
    aad.extend_from_slice(&(binding.len() as u64).to_be_bytes());
    aad.extend_from_slice(binding.as_bytes());
    aad
}

fn validate_identity(worker: &str, binding: &str) -> Result<()> {
    if !rf_core::manifest::valid_name(worker) || !valid_binding_name(binding) {
        bail!("Worker 或 Secret 绑定名称无效");
    }
    Ok(())
}

fn validate_plaintext(plaintext: &str) -> Result<()> {
    if plaintext.is_empty() {
        bail!("Worker Secret 不能为空");
    }
    if plaintext.len() > MAX_SECRET_BYTES {
        bail!("Worker Secret 超过 64 KiB");
    }
    if plaintext.contains('\0') {
        bail!("Worker Secret 不能包含 NUL 字符");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_is_random_and_bound_to_worker_and_name() {
        let cluster = [7u8; 32];
        let first = encrypt(&cluster, "frontend", "API_TOKEN", "very-private-value").unwrap();
        let second = encrypt(&cluster, "frontend", "API_TOKEN", "very-private-value").unwrap();
        assert_ne!(first, second);
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains("very-private-value"));
        assert_eq!(
            decrypt(&cluster, "frontend", "API_TOKEN", &first).unwrap(),
            "very-private-value"
        );
        assert!(decrypt(&cluster, "backend", "API_TOKEN", &first).is_err());
        assert!(decrypt(&cluster, "frontend", "OTHER_TOKEN", &first).is_err());
        assert!(decrypt(&[8u8; 32], "frontend", "API_TOKEN", &first).is_err());
    }

    #[test]
    fn invalid_values_are_rejected() {
        let cluster = [7u8; 32];
        assert!(encrypt(&cluster, "frontend", "bad-name", "value").is_err());
        assert!(encrypt(&cluster, "frontend", "TOKEN", "").is_err());
        assert!(encrypt(&cluster, "frontend", "TOKEN", "a\0b").is_err());
    }

    #[test]
    fn manifest_update_contains_only_ciphertext_and_links_history() {
        let manifest = WorkerManifest {
            name: "frontend".into(),
            version: 3,
            prev: Some([2; 32]),
            deleted: false,
            main: String::new(),
            modules: vec![],
            assets: vec![],
            hostnames: vec![],
            env: BTreeMap::new(),
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-08-04".into(),
        };
        let updated = put_manifest_secret(
            manifest,
            [9; 32],
            &[7; 32],
            "API_TOKEN",
            "never-store-this-plaintext",
        )
        .unwrap();
        assert_eq!(updated.version, 4);
        assert_eq!(updated.prev, Some([9; 32]));
        let serialized = serde_json::to_string(&updated).unwrap();
        assert!(!serialized.contains("never-store-this-plaintext"));
        assert_eq!(
            decrypt_manifest(&[7; 32], &updated).unwrap()["API_TOKEN"],
            "never-store-this-plaintext"
        );
        let deleted = delete_manifest_secret(updated, [8; 32], "API_TOKEN").unwrap();
        assert!(!deleted.env.contains_key(crate::deploy::SECRET_METADATA_ENV));
    }
}
