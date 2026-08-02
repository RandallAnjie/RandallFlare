//! Key files: 32-byte hex seeds, mode 600. A node key identifies the
//! node in claims; the operator key signs deploys and lives on the
//! operator's machine, never on nodes.

use anyhow::{Context, Result};
use rand::RngCore;
use rf_core::identity::{AnyKeypair, EthKeypair, Keypair};
use std::path::Path;

pub fn load_or_create(path: &Path) -> Result<Keypair> {
    if path.exists() {
        load(path)
    } else {
        let kp = generate();
        save(path, &kp)?;
        Ok(kp)
    }
}

pub fn load(path: &Path) -> Result<Keypair> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading key {}", path.display()))?;
    let bytes = hex::decode(raw.trim()).context("key file is not hex")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must hold 32 bytes"))?;
    Ok(Keypair::from_seed(seed))
}

pub fn save(path: &Path, kp: &Keypair) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    std::fs::write(path, hex::encode(kp.seed()))
        .with_context(|| format!("writing key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn generate() -> Keypair {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    Keypair::from_seed(seed)
}

// ---- operator keys: either scheme ----
// File format: "<hex64>" (legacy ed25519), "ed25519:<hex64>", or
// "secp256k1:<hex64>" (Ethereum wallet key).

pub fn generate_eth() -> EthKeypair {
    loop {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        // ~2^-128 chance of an invalid scalar; loop for correctness.
        if let Some(kp) = EthKeypair::from_seed(seed) {
            return kp;
        }
    }
}

pub fn load_any(path: &Path) -> Result<AnyKeypair> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading key {}", path.display()))?;
    let raw = raw.trim();
    let (scheme, hexpart) = match raw.split_once(':') {
        Some((s, h)) => (s, h),
        None => ("ed25519", raw),
    };
    let bytes = hex::decode(hexpart.trim()).context("key file is not hex")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must hold 32 bytes"))?;
    match scheme {
        "ed25519" => Ok(AnyKeypair::Ed(Keypair::from_seed(seed))),
        "secp256k1" => EthKeypair::from_seed(seed)
            .map(AnyKeypair::Eth)
            .ok_or_else(|| anyhow::anyhow!("invalid secp256k1 key")),
        other => anyhow::bail!("unknown key scheme {other:?}"),
    }
}

pub fn save_any(path: &Path, kp: &AnyKeypair) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let contents = match kp {
        AnyKeypair::Ed(k) => format!("ed25519:{}", hex::encode(k.seed())),
        AnyKeypair::Eth(k) => format!("secp256k1:{}", hex::encode(k.seed())),
    };
    std::fs::write(path, contents).with_context(|| format!("writing key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("rf-keys-{}", std::process::id()));
        let path = dir.join("node.key");
        let a = load_or_create(&path).unwrap();
        let b = load_or_create(&path).unwrap();
        assert_eq!(a.public(), b.public());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn any_key_roundtrip_both_schemes() {
        let dir = std::env::temp_dir().join(format!("rf-anykeys-{}", std::process::id()));
        let ed = AnyKeypair::Ed(generate());
        let eth = AnyKeypair::Eth(generate_eth());
        for (name, kp) in [("ed.key", &ed), ("eth.key", &eth)] {
            let path = dir.join(name);
            save_any(&path, kp).unwrap();
            let back = load_any(&path).unwrap();
            assert_eq!(back.signer_id(), kp.signer_id());
        }
        // Legacy bare-hex file loads as ed25519.
        let legacy = dir.join("legacy.key");
        if let AnyKeypair::Ed(k) = &ed {
            std::fs::write(&legacy, hex::encode(k.seed())).unwrap();
        }
        assert_eq!(load_any(&legacy).unwrap().signer_id(), ed.signer_id());
        std::fs::remove_dir_all(&dir).ok();
    }
}
