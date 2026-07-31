//! Key files: 32-byte hex seeds, mode 600. A node key identifies the
//! node in claims; the operator key signs deploys and lives on the
//! operator's machine, never on nodes.

use anyhow::{Context, Result};
use rand::RngCore;
use rf_core::identity::Keypair;
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
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading key {}", path.display()))?;
    let bytes = hex::decode(raw.trim()).context("key file is not hex")?;
    let seed: [u8; 32] =
        bytes.try_into().map_err(|_| anyhow::anyhow!("key file must hold 32 bytes"))?;
    Ok(Keypair::from_seed(seed))
}

pub fn save(path: &Path, kp: &Keypair) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
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
}
