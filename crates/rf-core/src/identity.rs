//! Node and operator identity: ed25519 keypairs.
//!
//! A node *is* its public key — there is no registry to hand out ids.
//! Key generation takes a caller-supplied 32-byte seed so this crate
//! stays IO-free; the binary feeds it from OS randomness.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A node's identity = its ed25519 public key bytes.
pub type NodeId = [u8; 32];

/// Any public identity (node or operator) with verification helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicId(pub [u8; 32]);

impl PublicId {
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..6])
    }
}

impl std::fmt::Display for PublicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::str::FromStr for PublicId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s.trim()).map_err(|e| e.to_string())?;
        let arr: [u8; 32] =
            bytes.try_into().map_err(|_| "expected 32 hex-encoded bytes".to_string())?;
        Ok(PublicId(arr))
    }
}

/// A signing identity (secret half lives only in memory / on the
/// node's own disk).
#[derive(Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> PublicId {
        PublicId(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keypair({})", self.public().short())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Keypair::from_seed([7u8; 32]);
        let sig = kp.sign(b"hello");
        assert!(kp.public().verify(b"hello", &sig));
        assert!(!kp.public().verify(b"hell0", &sig));
    }

    #[test]
    fn public_id_hex_roundtrip() {
        let kp = Keypair::from_seed([9u8; 32]);
        let s = kp.public().to_string();
        let back: PublicId = s.parse().unwrap();
        assert_eq!(back, kp.public());
    }
}
