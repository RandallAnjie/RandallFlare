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
/// Serde: hex string in human-readable formats (TOML/JSON), raw bytes
/// in binary ones (postcard wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicId(pub [u8; 32]);

impl Serialize for PublicId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(D::Error::custom)
        } else {
            let b: serde_bytes_shim::Bytes = Deserialize::deserialize(d)?;
            let arr: [u8; 32] =
                b.0.try_into().map_err(|_| D::Error::custom("expected 32 bytes"))?;
            Ok(PublicId(arr))
        }
    }
}

/// Minimal owned-bytes shim so we don't pull the serde_bytes crate:
/// postcard encodes `serialize_bytes` as a length-prefixed byte run,
/// and this deserializes it back without an intermediate Vec<u64>.
mod serde_bytes_shim {
    pub struct Bytes(pub Vec<u8>);
    impl<'de> serde::Deserialize<'de> for Bytes {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Bytes;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                    Ok(Bytes(v.to_vec()))
                }
                fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                    Ok(Bytes(v))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Bytes, A::Error> {
                    let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(Bytes(out))
                }
            }
            d.deserialize_byte_buf(V)
        }
    }
}

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
