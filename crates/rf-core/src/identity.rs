//! Node and operator identity.
//!
//! Nodes are always ed25519 — a node *is* its public key; there is no
//! registry to hand out ids. The *operator* (the deploy authority) may
//! be either an ed25519 key or an Ethereum wallet (secp256k1, EIP-191
//! personal_sign) — see [`SignerId`] / [`AnyKeypair`]. Key generation
//! takes a caller-supplied 32-byte seed so this crate stays IO-free;
//! the binary feeds it from OS randomness.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};

/// A node's identity = its ed25519 public key bytes.
pub type NodeId = [u8; 32];

/// Any public identity (node or operator) with verification helpers.
/// Serde: hex string in human-readable formats (TOML/JSON), raw bytes
/// in binary ones (postcard wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// An Ethereum-style signing identity: secp256k1 key, identified by
/// its 20-byte address, signing via EIP-191 (`personal_sign`) so a
/// browser wallet could produce compatible signatures.
#[derive(Clone)]
pub struct EthKeypair {
    sk: k256::ecdsa::SigningKey,
}

pub fn eth_address_of(vk: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = vk.to_sec1_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]); // drop the 0x04 tag
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// keccak256 of the EIP-191 personal-message wrapping of `payload`.
pub fn eip191_hash(payload: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(format!("\x19Ethereum Signed Message:\n{}", payload.len()).as_bytes());
    h.update(payload);
    h.finalize().into()
}

impl EthKeypair {
    pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
        k256::ecdsa::SigningKey::from_bytes((&seed).into()).ok().map(|sk| Self { sk })
    }

    pub fn seed(&self) -> [u8; 32] {
        self.sk.to_bytes().into()
    }

    pub fn address(&self) -> [u8; 20] {
        eth_address_of(self.sk.verifying_key())
    }

    /// 65-byte r||s||v signature (v ∈ {27, 28}, wallet convention).
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let digest = eip191_hash(payload);
        let (sig, recid) = self.sk.sign_prehash_recoverable(&digest);
        let mut out = sig.to_bytes().to_vec();
        out.push(recid.to_byte() + 27);
        out
    }
}

impl std::fmt::Debug for EthKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EthKeypair(0x{})", hex::encode(self.address()))
    }
}

/// Recover the signing address from an EIP-191 signature over
/// `payload`. Returns None on any malformed input.
pub fn eth_recover(payload: &[u8], sig: &[u8]) -> Option<[u8; 20]> {
    if sig.len() != 65 {
        return None;
    }
    let v = sig[64];
    let recid = k256::ecdsa::RecoveryId::from_byte(v.checked_sub(27)?)?;
    let signature = k256::ecdsa::Signature::from_slice(&sig[..64]).ok()?;
    let digest = eip191_hash(payload);
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &signature, recid).ok()?;
    Some(eth_address_of(&vk))
}

/// Who signed something: an ed25519 key (nodes, classic operator) or
/// an Ethereum address (wallet operator). Human-readable serde form is
/// 64 hex chars for Ed, `0x` + 40 hex chars for Eth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerId {
    Ed(PublicId),
    Eth([u8; 20]),
}

impl SignerId {
    /// Verify `sig` over `payload` for this identity.
    pub fn verify(&self, payload: &[u8], sig: &[u8]) -> bool {
        match self {
            SignerId::Ed(pk) => {
                let Ok(arr): Result<&[u8; 64], _> = sig.try_into() else {
                    return false;
                };
                pk.verify(payload, arr)
            }
            SignerId::Eth(addr) => eth_recover(payload, sig) == Some(*addr),
        }
    }
}

impl std::fmt::Display for SignerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerId::Ed(pk) => write!(f, "{pk}"),
            SignerId::Eth(addr) => write!(f, "0x{}", hex::encode(addr)),
        }
    }
}

impl std::str::FromStr for SignerId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(hexpart) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            let bytes = hex::decode(hexpart).map_err(|e| e.to_string())?;
            let arr: [u8; 20] =
                bytes.try_into().map_err(|_| "eth address must be 20 bytes".to_string())?;
            Ok(SignerId::Eth(arr))
        } else {
            Ok(SignerId::Ed(s.parse()?))
        }
    }
}

impl Serialize for SignerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            match self {
                SignerId::Ed(pk) => s.serialize_newtype_variant("SignerId", 0, "Ed", pk),
                SignerId::Eth(addr) => {
                    s.serialize_newtype_variant("SignerId", 1, "Eth", addr)
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for SignerId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(D::Error::custom)
        } else {
            #[derive(Deserialize)]
            enum Shadow {
                Ed(PublicId),
                Eth([u8; 20]),
            }
            Ok(match Shadow::deserialize(d)? {
                Shadow::Ed(pk) => SignerId::Ed(pk),
                Shadow::Eth(a) => SignerId::Eth(a),
            })
        }
    }
}

/// Either kind of signing key — what the deploy path holds.
#[derive(Debug, Clone)]
pub enum AnyKeypair {
    Ed(Keypair),
    Eth(EthKeypair),
}

impl AnyKeypair {
    pub fn signer_id(&self) -> SignerId {
        match self {
            AnyKeypair::Ed(kp) => SignerId::Ed(kp.public()),
            AnyKeypair::Eth(kp) => SignerId::Eth(kp.address()),
        }
    }

    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            AnyKeypair::Ed(kp) => kp.sign(payload).to_vec(),
            AnyKeypair::Eth(kp) => kp.sign(payload),
        }
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

    #[test]
    fn eth_sign_recover_roundtrip() {
        let kp = EthKeypair::from_seed([3u8; 32]).unwrap();
        let sig = kp.sign(b"deploy this");
        assert_eq!(sig.len(), 65);
        assert_eq!(eth_recover(b"deploy this", &sig), Some(kp.address()));
        assert_ne!(eth_recover(b"deploy that", &sig), Some(kp.address()));
    }

    #[test]
    fn eth_address_matches_known_vector() {
        // secp256k1 private key 0x01 → well-known address
        // 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
        let mut seed = [0u8; 32];
        seed[31] = 1;
        let kp = EthKeypair::from_seed(seed).unwrap();
        assert_eq!(
            hex::encode(kp.address()),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn signer_id_parse_display_roundtrip() {
        let ed: SignerId = SignerId::Ed(Keypair::from_seed([1; 32]).public());
        let eth = SignerId::Eth([0xab; 20]);
        assert_eq!(ed.to_string().parse::<SignerId>().unwrap(), ed);
        assert_eq!(eth.to_string().parse::<SignerId>().unwrap(), eth);
        assert!(eth.to_string().starts_with("0x"));
    }

    #[test]
    fn signer_id_verify_dispatches() {
        let ed_kp = AnyKeypair::Ed(Keypair::from_seed([5; 32]));
        let eth_kp = AnyKeypair::Eth(EthKeypair::from_seed([6; 32]).unwrap());
        for kp in [ed_kp, eth_kp] {
            let sig = kp.sign(b"msg");
            assert!(kp.signer_id().verify(b"msg", &sig));
            assert!(!kp.signer_id().verify(b"other", &sig));
        }
    }

    #[test]
    fn signer_id_postcard_roundtrip() {
        for id in [
            SignerId::Ed(Keypair::from_seed([7; 32]).public()),
            SignerId::Eth([9; 20]),
        ] {
            let bytes = postcard::to_stdvec(&id).unwrap();
            let back: SignerId = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(back, id);
        }
    }
}
