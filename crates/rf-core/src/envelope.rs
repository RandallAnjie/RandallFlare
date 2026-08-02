//! Signed envelopes: the canonical wire form for anything a node or
//! operator asserts (claims, manifests).
//!
//! Signing covers the postcard encoding of the payload — postcard is
//! deterministic for a fixed struct definition, which is all
//! canonicalization we need since both sides share this crate. The
//! envelope carries the payload *bytes*, so verification never depends
//! on re-serialization equality across versions: you verify the bytes
//! you decode.
//!
//! Two signature schemes (see [`SignerId`]): ed25519 (nodes, classic
//! operators) and Ethereum EIP-191 personal_sign (wallet operators).

use crate::identity::{AnyKeypair, Keypair, SignerId};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// postcard-encoded payload.
    pub payload: Vec<u8>,
    pub signer: SignerId,
    /// 64 bytes (ed25519) or 65 bytes (eth r||s||v).
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    BadSignature,
    Decode,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::BadSignature => f.write_str("bad signature"),
            EnvelopeError::Decode => f.write_str("payload decode failed"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl Envelope {
    /// Seal with a node (ed25519) key.
    pub fn seal<T: Serialize>(payload: &T, key: &Keypair) -> Self {
        Self::seal_any(payload, &AnyKeypair::Ed(key.clone()))
    }

    /// Seal with either key kind.
    pub fn seal_any<T: Serialize>(payload: &T, key: &AnyKeypair) -> Self {
        let bytes =
            postcard::to_stdvec(payload).expect("postcard encode is infallible for our types");
        let sig = key.sign(&bytes);
        Envelope {
            payload: bytes,
            signer: key.signer_id(),
            sig,
        }
    }

    /// Verify the signature and decode. `expected_signer` pins who is
    /// allowed to have signed this (e.g. the operator identity for
    /// manifests); pass `None` to accept any signer and inspect
    /// `.signer` yourself (claims: any cluster node).
    pub fn open<T: DeserializeOwned>(
        &self,
        expected_signer: Option<&SignerId>,
    ) -> Result<T, EnvelopeError> {
        if let Some(want) = expected_signer {
            if *want != self.signer {
                return Err(EnvelopeError::BadSignature);
            }
        }
        if !self.signer.verify(&self.payload, &self.sig) {
            return Err(EnvelopeError::BadSignature);
        }
        postcard::from_bytes(&self.payload).map_err(|_| EnvelopeError::Decode)
    }

    /// Content hash of the signed bytes — stable id for dedup,
    /// deterministic tie-breaks, and hash-chain links.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.payload);
        h.update(self.signer.to_string().as_bytes());
        h.update(&self.sig);
        h.finalize().into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard encode is infallible for our types")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, EnvelopeError> {
        postcard::from_bytes(b).map_err(|_| EnvelopeError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EthKeypair;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Payload {
        a: u64,
        b: String,
    }

    #[test]
    fn seal_open_roundtrip_ed() {
        let kp = Keypair::from_seed([1u8; 32]);
        let env = Envelope::seal(
            &Payload {
                a: 7,
                b: "x".into(),
            },
            &kp,
        );
        let got: Payload = env.open(Some(&SignerId::Ed(kp.public()))).unwrap();
        assert_eq!(
            got,
            Payload {
                a: 7,
                b: "x".into()
            }
        );
    }

    #[test]
    fn seal_open_roundtrip_eth() {
        let kp = AnyKeypair::Eth(EthKeypair::from_seed([2u8; 32]).unwrap());
        let env = Envelope::seal_any(
            &Payload {
                a: 9,
                b: "y".into(),
            },
            &kp,
        );
        let got: Payload = env.open(Some(&kp.signer_id())).unwrap();
        assert_eq!(
            got,
            Payload {
                a: 9,
                b: "y".into()
            }
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        for kp in [
            AnyKeypair::Ed(Keypair::from_seed([1u8; 32])),
            AnyKeypair::Eth(EthKeypair::from_seed([2u8; 32]).unwrap()),
        ] {
            let mut env = Envelope::seal_any(
                &Payload {
                    a: 7,
                    b: "x".into(),
                },
                &kp,
            );
            env.payload[0] ^= 1;
            assert_eq!(
                env.open::<Payload>(None).unwrap_err(),
                EnvelopeError::BadSignature
            );
        }
    }

    #[test]
    fn wrong_signer_rejected() {
        let kp = Keypair::from_seed([1u8; 32]);
        let other = Keypair::from_seed([2u8; 32]);
        let env = Envelope::seal(
            &Payload {
                a: 7,
                b: "x".into(),
            },
            &kp,
        );
        assert_eq!(
            env.open::<Payload>(Some(&SignerId::Ed(other.public())))
                .unwrap_err(),
            EnvelopeError::BadSignature
        );
    }

    #[test]
    fn cross_scheme_signer_mismatch_rejected() {
        let ed = Keypair::from_seed([1u8; 32]);
        let eth = AnyKeypair::Eth(EthKeypair::from_seed([2u8; 32]).unwrap());
        let env = Envelope::seal(
            &Payload {
                a: 1,
                b: "z".into(),
            },
            &ed,
        );
        assert_eq!(
            env.open::<Payload>(Some(&eth.signer_id())).unwrap_err(),
            EnvelopeError::BadSignature
        );
    }

    #[test]
    fn wire_roundtrip_preserves_digest() {
        let kp = AnyKeypair::Eth(EthKeypair::from_seed([3u8; 32]).unwrap());
        let env = Envelope::seal_any(
            &Payload {
                a: 1,
                b: "y".into(),
            },
            &kp,
        );
        let back = Envelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(env.digest(), back.digest());
    }
}
