//! rf-core — the pure decision core of RandallFlare.
//!
//! Everything the cluster *decides* lives here as deterministic,
//! IO-free functions: identity and signatures, hybrid logical clocks,
//! claim adjudication, manifest merging, KV last-write-wins, cron
//! matching. The `rf` binary is a thin IO shell around this crate;
//! bugs that matter should be reproducible in a unit test here.

pub mod claim;
pub mod cron;
pub mod envelope;
pub mod hlc;
pub mod identity;
pub mod kv;
pub mod manifest;
pub mod quorum;

pub use hlc::Hlc;
pub use identity::{NodeId, PublicId};
