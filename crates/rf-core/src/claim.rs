//! The claim engine (抢单): leaderless singleton scheduling.
//!
//! A claim is a signed assertion "I hold task T": acquisition HLC
//! (fixed for the lifetime of the hold), renewal HLC (bumped while the
//! holder is alive) and a TTL. Everyone ingests everyone's claims via
//! gossip and runs the same pure adjudication:
//!
//!   winner(T) = live claim with the earliest `acquired`,
//!               ties broken by envelope digest (lower wins).
//!
//! Liveness = renewal not older than TTL (+ skew slack, judged against
//! the local wall clock). Uniqueness is therefore *eventual*: during a
//! partition two nodes can both believe they hold T. Claims are only
//! used for tasks where duplicate execution is safe (idempotent or
//! at-least-once); single-writer state gets micro-quorums, not claims.

use crate::envelope::{Envelope, EnvelopeError};
use crate::hlc::Hlc;
use crate::identity::{Keypair, PublicId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Clock-skew slack added to liveness checks. Generous on purpose:
/// premature takeover costs a duplicate execution, a late one costs a
/// few seconds of nobody-holding — both safe, so lean conservative.
pub const SKEW_SLACK_MS: u64 = 15_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub task: String,
    pub holder: PublicId,
    /// First acquisition; MUST stay identical across renewals — this
    /// is what adjudication orders on.
    pub acquired: Hlc,
    /// Latest renewal (== `acquired` on first issue).
    pub renewed: Hlc,
    pub ttl_ms: u64,
    /// True = the holder is done and releases the task early.
    pub released: bool,
}

impl Claim {
    pub fn expires_at_ms(&self) -> u64 {
        self.renewed.wall_ms.saturating_add(self.ttl_ms)
    }

    pub fn live(&self, now_ms: u64) -> bool {
        !self.released && now_ms < self.expires_at_ms().saturating_add(SKEW_SLACK_MS)
    }
}

/// One ingested, signature-verified claim.
#[derive(Debug, Clone)]
pub struct ClaimRecord {
    pub claim: Claim,
    pub digest: [u8; 32],
    pub envelope: Envelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingest {
    /// New information — persist and re-gossip.
    Changed,
    /// Already known or older than what we have — drop silently.
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    Envelope(EnvelopeError),
    /// envelope signer != claim.holder — a forged hold attempt.
    HolderMismatch,
    /// renewal sorts before acquisition — nonsensical.
    RenewedBeforeAcquired,
    /// A renewal changed `acquired` for the same (task, holder) —
    /// backdating an existing hold is rejected.
    AcquiredMoved,
    /// Zero TTL claims can never be live.
    ZeroTtl,
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimError::Envelope(e) => write!(f, "envelope: {e}"),
            ClaimError::HolderMismatch => f.write_str("signer is not the claimed holder"),
            ClaimError::RenewedBeforeAcquired => f.write_str("renewed < acquired"),
            ClaimError::AcquiredMoved => f.write_str("acquired changed across renewal"),
            ClaimError::ZeroTtl => f.write_str("ttl is zero"),
        }
    }
}

impl std::error::Error for ClaimError {}

/// All claims this node knows about, keyed (task → holder → record).
/// Pure state machine: ingest events in, decisions out.
#[derive(Debug, Default)]
pub struct ClaimSet {
    tasks: HashMap<String, HashMap<PublicId, ClaimRecord>>,
}

impl ClaimSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a fresh signed claim for `task`.
    pub fn make_claim(key: &Keypair, task: &str, now: Hlc, ttl_ms: u64) -> Envelope {
        let claim = Claim {
            task: task.to_string(),
            holder: key.public(),
            acquired: now,
            renewed: now,
            ttl_ms,
            released: false,
        };
        Envelope::seal(&claim, key)
    }

    /// Renew (or release) an existing hold, keeping `acquired` fixed.
    pub fn renew(key: &Keypair, prior: &Claim, renewed: Hlc, released: bool) -> Envelope {
        let claim = Claim {
            task: prior.task.clone(),
            holder: key.public(),
            acquired: prior.acquired,
            renewed,
            ttl_ms: prior.ttl_ms,
            released,
        };
        Envelope::seal(&claim, key)
    }

    /// Verify + fold one claim envelope in.
    pub fn ingest(&mut self, env: &Envelope) -> Result<Ingest, ClaimError> {
        let claim: Claim = env.open(None).map_err(ClaimError::Envelope)?;
        if claim.holder != env.signer {
            return Err(ClaimError::HolderMismatch);
        }
        if claim.renewed < claim.acquired {
            return Err(ClaimError::RenewedBeforeAcquired);
        }
        if claim.ttl_ms == 0 {
            return Err(ClaimError::ZeroTtl);
        }
        let digest = env.digest();
        let per_task = self.tasks.entry(claim.task.clone()).or_default();
        match per_task.get(&claim.holder) {
            Some(existing) => {
                if existing.digest == digest {
                    return Ok(Ingest::Stale);
                }
                // Same hold, newer renewal → replace. A *new* hold by
                // the same holder (after release/expiry) starts a new
                // acquired, which must sort after the old one.
                if claim.acquired == existing.claim.acquired {
                    if claim.renewed <= existing.claim.renewed {
                        return Ok(Ingest::Stale);
                    }
                } else if claim.acquired > existing.claim.acquired {
                    // fresh re-acquisition, accept
                } else {
                    return Err(ClaimError::AcquiredMoved);
                }
                per_task.insert(claim.holder, ClaimRecord { claim, digest, envelope: env.clone() });
                Ok(Ingest::Changed)
            }
            None => {
                per_task.insert(claim.holder, ClaimRecord { claim, digest, envelope: env.clone() });
                Ok(Ingest::Changed)
            }
        }
    }

    /// The current holder of `task`, if any live claim exists.
    pub fn winner(&self, task: &str, now_ms: u64) -> Option<&ClaimRecord> {
        self.tasks.get(task)?.values().filter(|r| r.claim.live(now_ms)).min_by(
            |a, b| {
                a.claim
                    .acquired
                    .cmp(&b.claim.acquired)
                    .then_with(|| a.digest.cmp(&b.digest))
            },
        )
    }

    /// Does `me` currently hold `task`?
    pub fn holds(&self, task: &str, me: &PublicId, now_ms: u64) -> bool {
        self.winner(task, now_ms).map(|r| r.claim.holder == *me).unwrap_or(false)
    }

    /// Should a node try to grab `task`? True when nobody holds it.
    pub fn open_for_claim(&self, task: &str, now_ms: u64) -> bool {
        self.winner(task, now_ms).is_none()
    }

    /// My own current claim on a task (live or not), for renewal.
    pub fn mine<'a>(&'a self, task: &str, me: &PublicId) -> Option<&'a ClaimRecord> {
        self.tasks.get(task)?.get(me)
    }

    /// Drop records dead for longer than `horizon_ms`. Returns pruned count.
    pub fn gc(&mut self, now_ms: u64, horizon_ms: u64) -> usize {
        let mut pruned = 0;
        self.tasks.retain(|_, per_task| {
            per_task.retain(|_, r| {
                let dead_since = r.claim.expires_at_ms().saturating_add(SKEW_SLACK_MS);
                let keep = !r.claim.released && now_ms < dead_since.saturating_add(horizon_ms);
                if !keep {
                    pruned += 1;
                }
                keep
            });
            !per_task.is_empty()
        });
        pruned
    }

    /// All live envelopes (for anti-entropy full-sync).
    pub fn live_envelopes(&self, now_ms: u64) -> Vec<&Envelope> {
        self.tasks
            .values()
            .flat_map(|m| m.values())
            .filter(|r| r.claim.live(now_ms))
            .map(|r| &r.envelope)
            .collect()
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Clock;

    fn kp(n: u8) -> Keypair {
        Keypair::from_seed([n; 32])
    }

    #[test]
    fn earliest_acquisition_wins() {
        let (a, b) = (kp(1), kp(2));
        let mut set = ClaimSet::new();
        let mut ca = Clock::new();
        let mut cb = Clock::new();
        let claim_a = ClaimSet::make_claim(&a, "t", ca.now(1000), 30_000);
        let claim_b = ClaimSet::make_claim(&b, "t", cb.now(2000), 30_000);
        set.ingest(&claim_b).unwrap();
        set.ingest(&claim_a).unwrap();
        assert_eq!(set.winner("t", 5000).unwrap().claim.holder, a.public());
    }

    #[test]
    fn expired_holder_loses_to_live_later_claim() {
        let (a, b) = (kp(1), kp(2));
        let mut set = ClaimSet::new();
        let claim_a =
            ClaimSet::make_claim(&a, "t", Hlc { wall_ms: 1000, logical: 0 }, 10_000);
        let claim_b =
            ClaimSet::make_claim(&b, "t", Hlc { wall_ms: 2000, logical: 0 }, 300_000);
        set.ingest(&claim_a).unwrap();
        set.ingest(&claim_b).unwrap();
        // While A is live it wins…
        assert_eq!(set.winner("t", 5000).unwrap().claim.holder, a.public());
        // …after A's ttl+slack lapses, B takes over.
        let after_a = 1000 + 10_000 + SKEW_SLACK_MS + 1;
        assert_eq!(set.winner("t", after_a).unwrap().claim.holder, b.public());
    }

    #[test]
    fn renewal_keeps_priority() {
        let a = kp(1);
        let mut set = ClaimSet::new();
        let first = ClaimSet::make_claim(&a, "t", Hlc { wall_ms: 1000, logical: 0 }, 10_000);
        set.ingest(&first).unwrap();
        let prior = set.mine("t", &a.public()).unwrap().claim.clone();
        let renewed = ClaimSet::renew(&a, &prior, Hlc { wall_ms: 9000, logical: 0 }, false);
        assert_eq!(set.ingest(&renewed).unwrap(), Ingest::Changed);
        // Still live well past the original expiry.
        let now = 1000 + 10_000 + 5000;
        assert_eq!(set.winner("t", now).unwrap().claim.holder, a.public());
        // Acquired unchanged → still beats a later acquirer.
        let b = kp(2);
        let cb = ClaimSet::make_claim(&b, "t", Hlc { wall_ms: 1500, logical: 0 }, 300_000);
        set.ingest(&cb).unwrap();
        assert_eq!(set.winner("t", now).unwrap().claim.holder, a.public());
    }

    #[test]
    fn release_frees_the_task() {
        let a = kp(1);
        let mut set = ClaimSet::new();
        let first = ClaimSet::make_claim(&a, "t", Hlc { wall_ms: 1000, logical: 0 }, 60_000);
        set.ingest(&first).unwrap();
        assert!(!set.open_for_claim("t", 2000));
        let prior = set.mine("t", &a.public()).unwrap().claim.clone();
        let rel = ClaimSet::renew(&a, &prior, Hlc { wall_ms: 3000, logical: 0 }, true);
        set.ingest(&rel).unwrap();
        assert!(set.open_for_claim("t", 4000));
    }

    #[test]
    fn forged_holder_rejected() {
        let (a, b) = (kp(1), kp(2));
        let claim = Claim {
            task: "t".into(),
            holder: a.public(), // claims to be A…
            acquired: Hlc { wall_ms: 1, logical: 0 },
            renewed: Hlc { wall_ms: 1, logical: 0 },
            ttl_ms: 1000,
            released: false,
        };
        let env = Envelope::seal(&claim, &b); // …signed by B
        let mut set = ClaimSet::new();
        assert_eq!(set.ingest(&env).unwrap_err(), ClaimError::HolderMismatch);
    }

    #[test]
    fn backdated_reacquisition_rejected() {
        let a = kp(1);
        let mut set = ClaimSet::new();
        set.ingest(&ClaimSet::make_claim(&a, "t", Hlc { wall_ms: 5000, logical: 0 }, 1000))
            .unwrap();
        let back = ClaimSet::make_claim(&a, "t", Hlc { wall_ms: 100, logical: 0 }, 1000);
        assert_eq!(set.ingest(&back).unwrap_err(), ClaimError::AcquiredMoved);
    }

    #[test]
    fn deterministic_tie_break_converges() {
        // Two claims with identical HLC: every node must pick the same
        // winner regardless of ingest order.
        let (a, b) = (kp(1), kp(2));
        let t = Hlc { wall_ms: 1000, logical: 0 };
        let ca = ClaimSet::make_claim(&a, "t", t, 60_000);
        let cb = ClaimSet::make_claim(&b, "t", t, 60_000);
        let mut s1 = ClaimSet::new();
        s1.ingest(&ca).unwrap();
        s1.ingest(&cb).unwrap();
        let mut s2 = ClaimSet::new();
        s2.ingest(&cb).unwrap();
        s2.ingest(&ca).unwrap();
        assert_eq!(
            s1.winner("t", 2000).unwrap().claim.holder,
            s2.winner("t", 2000).unwrap().claim.holder
        );
    }

    #[test]
    fn gc_prunes_long_dead_claims() {
        let a = kp(1);
        let mut set = ClaimSet::new();
        set.ingest(&ClaimSet::make_claim(&a, "t", Hlc { wall_ms: 1000, logical: 0 }, 1000))
            .unwrap();
        assert_eq!(set.gc(1000 + 1000 + SKEW_SLACK_MS + 10_000 + 1, 10_000), 1);
        assert_eq!(set.task_count(), 0);
    }
}
