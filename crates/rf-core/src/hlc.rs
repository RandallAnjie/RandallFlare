//! Hybrid logical clock.
//!
//! Total order over events in a cluster with loosely-synced wall
//! clocks: `(wall_ms, logical)` advances monotonically even when the
//! local wall clock stalls or steps backward, and observing a remote
//! timestamp pulls us ahead of it. Ties across nodes are broken by the
//! caller (claims hash-break; KV breaks by writer id) — the clock
//! itself carries no node id so equal timestamps stay comparable.

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Hlc {
    pub wall_ms: u64,
    pub logical: u32,
}

/// Clock state. Pure: the caller feeds in wall time, so tests (and a
/// future deterministic simulator) control time completely.
#[derive(Debug, Clone, Copy, Default)]
pub struct Clock {
    last: Hlc,
}

impl Clock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Timestamp a local event at wall time `wall_ms`.
    pub fn now(&mut self, wall_ms: u64) -> Hlc {
        if wall_ms > self.last.wall_ms {
            self.last = Hlc {
                wall_ms,
                logical: 0,
            };
        } else {
            self.last.logical += 1;
        }
        self.last
    }

    /// Fold a remote timestamp in; the next `now()` is guaranteed to
    /// sort after both it and everything we issued before.
    pub fn observe(&mut self, remote: Hlc, wall_ms: u64) {
        let base = self.last.max(remote);
        self.last = if wall_ms > base.wall_ms {
            // Real time has moved past both — logical resets on the
            // next tick via now(); store base so ordering holds even
            // if now() is called with a stale wall clock.
            base
        } else {
            Hlc {
                wall_ms: base.wall_ms,
                logical: base.logical + 1,
            }
        };
    }

    pub fn last(&self) -> Hlc {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_under_stalled_wall_clock() {
        let mut c = Clock::new();
        let a = c.now(100);
        let b = c.now(100);
        let d = c.now(99); // wall clock stepped back
        assert!(a < b && b < d);
    }

    #[test]
    fn observe_pulls_ahead_of_remote() {
        let mut c = Clock::new();
        c.now(100);
        let remote = Hlc {
            wall_ms: 5000,
            logical: 7,
        };
        c.observe(remote, 100);
        assert!(c.now(100) > remote);
    }

    #[test]
    fn wall_progress_resets_logical() {
        let mut c = Clock::new();
        for _ in 0..10 {
            c.now(100);
        }
        let t = c.now(200);
        assert_eq!(
            t,
            Hlc {
                wall_ms: 200,
                logical: 0
            }
        );
    }

    #[test]
    fn observe_then_real_time_advances() {
        let mut c = Clock::new();
        c.observe(
            Hlc {
                wall_ms: 500,
                logical: 3,
            },
            100,
        );
        let t = c.now(600);
        assert_eq!(
            t,
            Hlc {
                wall_ms: 600,
                logical: 0
            }
        );
        let t2 = c.now(600);
        assert!(t2 > t);
    }
}
