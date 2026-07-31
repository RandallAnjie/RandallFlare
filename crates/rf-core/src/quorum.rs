//! Per-object micro-quorum: a small, faithful Raft specialized to
//! RandallFlare's setting — one instance per replicated object (a D1
//! database, later a Durable Object), a fixed 3-node replica group
//! chosen by rendezvous hashing, crash-stop faults, non-Byzantine
//! members (cluster-authenticated transport).
//!
//! Terminology maps to the DESIGN.md language: `epoch` is Raft's
//! term (the fencing token), `seq` is the log index. The guarantees
//! we lean on are Raft's:
//!   - Election safety: one leader per epoch (majority votes).
//!   - Leader completeness: a committed entry survives into every
//!     later epoch (election restriction on log up-to-dateness).
//!   - State machine safety: all members apply the same sequence.
//!
//! Pure core: no IO, no clocks, no randomness. The caller drives it
//! with `handle()` / `tick_election()` / `heartbeat()` and executes
//! the returned [`Action`]s (persist, send, apply). Timeouts and
//! their jitter live in the IO shell.
//!
//! Membership change is deliberately out of scope: a group is fixed
//! at object creation; regrouping is an operator-level copy-and-
//! switch (v0.4 problem).

use crate::identity::PublicId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub epoch: u64,
    pub seq: u64,
    pub cmd: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg {
    VoteReq {
        epoch: u64,
        last_epoch: u64,
        last_seq: u64,
    },
    VoteResp {
        epoch: u64,
        granted: bool,
    },
    Append {
        epoch: u64,
        prev_seq: u64,
        prev_epoch: u64,
        entries: Vec<Entry>,
        commit: u64,
    },
    AppendResp {
        epoch: u64,
        /// On success: highest seq now matching the leader's log.
        /// On failure: hint for the leader to back up (our last seq).
        match_seq: u64,
        ok: bool,
    },
}

/// What the IO shell must do after a transition. Ordering matters:
/// persistence actions precede the sends that depend on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Durably store (epoch, voted_for) BEFORE any subsequent send.
    PersistMeta,
    /// Durably store the log from `from_seq` onward (truncate + append).
    PersistLog { from_seq: u64 },
    Send(PublicId, Msg),
    /// Entry is committed — apply to the state machine (in order).
    Apply(Entry),
    /// Signals for the driver's bookkeeping.
    BecameLeader,
    LostLeadership,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Role {
    Follower,
    Candidate { votes: Vec<PublicId> },
    Leader { next: Vec<(PublicId, u64)>, matched: Vec<(PublicId, u64)> },
}

#[derive(Debug)]
pub struct Raft {
    pub me: PublicId,
    /// Full group, including `me`. Fixed for the object's lifetime.
    pub group: Vec<PublicId>,
    pub epoch: u64,
    pub voted_for: Option<PublicId>,
    /// seq of log[0] is 1; log is contiguous.
    pub log: Vec<Entry>,
    pub commit: u64,
    applied: u64,
    role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotLeader {
    /// Best guess at who is (the node we last granted a vote to or
    /// heard an Append from), for request forwarding.
    pub hint: Option<PublicId>,
}

impl Raft {
    pub fn new(me: PublicId, mut group: Vec<PublicId>) -> Self {
        if !group.contains(&me) {
            group.push(me);
        }
        group.sort_by(|a, b| a.0.cmp(&b.0));
        Self {
            me,
            group,
            epoch: 0,
            voted_for: None,
            log: Vec::new(),
            commit: 0,
            applied: 0,
            role: Role::Follower,
        }
    }

    /// Restore from persisted state (meta + log + last applied).
    pub fn restore(
        me: PublicId,
        group: Vec<PublicId>,
        epoch: u64,
        voted_for: Option<PublicId>,
        log: Vec<Entry>,
        applied: u64,
    ) -> Self {
        let mut r = Self::new(me, group);
        r.epoch = epoch;
        r.voted_for = voted_for;
        r.log = log;
        // Commit is volatile in Raft; it re-derives. Applied is the
        // state machine's high-water mark (never re-apply).
        r.commit = applied;
        r.applied = applied;
        r
    }

    pub fn is_leader(&self) -> bool {
        matches!(self.role, Role::Leader { .. })
    }

    pub fn leader_hint(&self) -> Option<PublicId> {
        if self.is_leader() {
            Some(self.me)
        } else {
            self.voted_for
        }
    }

    fn majority(&self) -> usize {
        self.group.len() / 2 + 1
    }

    fn last(&self) -> (u64, u64) {
        match self.log.last() {
            Some(e) => (e.epoch, e.seq),
            None => (0, 0),
        }
    }

    fn entry(&self, seq: u64) -> Option<&Entry> {
        if seq == 0 || seq as usize > self.log.len() {
            None
        } else {
            self.log.get(seq as usize - 1)
        }
    }

    fn others(&self) -> impl Iterator<Item = PublicId> + '_ {
        self.group.iter().copied().filter(move |p| *p != self.me)
    }

    /// Election timeout fired (caller-jittered): become candidate.
    pub fn tick_election(&mut self) -> Vec<Action> {
        if self.is_leader() {
            return vec![];
        }
        self.epoch += 1;
        self.voted_for = Some(self.me);
        self.role = Role::Candidate { votes: vec![self.me] };
        let (last_epoch, last_seq) = self.last();
        let mut actions = vec![Action::PersistMeta];
        for peer in self.others() {
            actions.push(Action::Send(
                peer,
                Msg::VoteReq { epoch: self.epoch, last_epoch, last_seq },
            ));
        }
        // Single-member group: win instantly.
        actions.extend(self.try_win());
        actions
    }

    /// Leader heartbeat / replication pulse. No-op for non-leaders.
    pub fn heartbeat(&mut self) -> Vec<Action> {
        if !self.is_leader() {
            return vec![];
        }
        self.replicate_all()
    }

    /// Propose a command. Returns its seq; committed once Apply fires.
    pub fn propose(&mut self, cmd: Vec<u8>) -> Result<(u64, Vec<Action>), NotLeader> {
        if !self.is_leader() {
            return Err(NotLeader { hint: self.leader_hint() });
        }
        let seq = self.last().1 + 1;
        let entry = Entry { epoch: self.epoch, seq, cmd };
        self.log.push(entry);
        let mut actions = vec![Action::PersistLog { from_seq: seq }];
        actions.extend(self.replicate_all());
        // Single-member group commits immediately.
        actions.extend(self.advance_commit());
        Ok((seq, actions))
    }

    fn become_follower(&mut self, epoch: u64) -> Vec<Action> {
        let was_leader = self.is_leader();
        let bump = epoch > self.epoch;
        if bump {
            self.epoch = epoch;
            self.voted_for = None;
        }
        self.role = Role::Follower;
        let mut actions = vec![];
        if bump {
            actions.push(Action::PersistMeta);
        }
        if was_leader {
            actions.push(Action::LostLeadership);
        }
        actions
    }

    fn try_win(&mut self) -> Vec<Action> {
        let Role::Candidate { votes } = &self.role else { return vec![] };
        if votes.len() < self.majority() {
            return vec![];
        }
        let next_seq = self.last().1 + 1;
        let next = self.others().map(|p| (p, next_seq)).collect();
        let matched = self.others().map(|p| (p, 0)).collect();
        self.role = Role::Leader { next, matched };
        let mut actions = vec![Action::BecameLeader];
        actions.extend(self.replicate_all());
        // A no-op entry would let us commit prior-epoch entries
        // immediately (Raft §5.4.2); we rely on the driver proposing
        // regularly instead, and on advance_commit's epoch check for
        // safety. D1 drivers propose a no-op on BecameLeader.
        actions
    }

    fn replicate_all(&mut self) -> Vec<Action> {
        let commit = self.commit;
        let epoch = self.epoch;
        let Role::Leader { next, .. } = &self.role else { return vec![] };
        let mut actions = vec![];
        for (peer, next_seq) in next.clone() {
            let prev_seq = next_seq - 1;
            let prev_epoch = self.entry(prev_seq).map(|e| e.epoch).unwrap_or(0);
            let entries: Vec<Entry> =
                self.log.iter().filter(|e| e.seq >= next_seq).cloned().collect();
            actions.push(Action::Send(
                peer,
                Msg::Append { epoch, prev_seq, prev_epoch, entries, commit },
            ));
        }
        actions
    }

    fn advance_commit(&mut self) -> Vec<Action> {
        let me_last = self.last().1;
        let epoch = self.epoch;
        let majority = self.majority();
        let Role::Leader { matched, .. } = &self.role else { return vec![] };
        // Highest N replicated on a majority (counting ourselves)
        // with log[N].epoch == current epoch (Raft's commit rule).
        let mut candidate = self.commit;
        for n in (self.commit + 1)..=me_last {
            let replicas =
                1 + matched.iter().filter(|(_, m)| *m >= n).count();
            if replicas >= majority {
                if self.entry(n).map(|e| e.epoch) == Some(epoch) {
                    candidate = n;
                }
            } else {
                break;
            }
        }
        let advanced = candidate > self.commit;
        if advanced {
            self.commit = candidate;
        }
        let mut actions = self.apply_committed();
        // Push the new commit index out immediately instead of
        // waiting a heartbeat — followers apply sooner, and the
        // exchange quiesces (their acks change nothing).
        if advanced {
            actions.extend(self.replicate_all());
        }
        actions
    }

    fn apply_committed(&mut self) -> Vec<Action> {
        let mut actions = vec![];
        while self.applied < self.commit {
            self.applied += 1;
            if let Some(e) = self.entry(self.applied) {
                actions.push(Action::Apply(e.clone()));
            }
        }
        actions
    }

    pub fn handle(&mut self, from: PublicId, msg: Msg) -> Vec<Action> {
        match msg {
            Msg::VoteReq { epoch, last_epoch, last_seq } => {
                let mut actions = vec![];
                if epoch > self.epoch {
                    actions.extend(self.become_follower(epoch));
                }
                let up_to_date = (last_epoch, last_seq) >= (self.last().0, self.last().1);
                let granted = epoch == self.epoch
                    && up_to_date
                    && (self.voted_for.is_none() || self.voted_for == Some(from));
                if granted && self.voted_for.is_none() {
                    self.voted_for = Some(from);
                    actions.push(Action::PersistMeta);
                }
                actions.push(Action::Send(
                    from,
                    Msg::VoteResp { epoch: self.epoch, granted },
                ));
                actions
            }
            Msg::VoteResp { epoch, granted } => {
                if epoch > self.epoch {
                    return self.become_follower(epoch);
                }
                if epoch != self.epoch || !granted {
                    return vec![];
                }
                if let Role::Candidate { votes } = &mut self.role {
                    if !votes.contains(&from) {
                        votes.push(from);
                    }
                }
                self.try_win()
            }
            Msg::Append { epoch, prev_seq, prev_epoch, entries, commit } => {
                if epoch < self.epoch {
                    return vec![Action::Send(
                        from,
                        Msg::AppendResp { epoch: self.epoch, match_seq: 0, ok: false },
                    )];
                }
                let mut actions = self.become_follower(epoch);
                // Heartbeats double as leadership discovery for
                // forwarding: remember who leads this epoch.
                if self.voted_for.is_none() {
                    self.voted_for = Some(from);
                    actions.push(Action::PersistMeta);
                }
                // Log consistency check at (prev_seq, prev_epoch).
                let prev_ok = prev_seq == 0
                    || self.entry(prev_seq).map(|e| e.epoch) == Some(prev_epoch);
                if !prev_ok {
                    let hint = self.last().1.min(prev_seq.saturating_sub(1));
                    actions.push(Action::Send(
                        from,
                        Msg::AppendResp { epoch: self.epoch, match_seq: hint, ok: false },
                    ));
                    return actions;
                }
                // Append, truncating any conflicting suffix.
                let mut persist_from: Option<u64> = None;
                for e in entries {
                    match self.entry(e.seq) {
                        Some(existing) if existing.epoch == e.epoch => continue,
                        _ => {
                            self.log.truncate(e.seq as usize - 1);
                            persist_from.get_or_insert(e.seq);
                            self.log.push(e);
                        }
                    }
                }
                if let Some(from_seq) = persist_from {
                    actions.push(Action::PersistLog { from_seq });
                }
                let match_seq = self.last().1;
                if commit > self.commit {
                    self.commit = commit.min(match_seq);
                    actions.extend(self.apply_committed());
                }
                actions.push(Action::Send(
                    from,
                    Msg::AppendResp { epoch: self.epoch, match_seq, ok: true },
                ));
                actions
            }
            Msg::AppendResp { epoch, match_seq, ok } => {
                if epoch > self.epoch {
                    return self.become_follower(epoch);
                }
                if epoch != self.epoch || !self.is_leader() {
                    return vec![];
                }
                let Role::Leader { next, matched } = &mut self.role else {
                    return vec![];
                };
                if ok {
                    if let Some(m) = matched.iter_mut().find(|(p, _)| *p == from) {
                        m.1 = m.1.max(match_seq);
                    }
                    if let Some(n) = next.iter_mut().find(|(p, _)| *p == from) {
                        n.1 = match_seq + 1;
                    }
                    self.advance_commit()
                } else {
                    // Back up toward the follower's hint and retry.
                    if let Some(n) = next.iter_mut().find(|(p, _)| *p == from) {
                        n.1 = (match_seq + 1).max(1).min(n.1.saturating_sub(1).max(1));
                    }
                    self.replicate_all()
                }
            }
        }
    }
}

/// Rendezvous hashing: pick the replica group for an object from the
/// node universe — deterministic on every node, no coordinator, and
/// adding nodes only moves ~1/n of objects.
pub fn rendezvous_group(object: &str, universe: &[PublicId], size: usize) -> Vec<PublicId> {
    use sha2::{Digest, Sha256};
    let mut scored: Vec<([u8; 32], PublicId)> = universe
        .iter()
        .map(|node| {
            let mut h = Sha256::new();
            h.update(object.as_bytes());
            h.update([0u8]);
            h.update(node.0);
            (h.finalize().into(), *node)
        })
        .collect();
    scored.sort();
    scored.into_iter().rev().take(size).map(|(_, n)| n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    fn pid(n: u8) -> PublicId {
        PublicId([n; 32])
    }

    /// Deterministic in-memory cluster harness: delivers messages
    /// from per-link queues in a caller-controlled order, tracks
    /// applied entries per node, and can partition links.
    struct Net {
        nodes: HashMap<PublicId, Raft>,
        queues: VecDeque<(PublicId, PublicId, Msg)>, // (from, to, msg)
        applied: HashMap<PublicId, Vec<Entry>>,
        cut: Vec<(PublicId, PublicId)>, // blocked directed links
        leaders_events: Vec<(PublicId, bool)>,
    }

    impl Net {
        fn new(ids: &[u8]) -> Self {
            let group: Vec<PublicId> = ids.iter().map(|n| pid(*n)).collect();
            let nodes = group
                .iter()
                .map(|id| (*id, Raft::new(*id, group.clone())))
                .collect();
            Net {
                nodes,
                queues: VecDeque::new(),
                applied: HashMap::new(),
                cut: Vec::new(),
                leaders_events: Vec::new(),
            }
        }

        fn absorb(&mut self, me: PublicId, actions: Vec<Action>) {
            for a in actions {
                match a {
                    Action::Send(to, msg) => self.queues.push_back((me, to, msg)),
                    Action::Apply(e) => self.applied.entry(me).or_default().push(e),
                    Action::BecameLeader => self.leaders_events.push((me, true)),
                    Action::LostLeadership => self.leaders_events.push((me, false)),
                    Action::PersistMeta | Action::PersistLog { .. } => {}
                }
            }
        }

        fn deliver_all(&mut self) {
            let mut budget = 10_000;
            while let Some((from, to, msg)) = self.queues.pop_front() {
                budget -= 1;
                assert!(budget > 0, "message storm — protocol not quiescing");
                if self.cut.contains(&(from, to)) {
                    continue;
                }
                let actions = self.nodes.get_mut(&to).unwrap().handle(from, msg);
                self.absorb(to, actions);
            }
        }

        fn elect(&mut self, id: u8) {
            let me = pid(id);
            let actions = self.nodes.get_mut(&me).unwrap().tick_election();
            self.absorb(me, actions);
            self.deliver_all();
        }

        fn propose(&mut self, id: u8, cmd: &[u8]) -> u64 {
            let me = pid(id);
            let (seq, actions) =
                self.nodes.get_mut(&me).unwrap().propose(cmd.to_vec()).expect("is leader");
            self.absorb(me, actions);
            self.deliver_all();
            seq
        }

        fn heartbeat(&mut self, id: u8) {
            let me = pid(id);
            let actions = self.nodes.get_mut(&me).unwrap().heartbeat();
            self.absorb(me, actions);
            self.deliver_all();
        }

        fn isolate(&mut self, id: u8) {
            let me = pid(id);
            for other in self.nodes.keys().copied().collect::<Vec<_>>() {
                if other != me {
                    self.cut.push((me, other));
                    self.cut.push((other, me));
                }
            }
        }

        fn heal(&mut self) {
            self.cut.clear();
        }

        fn applied_cmds(&self, id: u8) -> Vec<Vec<u8>> {
            self.applied
                .get(&pid(id))
                .map(|v| v.iter().map(|e| e.cmd.clone()).collect())
                .unwrap_or_default()
        }
    }

    #[test]
    fn three_node_replicate_and_commit() {
        let mut net = Net::new(&[1, 2, 3]);
        net.elect(1);
        assert!(net.nodes[&pid(1)].is_leader());
        net.propose(1, b"a");
        net.propose(1, b"b");
        for id in [1, 2, 3] {
            assert_eq!(net.applied_cmds(id), vec![b"a".to_vec(), b"b".to_vec()], "node {id}");
        }
    }

    #[test]
    fn stale_leader_is_fenced() {
        let mut net = Net::new(&[1, 2, 3]);
        net.elect(1);
        net.propose(1, b"a");
        // Old leader cut off; a new epoch starts without it.
        net.isolate(1);
        net.elect(2);
        assert!(net.nodes[&pid(2)].is_leader());
        net.propose(2, b"b");
        // The stale leader accepts a proposal locally but can commit
        // nothing (no majority reachable).
        let me = pid(1);
        let (_seq, actions) =
            net.nodes.get_mut(&me).unwrap().propose(b"stale".to_vec()).unwrap();
        net.absorb(me, actions);
        net.deliver_all();
        assert!(!net.applied_cmds(1).contains(&b"stale".to_vec()));
        // Once healed, its next pulse meets epoch 2 and it steps down.
        net.heal();
        net.heartbeat(1); // stale leader pulses, gets rejected + deposed
        net.heartbeat(2); // real leader converges everyone
        assert!(!net.nodes[&pid(1)].is_leader());
        for id in [1, 2, 3] {
            assert_eq!(net.applied_cmds(id), vec![b"a".to_vec(), b"b".to_vec()], "node {id}");
            assert!(!net.applied_cmds(id).contains(&b"stale".to_vec()));
        }
    }

    #[test]
    fn committed_entries_survive_leader_change() {
        let mut net = Net::new(&[1, 2, 3]);
        net.elect(1);
        net.propose(1, b"a");
        net.isolate(1);
        net.elect(2);
        net.propose(2, b"b");
        net.heal();
        net.heartbeat(2);
        // Node 1 rejoins as follower and converges on [a, b].
        assert_eq!(net.applied_cmds(1), vec![b"a".to_vec(), b"b".to_vec()]);
        assert!(!net.nodes[&pid(1)].is_leader());
    }

    #[test]
    fn election_restriction_protects_committed_entries() {
        let mut net = Net::new(&[1, 2, 3]);
        net.elect(1);
        net.propose(1, b"a"); // committed on all three
        net.isolate(3);
        net.propose(1, b"b"); // committed on 1+2 only
        net.heal();
        // Node 3 (shorter log) calls an election: 1 and 2 must refuse.
        net.elect(3);
        assert!(!net.nodes[&pid(3)].is_leader());
        // A node holding "b" can win and preserve it.
        net.elect(2);
        assert!(net.nodes[&pid(2)].is_leader());
        net.heartbeat(2);
        net.propose(2, b"c");
        for id in [1, 2, 3] {
            assert_eq!(
                net.applied_cmds(id),
                vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
                "node {id}"
            );
        }
    }

    #[test]
    fn divergent_uncommitted_suffix_is_overwritten() {
        let mut net = Net::new(&[1, 2, 3]);
        net.elect(1);
        net.propose(1, b"a");
        // Leader 1 accepts an entry locally but is cut before
        // replicating it.
        net.isolate(1);
        let me = pid(1);
        let (_seq, actions) = net.nodes.get_mut(&me).unwrap().propose(b"lost".to_vec()).unwrap();
        net.absorb(me, actions);
        net.deliver_all(); // all its sends are cut
        // New leader commits a different entry at that seq.
        net.elect(3);
        net.propose(3, b"kept");
        net.heal();
        net.heartbeat(3);
        // Node 1's uncommitted "lost" is gone; everyone has a, kept.
        for id in [1, 2, 3] {
            assert_eq!(net.applied_cmds(id), vec![b"a".to_vec(), b"kept".to_vec()], "node {id}");
        }
        // And "lost" was never applied anywhere.
        for id in [1, 2, 3] {
            assert!(!net.applied_cmds(id).contains(&b"lost".to_vec()));
        }
    }

    #[test]
    fn no_double_vote_in_one_epoch() {
        let mut net = Net::new(&[1, 2, 3]);
        // 1 wins epoch 1.
        net.elect(1);
        // 2 calls an election for the same epoch structure (its
        // epoch 2); 1 and 3 may grant — but if 3 then also calls at
        // epoch 2 it must fail (votes spent).
        net.isolate(1);
        let me2 = pid(2);
        let a = net.nodes.get_mut(&me2).unwrap().tick_election();
        net.absorb(me2, a);
        net.deliver_all();
        let me3 = pid(3);
        let a = net.nodes.get_mut(&me3).unwrap().tick_election();
        net.absorb(me3, a);
        net.deliver_all();
        let leaders = [2u8, 3]
            .iter()
            .filter(|id| net.nodes[&pid(**id)].is_leader())
            .count();
        assert!(leaders <= 1, "split vote must not elect two leaders in one epoch");
    }

    #[test]
    fn rendezvous_is_stable_and_spreads() {
        let universe: Vec<PublicId> = (1..=10u8).map(pid).collect();
        let g1 = rendezvous_group("db-a", &universe, 3);
        let g2 = rendezvous_group("db-a", &universe, 3);
        assert_eq!(g1, g2);
        assert_eq!(g1.len(), 3);
        // Removing an unrelated node keeps the group when possible.
        let smaller: Vec<PublicId> =
            universe.iter().copied().filter(|p| !g1.contains(p)).chain(g1.clone()).collect();
        let g3 = rendezvous_group("db-a", &smaller, 3);
        assert_eq!(
            g1.iter().collect::<std::collections::HashSet<_>>(),
            g3.iter().collect::<std::collections::HashSet<_>>()
        );
        // Different objects land on different groups at least sometimes.
        let spread: std::collections::HashSet<Vec<PublicId>> =
            (0..20).map(|i| rendezvous_group(&format!("db-{i}"), &universe, 3)).collect();
        assert!(spread.len() > 5);
    }

    #[test]
    fn single_member_group_commits_alone() {
        let mut net = Net::new(&[1]);
        net.elect(1);
        assert!(net.nodes[&pid(1)].is_leader());
        net.propose(1, b"solo");
        assert_eq!(net.applied_cmds(1), vec![b"solo".to_vec()]);
    }

    /// Chaos: random elections, proposals, partitions, message
    /// reorderings and drops across many seeds. Invariant: applied
    /// command sequences on any two nodes are prefix-compatible
    /// (state machine safety), regardless of what the network did.
    #[test]
    fn chaos_applied_logs_stay_prefix_consistent() {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        for seed in 0..60u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut net = Net::new(&[1, 2, 3]);
            let mut proposed = 0u32;
            for step in 0..400 {
                match rng.gen_range(0..100) {
                    0..=9 => {
                        let id = *[1u8, 2, 3].iter().nth(rng.gen_range(0..3)).unwrap();
                        let me = pid(id);
                        let actions = net.nodes.get_mut(&me).unwrap().tick_election();
                        net.absorb(me, actions);
                    }
                    10..=39 => {
                        // Propose on whichever node thinks it leads.
                        for id in [1u8, 2, 3] {
                            let me = pid(id);
                            if net.nodes[&me].is_leader() {
                                proposed += 1;
                                let cmd = format!("c{proposed}-s{step}").into_bytes();
                                if let Ok((_, actions)) =
                                    net.nodes.get_mut(&me).unwrap().propose(cmd)
                                {
                                    net.absorb(me, actions);
                                }
                                break;
                            }
                        }
                    }
                    40..=49 => {
                        // Random partition flip.
                        if net.cut.is_empty() {
                            let id = *[1u8, 2, 3].iter().nth(rng.gen_range(0..3)).unwrap();
                            net.isolate(id);
                        } else {
                            net.heal();
                        }
                    }
                    50..=59 => {
                        // Drop a random in-flight message.
                        if !net.queues.is_empty() {
                            let idx = rng.gen_range(0..net.queues.len());
                            net.queues.remove(idx);
                        }
                    }
                    _ => {
                        // Deliver ONE random in-flight message.
                        if !net.queues.is_empty() {
                            let idx = rng.gen_range(0..net.queues.len());
                            let (from, to, msg) = net.queues.remove(idx).unwrap();
                            if !net.cut.contains(&(from, to)) {
                                let actions =
                                    net.nodes.get_mut(&to).unwrap().handle(from, msg);
                                net.absorb(to, actions);
                            }
                        }
                    }
                }
            }
            net.heal();
            net.deliver_all();
            // Invariant check.
            for a in [1u8, 2, 3] {
                for b in [1u8, 2, 3] {
                    let la = net.applied_cmds(a);
                    let lb = net.applied_cmds(b);
                    let n = la.len().min(lb.len());
                    assert_eq!(
                        &la[..n],
                        &lb[..n],
                        "seed {seed}: applied logs diverged between {a} and {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn restore_rejoins_and_catches_up() {
        let mut net = Net::new(&[1, 2, 3]);
        net.elect(1);
        net.propose(1, b"a");
        // Snapshot node 3's durable state and "restart" it.
        let old = &net.nodes[&pid(3)];
        let restored = Raft::restore(
            pid(3),
            old.group.clone(),
            old.epoch,
            old.voted_for,
            old.log.clone(),
            1, // applied a
        );
        net.nodes.insert(pid(3), restored);
        net.propose(1, b"b");
        // Restored node applies only the new entry (no re-apply of a).
        assert_eq!(net.applied_cmds(3), vec![b"a".to_vec(), b"b".to_vec()]);
        let post_restart = net.applied.get(&pid(3)).unwrap();
        assert_eq!(post_restart.iter().filter(|e| e.cmd == b"a").count(), 1);
    }
}
