//! D1 — replicated SQLite over per-database micro-quorums.
//!
//! Each database has a fixed replica group (rendezvous-hashed at
//! creation, recorded in the `__rf` KV as `d1/<name>`). Group members
//! run one driver task apiece: a `rf_core::quorum::Raft` instance
//! whose committed commands are SQL statements applied to a local
//! SQLite file. Writes go leader → majority-replicated log → applied
//! everywhere; the proposer's HTTP request completes when its entry
//! applies. Reads run on the leader's local SQLite.
//!
//! Raft state is durable in redb (meta + log) next to everything
//! else; the SQLite file tracks `applied` via a `_rf_applied` marker
//! table updated in the same transaction as each statement, so a
//! crash between "apply" and "remember we applied" can't double-run
//! a statement.

use crate::node::Node;
use crate::peers::PeerClient;
use anyhow::{Context, Result};
use rf_core::identity::PublicId;
use rf_core::quorum::{Action, Entry, Msg, Raft};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Serialize, Deserialize)]
pub struct DbMeta {
    pub group: Vec<PublicId>,
    pub created_ms: u64,
}

/// A committed command: one SQL statement with JSON params.
#[derive(Debug, Serialize, Deserialize)]
pub struct Cmd {
    #[serde(default)]
    pub sql: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
    /// Newer commands may contain an atomic ordered batch. Empty keeps the
    /// original single-statement wire format backward-compatible with stored
    /// Raft logs and snapshots.
    #[serde(default)]
    pub statements: Vec<Statement>,
    /// Random tag so the proposer can recognize its own entry.
    pub tag: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub sql: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementResult {
    pub rows: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
    pub rows_affected: Option<u64>,
}

pub struct SnapshotResult {
    pub data: Option<Vec<u8>>,
    pub leader_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireMsg {
    pub from: PublicId,
    pub msg: Msg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecResult {
    pub rows: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
    pub rows_affected: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<Vec<StatementResult>>,
    /// Set when this node isn't the leader: api addr to retry against.
    pub leader_hint: Option<String>,
}

pub enum DriverCmd {
    Net(WireMsg),
    Exec {
        sql: String,
        params: Vec<serde_json::Value>,
        resp: oneshot::Sender<Result<ExecResult>>,
    },
    Batch {
        statements: Vec<Statement>,
        resp: oneshot::Sender<Result<ExecResult>>,
    },
    Snapshot {
        resp: oneshot::Sender<Result<SnapshotResult>>,
    },
}

/// db name → driver inbox; peerapi routes into this.
pub type Registry = Arc<Mutex<HashMap<String, mpsc::Sender<DriverCmd>>>>;
/// Database name → most recently observed Raft leader. Followers learn
/// this from Append heartbeats; runtimes use it for fenced ownership.
pub type Leadership = Arc<Mutex<HashMap<String, PublicId>>>;

pub fn kv_key(name: &str) -> String {
    format!("d1/{name}")
}

pub fn database_names(node: &Node) -> Vec<String> {
    let mut names = node
        .kv_dump(acme_ns())
        .into_iter()
        .filter_map(|(key, entry)| {
            entry
                .visible(crate::node::now_ms())
                .and_then(|_| key.strip_prefix("d1/").map(str::to_string))
        })
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

/// Create a fixed micro-quorum record if absent. The caller should do
/// this after membership has converged; the group is immutable once
/// published, exactly like user-created D1 databases.
pub fn ensure_database(node: &Node, name: &str) -> Result<Vec<PublicId>> {
    let mut universe = vec![node.id()];
    for (id_hex, _) in node.peers() {
        if let Ok(id) = id_hex.parse() {
            universe.push(id);
        }
    }
    ensure_database_on(node, name, universe)
}

/// Create a database on an explicitly selected immutable replica universe.
/// Durable Objects use this to keep their fenced owner inside the Worker's
/// signed placement constraints from the first commit onward.
pub fn ensure_database_on(
    node: &Node,
    name: &str,
    mut universe: Vec<PublicId>,
) -> Result<Vec<PublicId>> {
    let key = kv_key(name);
    if let Some(raw) = node.kv_get(acme_ns(), &key) {
        let meta: DbMeta = serde_json::from_slice(&raw)?;
        return Ok(meta.group);
    }
    universe.sort();
    universe.dedup();
    if universe.is_empty() {
        anyhow::bail!("D1 replica universe cannot be empty");
    }
    let group = rf_core::quorum::rendezvous_group(name, &universe, 3);
    let meta = DbMeta {
        group: group.clone(),
        created_ms: crate::node::now_ms(),
    };
    node.kv_put(acme_ns(), &key, Some(serde_json::to_vec(&meta)?), None)?;
    Ok(group)
}

/// Execute directly against a local driver. This is used by the DO
/// owner after Leadership says this node is the fenced leader.
pub async fn exec_local(
    registry: &Registry,
    name: &str,
    sql: impl Into<String>,
    params: Vec<serde_json::Value>,
) -> Result<ExecResult> {
    let tx = registry
        .lock()
        .unwrap()
        .get(name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("quorum driver {name} is not local"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(DriverCmd::Exec {
        sql: sql.into(),
        params,
        resp: resp_tx,
    })
    .await
    .map_err(|_| anyhow::anyhow!("quorum driver {name} stopped"))?;
    let result = tokio::time::timeout(Duration::from_secs(30), resp_rx)
        .await
        .context("quorum commit timed out")?
        .context("quorum driver dropped response")??;
    if result.leader_hint.is_some() || (result.rows.is_none() && result.rows_affected.is_none()) {
        anyhow::bail!("local node is not leader for {name}");
    }
    Ok(result)
}

fn is_read(conn: &rusqlite::Connection, sql: &str) -> Result<bool> {
    // Let SQLite classify the compiled statement. Prefix matching
    // gets CTE reads wrong and, more dangerously, treats mutating
    // PRAGMAs as leader-local reads.
    Ok(conn.prepare(sql)?.readonly())
}

/// Manager: watches the KV for databases whose group includes us and
/// spawns a driver per db.
pub fn spawn_manager(
    node: Arc<Node>,
    registry: Registry,
    leadership: Leadership,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            for key in node.kv_list(acme_ns(), "d1/", 10_000) {
                let name = key.trim_start_matches("d1/").to_string();
                let Some(raw) = node.kv_get(acme_ns(), &key) else {
                    continue;
                };
                let Ok(meta) = serde_json::from_slice::<DbMeta>(&raw) else {
                    continue;
                };
                if !meta.group.contains(&node.id()) {
                    continue;
                }
                let mut reg = registry.lock().unwrap();
                if reg.contains_key(&name) {
                    continue;
                }
                let (tx, rx) = mpsc::channel(256);
                reg.insert(name.clone(), tx);
                drop(reg);
                match Driver::open(
                    node.clone(),
                    name.clone(),
                    meta.group.clone(),
                    leadership.clone(),
                ) {
                    Ok(driver) => {
                        tokio::spawn(driver.run(rx));
                        tracing::info!("d1: driver up for {name}");
                    }
                    Err(e) => {
                        tracing::warn!("d1: opening {name}: {e:#}");
                        registry.lock().unwrap().remove(&name);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

struct Driver {
    node: Arc<Node>,
    name: String,
    raft: Raft,
    sql: rusqlite::Connection,
    path: std::path::PathBuf,
    client: PeerClient,
    /// tag → responder for proposals in flight.
    pending: HashMap<u64, oneshot::Sender<Result<ExecResult>>>,
    /// seq → tag for entries we proposed.
    my_entries: HashMap<u64, u64>,
    leadership: Leadership,
}

fn acme_ns() -> &'static str {
    crate::acme::NS
}

impl Driver {
    fn open(
        node: Arc<Node>,
        name: String,
        group: Vec<PublicId>,
        leadership: Leadership,
    ) -> Result<Self> {
        let dir = node.cfg.data_dir.join("d1");
        std::fs::create_dir_all(&dir)?;
        let sql = rusqlite::Connection::open(dir.join(format!("{name}.sqlite")))?;
        // (path recorded below for snapshot capture/install)
        sql.pragma_update(None, "journal_mode", "WAL")?;
        sql.execute_batch(
            "CREATE TABLE IF NOT EXISTS _rf_applied (id INTEGER PRIMARY KEY CHECK (id = 0), seq INTEGER NOT NULL);
             INSERT OR IGNORE INTO _rf_applied (id, seq) VALUES (0, 0);",
        )?;
        let applied_i: i64 =
            sql.query_row("SELECT seq FROM _rf_applied WHERE id = 0", [], |r| r.get(0))?;
        let applied = applied_i as u64;
        let (epoch, voted_for, base_seq, base_epoch) = node.store.load_d1_meta(&name)?;
        let log = node.store.load_d1_log(&name)?;
        let raft = Raft::restore(
            node.id(),
            group,
            epoch,
            voted_for,
            base_seq,
            base_epoch,
            log,
            applied,
        );
        let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
        let path = dir.join(format!("{name}.sqlite"));
        Ok(Self {
            node,
            name,
            raft,
            sql,
            path,
            client,
            pending: HashMap::new(),
            my_entries: HashMap::new(),
            leadership,
        })
    }

    async fn run(mut self, mut rx: mpsc::Receiver<DriverCmd>) {
        // Raft-standard randomized election timeout, re-rolled every
        // round — static jitter livelocks two survivors into repeated
        // split votes.
        fn roll() -> Duration {
            Duration::from_millis(1200 + rand::random::<u64>() % 1200)
        }
        let mut election_timeout = roll();
        let heartbeat_every = Duration::from_millis(400);
        let mut last_leader_contact = tokio::time::Instant::now();
        let mut heartbeat = tokio::time::interval(heartbeat_every);
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(DriverCmd::Net(wire)) => {
                        if matches!(wire.msg, Msg::Append { .. }) {
                            last_leader_contact = tokio::time::Instant::now();
                        }
                        let actions = self.raft.handle(wire.from, wire.msg);
                        self.execute(actions).await;
                    }
                    Some(DriverCmd::Exec { sql, params, resp }) => {
                        self.exec(sql, params, resp).await;
                    }
                    Some(DriverCmd::Batch { statements, resp }) => {
                        self.batch(statements, resp).await;
                    }
                    Some(DriverCmd::Snapshot { resp }) => {
                        if self.raft.is_leader() {
                            let result = self.export_snapshot().map(|data| SnapshotResult {
                                data: Some(data),
                                leader_hint: None,
                            });
                            let _ = resp.send(result);
                        } else {
                            let _ = resp.send(Ok(SnapshotResult {
                                data: None,
                                leader_hint: self.leader_api_addr(),
                            }));
                        }
                    }
                    None => return,
                },
                _ = heartbeat.tick() => {
                    if self.raft.is_leader() {
                        let actions = self.raft.heartbeat();
                        self.execute(actions).await;
                    } else if last_leader_contact.elapsed() > election_timeout {
                        last_leader_contact = tokio::time::Instant::now();
                        election_timeout = roll();
                        let actions = self.raft.tick_election();
                        self.execute(actions).await;
                    }
                }
            }
        }
    }

    async fn exec(
        &mut self,
        sql: String,
        params: Vec<serde_json::Value>,
        resp: oneshot::Sender<Result<ExecResult>>,
    ) {
        if !self.raft.is_leader() {
            let hint = self.leader_api_addr();
            let _ = resp.send(Ok(ExecResult {
                rows: None,
                rows_affected: None,
                batch: None,
                leader_hint: hint,
            }));
            return;
        }
        match is_read(&self.sql, &sql) {
            Ok(true) => {
                let _ = resp.send(run_query(&self.sql, &sql, &params));
                return;
            }
            Ok(false) => {}
            Err(e) => {
                let _ = resp.send(Err(e));
                return;
            }
        }
        let tag: u64 = rand::random();
        let cmd = Cmd {
            sql,
            params,
            statements: Vec::new(),
            tag,
        };
        self.propose(cmd, resp).await;
    }

    async fn batch(
        &mut self,
        statements: Vec<Statement>,
        resp: oneshot::Sender<Result<ExecResult>>,
    ) {
        if !self.raft.is_leader() {
            let hint = self.leader_api_addr();
            let _ = resp.send(Ok(ExecResult {
                rows: None,
                rows_affected: None,
                batch: None,
                leader_hint: hint,
            }));
            return;
        }
        if statements.is_empty() || statements.len() > 100 {
            let _ = resp.send(Err(anyhow::anyhow!(
                "D1 atomic batch must contain 1..100 statements"
            )));
            return;
        }
        if let Some(statement) = statements.iter().find(|statement| {
            statement.sql.trim().is_empty()
                || statement.sql.len() > 1024 * 1024
                || statement.params.len() > 1000
        }) {
            let _ = resp.send(Err(anyhow::anyhow!(
                "invalid D1 batch statement: {:?}",
                statement.sql.chars().take(80).collect::<String>()
            )));
            return;
        }
        let reads_only = statements
            .iter()
            .map(|statement| is_read(&self.sql, &statement.sql))
            .collect::<Result<Vec<_>>>();
        match reads_only {
            Ok(kinds) if kinds.iter().all(|read| *read) => {
                let result = (|| -> Result<ExecResult> {
                    let tx = self.sql.unchecked_transaction()?;
                    let results = run_statements(&tx, &statements)?;
                    tx.commit()?;
                    Ok(ExecResult {
                        rows: None,
                        rows_affected: Some(0),
                        batch: Some(results),
                        leader_hint: None,
                    })
                })();
                let _ = resp.send(result);
                return;
            }
            Ok(_) => {}
            Err(error) => {
                let _ = resp.send(Err(error));
                return;
            }
        }
        let tag: u64 = rand::random();
        let cmd = Cmd {
            sql: String::new(),
            params: Vec::new(),
            statements,
            tag,
        };
        self.propose(cmd, resp).await;
    }

    async fn propose(&mut self, cmd: Cmd, resp: oneshot::Sender<Result<ExecResult>>) {
        let tag = cmd.tag;
        let bytes = serde_json::to_vec(&cmd).expect("cmd encode");
        match self.raft.propose(bytes) {
            Ok((seq, actions)) => {
                self.pending.insert(tag, resp);
                self.my_entries.insert(seq, tag);
                self.execute(actions).await;
            }
            Err(_) => {
                let hint = self.leader_api_addr();
                let _ = resp.send(Ok(ExecResult {
                    rows: None,
                    rows_affected: None,
                    batch: None,
                    leader_hint: hint,
                }));
            }
        }
    }

    fn leader_api_addr(&self) -> Option<String> {
        let hint = self.raft.leader_hint()?;
        if hint == self.node.id() {
            return None;
        }
        self.node
            .peers()
            .get(&hint.to_string())
            .and_then(|p| p.api_addr)
            .map(|a| a.to_string())
    }

    async fn execute(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::PersistMeta => {
                    if let Err(e) = self.node.store.put_d1_meta(
                        &self.name,
                        self.raft.epoch,
                        self.raft.voted_for,
                        self.raft.base_seq,
                        self.raft.base_epoch,
                    ) {
                        tracing::error!("d1 {}: persist meta: {e:#}", self.name);
                    }
                }
                Action::PersistLog { from_seq } => {
                    let tail: Vec<Entry> = self
                        .raft
                        .log
                        .iter()
                        .filter(|e| e.seq >= from_seq)
                        .cloned()
                        .collect();
                    if let Err(e) = self.node.store.put_d1_log(&self.name, from_seq, &tail) {
                        tracing::error!("d1 {}: persist log: {e:#}", self.name);
                    }
                }
                Action::Send(to, msg) => {
                    let Some(peer) = self
                        .node
                        .peers()
                        .get(&to.to_string())
                        .and_then(|p| p.api_addr)
                    else {
                        continue; // peer offline; retried on next pulse
                    };
                    let wire = WireMsg {
                        from: self.node.id(),
                        msg,
                    };
                    let body = postcard::to_stdvec(&wire).expect("wire encode");
                    let client = self.client.clone();
                    let name = self.name.clone();
                    tokio::spawn(async move {
                        let path = format!("/v1/quorum/{name}");
                        if let Err(e) = client.post(&peer.to_string(), &path, body).await {
                            tracing::debug!("d1 {name}: send to {peer}: {e}");
                        }
                    });
                }
                Action::Apply(entry) => self.apply(entry),
                Action::NeedSnapshot { to } => match self.capture_snapshot() {
                    Ok(data) => {
                        let (last_seq, last_epoch) = self.raft.snapshot_point();
                        let msg = Msg::InstallSnapshot {
                            epoch: self.raft.epoch,
                            last_seq,
                            last_epoch,
                            data,
                        };
                        let wire = WireMsg {
                            from: self.node.id(),
                            msg,
                        };
                        let Some(peer) = self
                            .node
                            .peers()
                            .get(&to.to_string())
                            .and_then(|p| p.api_addr)
                        else {
                            continue;
                        };
                        let body = postcard::to_stdvec(&wire).expect("wire encode");
                        let client = self.client.clone();
                        let name = self.name.clone();
                        tokio::spawn(async move {
                            let path = format!("/v1/quorum/{name}");
                            if let Err(e) = client.post(&peer.to_string(), &path, body).await {
                                tracing::debug!("d1 {name}: snapshot to {peer}: {e}");
                            }
                        });
                        tracing::info!(
                            "d1 {}: shipping snapshot (seq {last_seq}) to laggard",
                            self.name
                        );
                    }
                    Err(e) => tracing::warn!("d1 {}: snapshot capture: {e:#}", self.name),
                },
                Action::ApplySnapshot { seq, data } => {
                    if let Err(e) = self.install_snapshot(seq, &data) {
                        tracing::error!("d1 {}: snapshot install: {e:#}", self.name);
                    } else {
                        tracing::info!("d1 {}: installed snapshot at seq {seq}", self.name);
                    }
                }
                Action::BecameLeader => {
                    tracing::info!("d1 {}: leader (epoch {})", self.name, self.raft.epoch);
                }
                Action::LostLeadership => {
                    tracing::info!("d1 {}: stepped down", self.name);
                    // Fail proposals we can no longer see through.
                    for (_, resp) in self.pending.drain() {
                        let _ = resp.send(Ok(ExecResult {
                            rows: None,
                            rows_affected: None,
                            batch: None,
                            leader_hint: None,
                        }));
                    }
                    self.my_entries.clear();
                }
            }
        }
        self.maybe_compact();
        let mut leaders = self.leadership.lock().unwrap();
        if let Some(leader) = self.raft.leader_hint() {
            leaders.insert(self.name.clone(), leader);
        } else {
            leaders.remove(&self.name);
        }
    }

    /// Read the SQLite file as a complete snapshot: checkpoint the
    /// WAL first so the main file alone is the full state.
    fn capture_snapshot(&mut self) -> Result<Vec<u8>> {
        self.sql
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .context("wal checkpoint")?;
        std::fs::read(&self.path).context("reading sqlite file")
    }

    /// Create a portable SQLite backup for an operator download. The Raft
    /// apply marker is stripped from the copy, never from the live database.
    fn export_snapshot(&mut self) -> Result<Vec<u8>> {
        let path = self
            .path
            .with_extension(format!("export-{}.sqlite", rand::random::<u64>()));
        let result = portable_sqlite_backup(&self.sql, &path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
        result
    }

    /// Replace the local database with a shipped snapshot.
    fn install_snapshot(&mut self, seq: u64, data: &[u8]) -> Result<()> {
        // Swap the connection out before touching files.
        let tmp = self.path.with_extension("snap-tmp");
        std::fs::write(&tmp, data)?;
        // Point the handle at an in-memory db while we replace the
        // file (dropping the old connection releases its locks).
        self.sql = rusqlite::Connection::open_in_memory()?;
        // Stale WAL/SHM from the old database must not survive the
        // swap — they'd be replayed into the new file.
        let _ = std::fs::remove_file(self.path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(self.path.with_extension("sqlite-shm"));
        std::fs::rename(&tmp, &self.path)?;
        let sql = rusqlite::Connection::open(&self.path)?;
        sql.pragma_update(None, "journal_mode", "WAL")?;
        let marker: i64 =
            sql.query_row("SELECT seq FROM _rf_applied WHERE id = 0", [], |r| r.get(0))?;
        if marker as u64 != seq {
            // Shouldn't happen (sender captures at its applied mark);
            // trust the protocol's declared seq.
            tracing::warn!(
                "d1 {}: snapshot marker {marker} != declared {seq}; correcting",
                self.name
            );
            sql.execute("UPDATE _rf_applied SET seq = ?1 WHERE id = 0", [seq as i64])?;
        }
        self.sql = sql;
        Ok(())
    }

    /// Compact the in-memory + stored log once it outgrows the
    /// configured threshold.
    fn maybe_compact(&mut self) {
        let (threshold, keep) = if self.name.starts_with("rfdo-") {
            // Each DO entry contains a compressed SQLite directory
            // snapshot and is much larger than an ordinary SQL command.
            (8, 1)
        } else {
            (
                self.node.cfg.d1.compact_threshold,
                self.node.cfg.d1.keep_tail,
            )
        };
        if (self.raft.log.len() as u64) <= threshold {
            return;
        }
        if self.raft.compact(keep) {
            if let Err(e) = self
                .node
                .store
                .compact_d1_log(&self.name, self.raft.base_seq)
            {
                tracing::error!("d1 {}: compact store: {e:#}", self.name);
            }
            if let Err(e) = self.node.store.put_d1_meta(
                &self.name,
                self.raft.epoch,
                self.raft.voted_for,
                self.raft.base_seq,
                self.raft.base_epoch,
            ) {
                tracing::error!("d1 {}: compact meta: {e:#}", self.name);
            }
            tracing::info!(
                "d1 {}: compacted log below seq {}",
                self.name,
                self.raft.base_seq
            );
        }
    }

    fn apply(&mut self, entry: Entry) {
        let result = (|| -> Result<(bool, Vec<StatementResult>)> {
            let cmd: Cmd = serde_json::from_slice(&entry.cmd).context("cmd decode")?;
            let is_batch = !cmd.statements.is_empty();
            let statements = if is_batch {
                cmd.statements
            } else {
                vec![Statement {
                    sql: cmd.sql,
                    params: cmd.params,
                }]
            };
            let tx = self.sql.unchecked_transaction()?;
            let results = run_statements(&tx, &statements)?;
            tx.execute(
                "UPDATE _rf_applied SET seq = ?1 WHERE id = 0",
                [entry.seq as i64],
            )?;
            tx.commit()?;
            Ok((is_batch, results))
        })();
        // Answer the proposer if this was ours.
        if let Some(tag) = self.my_entries.remove(&entry.seq) {
            if let Some(resp) = self.pending.remove(&tag) {
                let _ = resp.send(result.map(|(is_batch, mut results)| {
                    if is_batch {
                        let rows_affected = results
                            .iter()
                            .filter_map(|result| result.rows_affected)
                            .sum();
                        ExecResult {
                            rows: None,
                            rows_affected: Some(rows_affected),
                            batch: Some(results),
                            leader_hint: None,
                        }
                    } else {
                        let result = results.pop().unwrap_or(StatementResult {
                            rows: None,
                            rows_affected: Some(0),
                        });
                        ExecResult {
                            rows: result.rows,
                            rows_affected: result.rows_affected,
                            batch: None,
                            leader_hint: None,
                        }
                    }
                }));
                return;
            }
        }
        if let Err(e) = result {
            // Deterministic SQL errors (constraint violations) apply
            // as no-ops everywhere — consistent, just failed.
            tracing::debug!("d1 {}: apply seq {}: {e:#}", self.name, entry.seq);
        }
    }
}

fn bind_params(stmt: &mut rusqlite::Statement<'_>, params: &[serde_json::Value]) -> Result<()> {
    for (i, p) in params.iter().enumerate() {
        let idx = i + 1;
        match p {
            serde_json::Value::Null => stmt.raw_bind_parameter(idx, rusqlite::types::Null)?,
            serde_json::Value::Bool(b) => stmt.raw_bind_parameter(idx, *b as i64)?,
            serde_json::Value::Number(n) => {
                if let Some(v) = n.as_i64() {
                    stmt.raw_bind_parameter(idx, v)?
                } else {
                    stmt.raw_bind_parameter(idx, n.as_f64().unwrap_or(0.0))?
                }
            }
            serde_json::Value::String(s) => stmt.raw_bind_parameter(idx, s.as_str())?,
            other => stmt.raw_bind_parameter(idx, other.to_string())?,
        }
    }
    Ok(())
}

fn run_statements(
    connection: &rusqlite::Connection,
    statements: &[Statement],
) -> Result<Vec<StatementResult>> {
    let mut results = Vec::with_capacity(statements.len());
    for statement in statements {
        let mut prepared = connection.prepare(&statement.sql)?;
        bind_params(&mut prepared, &statement.params)?;
        // SQLite marks DML with RETURNING as mutating, but it still produces
        // rows and therefore must be stepped with query semantics. The
        // statement has already reached this function through the replicated
        // write path, so reading its result does not weaken consistency.
        if prepared.readonly() || prepared.column_count() > 0 {
            results.push(StatementResult {
                rows: Some(read_prepared_rows(&mut prepared)?),
                rows_affected: None,
            });
        } else {
            results.push(StatementResult {
                rows: None,
                rows_affected: Some(prepared.raw_execute()? as u64),
            });
        }
    }
    Ok(results)
}

fn portable_sqlite_backup(
    connection: &rusqlite::Connection,
    path: &std::path::Path,
) -> Result<Vec<u8>> {
    connection
        .backup(rusqlite::MAIN_DB, path, None)
        .context("creating D1 SQLite backup")?;
    let exported = rusqlite::Connection::open(path)?;
    exported.execute_batch(
        "DROP TABLE IF EXISTS _rf_applied;
         PRAGMA journal_mode = DELETE;
         VACUUM;",
    )?;
    drop(exported);
    let bytes = std::fs::read(path)?;
    if bytes.len() > crate::binary::MAX_BINARY_BYTES {
        anyhow::bail!("D1 export exceeds the 200 MiB transfer limit");
    }
    Ok(bytes)
}

fn run_query(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[serde_json::Value],
) -> Result<ExecResult> {
    let mut stmt = conn.prepare(sql)?;
    bind_params(&mut stmt, params)?;
    let rows = read_prepared_rows(&mut stmt)?;
    Ok(ExecResult {
        rows: Some(rows),
        rows_affected: None,
        batch: None,
        leader_hint: None,
    })
}

fn read_prepared_rows(
    stmt: &mut rusqlite::Statement<'_>,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    let cols: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
    let mut rows_out = Vec::new();
    let mut rows = stmt.raw_query();
    while let Some(row) = rows.next()? {
        if rows_out.len() >= 10_000 {
            anyhow::bail!("D1 query returned more than 10,000 rows");
        }
        let mut obj = serde_json::Map::new();
        for (i, col) in cols.iter().enumerate() {
            let v: serde_json::Value = match row.get_ref(i)? {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(n) => n.into(),
                rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).to_string().into(),
                rusqlite::types::ValueRef::Blob(b) => {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(b).into()
                }
            };
            obj.insert(col.clone(), v);
        }
        rows_out.push(obj);
    }
    Ok(rows_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_classifies_ctes_and_mutating_pragmas() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert!(is_read(&conn, "WITH n(v) AS (VALUES (1)) SELECT v FROM n").unwrap());
        assert!(is_read(&conn, "PRAGMA user_version").unwrap());
        assert!(!is_read(&conn, "PRAGMA user_version = 7").unwrap());
        assert!(!is_read(&conn, "CREATE TABLE t (id INTEGER)").unwrap());
    }

    #[test]
    fn atomic_statement_sets_commit_together_or_roll_back_together() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);")
            .unwrap();
        {
            let transaction = connection.unchecked_transaction().unwrap();
            let results = run_statements(
                &transaction,
                &[
                    Statement {
                        sql: "INSERT INTO items (id, name) VALUES (?1, ?2)".into(),
                        params: vec![1.into(), "one".into()],
                    },
                    Statement {
                        sql: "SELECT name FROM items WHERE id = ?1".into(),
                        params: vec![1.into()],
                    },
                ],
            )
            .unwrap();
            assert_eq!(results[0].rows_affected, Some(1));
            assert_eq!(results[1].rows.as_ref().unwrap()[0]["name"], "one");
            transaction.commit().unwrap();
        }
        {
            let transaction = connection.unchecked_transaction().unwrap();
            assert!(run_statements(
                &transaction,
                &[
                    Statement {
                        sql: "INSERT INTO items (id, name) VALUES (2, 'two')".into(),
                        params: vec![],
                    },
                    Statement {
                        sql: "INSERT INTO items (id, name) VALUES (1, 'duplicate')".into(),
                        params: vec![],
                    },
                ],
            )
            .is_err());
        }
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "failed batch must roll back its earlier insert");
    }

    #[test]
    fn mutating_returning_statements_commit_and_return_rows() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE jobs (id INTEGER PRIMARY KEY, status TEXT NOT NULL);")
            .unwrap();
        let results = run_statements(
            &connection,
            &[Statement {
                sql: "INSERT INTO jobs(status) VALUES('queued') RETURNING id,status".into(),
                params: vec![],
            }],
        )
        .unwrap();
        assert_eq!(results[0].rows.as_ref().unwrap()[0]["status"], "queued");
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn portable_export_keeps_user_data_and_strips_raft_marker() {
        let directory = std::env::temp_dir().join(format!(
            "rf-d1-export-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source_path = directory.join("source.sqlite");
        let export_path = directory.join("export.sqlite");
        let source = rusqlite::Connection::open(&source_path).unwrap();
        source
            .execute_batch(
                "CREATE TABLE _rf_applied (id INTEGER PRIMARY KEY, seq INTEGER NOT NULL);
                 INSERT INTO _rf_applied VALUES (0, 9);
                 CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                 INSERT INTO users VALUES (1, '安杰');",
            )
            .unwrap();
        let bytes = portable_sqlite_backup(&source, &export_path).unwrap();
        assert!(bytes.starts_with(b"SQLite format 3\0"));
        let exported = rusqlite::Connection::open(&export_path).unwrap();
        let name: String = exported
            .query_row("SELECT name FROM users WHERE id = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(name, "安杰");
        let internal: i64 = exported
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = '_rf_applied'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(internal, 0);
        drop(exported);
        drop(source);
        let _ = std::fs::remove_dir_all(directory);
    }
}
