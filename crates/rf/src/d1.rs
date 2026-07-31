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
    pub sql: String,
    pub params: Vec<serde_json::Value>,
    /// Random tag so the proposer can recognize its own entry.
    pub tag: u64,
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
    /// Set when this node isn't the leader: api addr to retry against.
    pub leader_hint: Option<String>,
}

pub enum DriverCmd {
    Net(WireMsg),
    Exec { sql: String, params: Vec<serde_json::Value>, resp: oneshot::Sender<Result<ExecResult>> },
}

/// db name → driver inbox; peerapi routes into this.
pub type Registry = Arc<Mutex<HashMap<String, mpsc::Sender<DriverCmd>>>>;

pub fn kv_key(name: &str) -> String {
    format!("d1/{name}")
}

fn is_read(sql: &str) -> bool {
    let s = sql.trim_start().to_ascii_uppercase();
    s.starts_with("SELECT") || s.starts_with("PRAGMA") || s.starts_with("EXPLAIN")
}

/// Manager: watches the KV for databases whose group includes us and
/// spawns a driver per db.
pub fn spawn_manager(node: Arc<Node>, registry: Registry) {
    tokio::spawn(async move {
        loop {
            for key in node.kv_list(acme_ns(), "d1/", 10_000) {
                let name = key.trim_start_matches("d1/").to_string();
                let Some(raw) = node.kv_get(acme_ns(), &key) else { continue };
                let Ok(meta) = serde_json::from_slice::<DbMeta>(&raw) else { continue };
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
                match Driver::open(node.clone(), name.clone(), meta.group.clone()) {
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
    });
}

struct Driver {
    node: Arc<Node>,
    name: String,
    raft: Raft,
    sql: rusqlite::Connection,
    client: PeerClient,
    /// tag → responder for proposals in flight.
    pending: HashMap<u64, oneshot::Sender<Result<ExecResult>>>,
    /// seq → tag for entries we proposed.
    my_entries: HashMap<u64, u64>,
}

fn acme_ns() -> &'static str {
    crate::acme::NS
}

impl Driver {
    fn open(node: Arc<Node>, name: String, group: Vec<PublicId>) -> Result<Self> {
        let dir = node.cfg.data_dir.join("d1");
        std::fs::create_dir_all(&dir)?;
        let sql = rusqlite::Connection::open(dir.join(format!("{name}.sqlite")))?;
        sql.pragma_update(None, "journal_mode", "WAL")?;
        sql.execute_batch(
            "CREATE TABLE IF NOT EXISTS _rf_applied (id INTEGER PRIMARY KEY CHECK (id = 0), seq INTEGER NOT NULL);
             INSERT OR IGNORE INTO _rf_applied (id, seq) VALUES (0, 0);",
        )?;
        let applied_i: i64 =
            sql.query_row("SELECT seq FROM _rf_applied WHERE id = 0", [], |r| r.get(0))?;
        let applied = applied_i as u64;
        let (epoch, voted_for) = node.store.load_d1_meta(&name)?;
        let log = node.store.load_d1_log(&name)?;
        let raft = Raft::restore(node.id(), group, epoch, voted_for, log, applied);
        let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
        Ok(Self { node, name, raft, sql, client, pending: HashMap::new(), my_entries: HashMap::new() })
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
            let _ = resp.send(Ok(ExecResult { rows: None, rows_affected: None, leader_hint: hint }));
            return;
        }
        if is_read(&sql) {
            let _ = resp.send(run_query(&self.sql, &sql, &params));
            return;
        }
        let tag: u64 = rand::random();
        let cmd = Cmd { sql, params, tag };
        let bytes = serde_json::to_vec(&cmd).expect("cmd encode");
        match self.raft.propose(bytes) {
            Ok((seq, actions)) => {
                self.pending.insert(tag, resp);
                self.my_entries.insert(seq, tag);
                self.execute(actions).await;
            }
            Err(_) => {
                let hint = self.leader_api_addr();
                let _ = resp.send(Ok(ExecResult { rows: None, rows_affected: None, leader_hint: hint }));
            }
        }
    }

    fn leader_api_addr(&self) -> Option<String> {
        let hint = self.raft.leader_hint()?;
        if hint == self.node.id() {
            return None;
        }
        self.node.peers().get(&hint.to_string()).and_then(|p| p.api_addr).map(|a| a.to_string())
    }

    async fn execute(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::PersistMeta => {
                    if let Err(e) = self.node.store.put_d1_meta(
                        &self.name,
                        self.raft.epoch,
                        self.raft.voted_for,
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
                    let wire = WireMsg { from: self.node.id(), msg };
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
                            leader_hint: None,
                        }));
                    }
                    self.my_entries.clear();
                }
            }
        }
    }

    fn apply(&mut self, entry: Entry) {
        let result = (|| -> Result<u64> {
            let cmd: Cmd = serde_json::from_slice(&entry.cmd).context("cmd decode")?;
            let tx = self.sql.unchecked_transaction()?;
            let affected = {
                let mut stmt = tx.prepare(&cmd.sql)?;
                bind_params(&mut stmt, &cmd.params)?;
                stmt.raw_execute()? as u64
            };
            tx.execute("UPDATE _rf_applied SET seq = ?1 WHERE id = 0", [entry.seq as i64])?;
            tx.commit()?;
            Ok(affected)
        })();
        // Answer the proposer if this was ours.
        if let Some(tag) = self.my_entries.remove(&entry.seq) {
            if let Some(resp) = self.pending.remove(&tag) {
                let _ = resp.send(result.map(|rows_affected| ExecResult {
                    rows: None,
                    rows_affected: Some(rows_affected),
                    leader_hint: None,
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

fn run_query(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[serde_json::Value],
) -> Result<ExecResult> {
    let mut stmt = conn.prepare(sql)?;
    bind_params(&mut stmt, params)?;
    let cols: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
    let mut rows_out = Vec::new();
    let mut rows = stmt.raw_query();
    while let Some(row) = rows.next()? {
        let mut obj = serde_json::Map::new();
        for (i, col) in cols.iter().enumerate() {
            let v: serde_json::Value = match row.get_ref(i)? {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(n) => n.into(),
                rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
                rusqlite::types::ValueRef::Text(t) => {
                    String::from_utf8_lossy(t).to_string().into()
                }
                rusqlite::types::ValueRef::Blob(b) => {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(b).into()
                }
            };
            obj.insert(col.clone(), v);
        }
        rows_out.push(obj);
    }
    Ok(ExecResult { rows: Some(rows_out), rows_affected: None, leader_hint: None })
}
