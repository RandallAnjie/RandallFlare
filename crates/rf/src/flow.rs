//! Visual, durable DAG orchestration without a control plane.
//!
//! A Flow graph is an operator-signed platform resource. Each run freezes the
//! exact graph it started with and persists node results in a dedicated D1
//! micro-quorum. Any eligible node can lease and advance the run; after a
//! crash, another node reconstructs routing state from the committed steps.

use crate::analytics::DataPoint;
use crate::d1;
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use futures_util::future::BoxFuture;
use jsonata_core::evaluator::{
    Context as JsonataContext, Evaluator as JsonataEvaluator,
    EvaluatorOptions as JsonataEvaluatorOptions,
};
use jsonata_core::{parser as jsonata_parser, value::JValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub const FLOW_KIND: &str = "flow";
pub const MAX_GRAPH_BYTES: usize = 768 * 1024;
pub const MAX_RUN_INPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NODE_RESULT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NODES: usize = 500;
pub const MAX_EDGES: usize = 2_000;
pub const MAX_LOOP_ITEMS: usize = 1_000;
pub const MAX_JSONATA_EXPRESSION_BYTES: usize = 16 * 1024;
const MAX_JSONATA_SEQUENCE_ITEMS: usize = 10_000;
const JSONATA_TIMEOUT_MS: u64 = 200;
const JSONATA_MAX_STACK_DEPTH: usize = 128;
const LEASE_MS: u64 = 5 * 60 * 1_000;
const DRIVER_INTERVAL_MS: u64 = 250;
const MAX_CONCURRENT_RUNS: usize = 24;
const MAX_NODES_PER_ADVANCE: usize = 40;
const HTTP_TIMEOUT_SECONDS: u64 = 30;

fn default_retention_days() -> u16 {
    30
}

fn default_max_concurrent_runs() -> u16 {
    32
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowTrigger {
    #[default]
    Manual,
    Webhook,
    Cron,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowPosition {
    pub x: f64,
    pub y: f64,
}

impl Default for FlowPosition {
    fn default() -> Self {
        Self { x: 0.0, y: 0.0 }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowNodeData {
    #[serde(rename = "nodeType")]
    pub node_type: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, rename = "onError")]
    pub on_error: String,
    #[serde(flatten)]
    pub config: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowNode {
    pub id: String,
    #[serde(default, rename = "type")]
    pub render_type: String,
    #[serde(default)]
    pub position: FlowPosition,
    pub data: FlowNodeData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    #[serde(default, rename = "sourceHandle")]
    pub source_handle: Option<String>,
    #[serde(default, rename = "targetHandle")]
    pub target_handle: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowGraph {
    #[serde(default)]
    pub nodes: Vec<FlowNode>,
    #[serde(default)]
    pub edges: Vec<FlowEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowToken {
    pub id: String,
    pub label: String,
    pub sha256: String,
    pub last_four: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSpec {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub graph: FlowGraph,
    #[serde(default)]
    pub trigger: FlowTrigger,
    #[serde(default)]
    pub cron: Option<String>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub tokens: Vec<FlowToken>,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub suspend_reason: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: u16,
    #[serde(default = "default_max_concurrent_runs")]
    pub max_concurrent_runs: u16,
    /// Optional node-local environment variable containing an alert webhook.
    /// Its value is never copied into a signed resource or D1 ledger.
    #[serde(default)]
    pub alert_webhook_env: Option<String>,
}

impl Default for FlowSpec {
    fn default() -> Self {
        Self {
            description: String::new(),
            graph: FlowGraph::default(),
            trigger: FlowTrigger::Manual,
            cron: None,
            hostnames: vec![],
            tokens: vec![],
            suspended: false,
            suspend_reason: String::new(),
            retention_days: default_retention_days(),
            max_concurrent_runs: default_max_concurrent_runs(),
            alert_webhook_env: None,
        }
    }
}

impl FlowSpec {
    pub fn validate(&self) -> Result<()> {
        if self.description.len() > 2_000 || self.suspend_reason.len() > 2_000 {
            bail!("Flow 描述或暂停原因不得超过 2000 个字符");
        }
        if !(1..=365).contains(&self.retention_days) {
            bail!("Flow 执行记录保留期必须介于 1 和 365 天之间");
        }
        if self.max_concurrent_runs > 1_000 {
            bail!("Flow 最大并发运行数不得超过 1000；0 表示不额外限制");
        }
        match self.trigger {
            FlowTrigger::Cron => {
                let source = self.cron.as_deref().context("Cron Flow 必须填写表达式")?;
                rf_core::cron::CronExpr::parse(source)
                    .map_err(|error| anyhow::anyhow!("Flow Cron 表达式无效：{error}"))?;
            }
            _ if self.cron.is_some() => bail!("只有 Cron 触发的 Flow 可以保存 Cron 表达式"),
            _ => {}
        }
        if self.hostnames.len() > 64 {
            bail!("Flow 自定义域名不得超过 64 个");
        }
        for hostname in &self.hostnames {
            if !rf_core::manifest::valid_hostname(hostname) {
                bail!("Flow 自定义域名无效：{hostname}");
            }
        }
        if self.tokens.len() > 64 {
            bail!("一个 Flow 最多允许 64 个 Webhook 令牌");
        }
        let mut token_ids = BTreeSet::new();
        for token in &self.tokens {
            if token.id.len() != 16
                || !token.id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || token.sha256.len() != 64
                || !token.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || token.last_four.len() != 4
                || token.label.len() > 128
                || !token_ids.insert(&token.id)
            {
                bail!("Flow Webhook 令牌元数据无效");
            }
        }
        if self.trigger == FlowTrigger::Webhook && self.tokens.is_empty() {
            bail!("Webhook Flow 至少需要一个只保存哈希的接收令牌");
        }
        if let Some(name) = &self.alert_webhook_env {
            validate_secret_env(name)?;
        }
        validate_graph(&self.graph)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRun {
    pub id: String,
    pub run_key: Option<String>,
    pub trigger: String,
    pub status: String,
    pub input: Value,
    pub output: Option<Value>,
    pub error: Option<String>,
    pub graph_version: u64,
    pub retry_of: Option<String>,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRunStep {
    pub node_id: String,
    pub node_type: String,
    pub iteration: u32,
    pub seq: u64,
    pub status: String,
    pub route_status: String,
    pub taken: Option<String>,
    pub input: Option<Value>,
    pub output: Option<Value>,
    pub error: Option<String>,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStats {
    pub queued: u64,
    pub running: u64,
    pub complete: u64,
    pub failed: u64,
    pub cancelled: u64,
}

#[derive(Debug, Clone)]
struct ClaimedRun {
    run: FlowRun,
    graph: FlowGraph,
    lease: String,
}

#[derive(Debug, Clone)]
struct StepState {
    route_status: String,
    output: Value,
    taken: Option<String>,
}

#[derive(Debug, Clone)]
struct ExecContext {
    input: Value,
    trigger: Value,
    nodes: BTreeMap<String, Value>,
    item: Option<Value>,
    depth: u8,
}

#[derive(Debug)]
struct ExecResult {
    status: String,
    route_status: String,
    output: Value,
    taken: Option<String>,
    error: Option<String>,
}

pub fn flow_record(node: &Node, name: &str) -> Option<(ResourceView, FlowSpec)> {
    let view = resource::head(node, FLOW_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = flow_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn flow_records(node: &Node) -> Vec<(ResourceView, FlowSpec)> {
    resource::heads(node, Some(FLOW_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| flow_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn flow_spec(record: &ResourceRecord) -> Result<FlowSpec> {
    if record.kind != FLOW_KIND {
        bail!("平台资源不是 Flow");
    }
    let spec: FlowSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn prepare_flow_after(
    name: &str,
    spec: FlowSpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.validate()?;
    resource::prepare_after(FLOW_KIND, name, serde_json::to_value(spec)?, deleted, head)
}

pub fn database_name(flow: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("flow/{flow}").as_bytes()));
    format!("flow-{}", &digest[..32])
}

pub fn mint_token(label: impl Into<String>) -> Result<(FlowToken, String)> {
    let label = label.into();
    if label.len() > 128 {
        bail!("Flow Webhook 令牌标签不得超过 128 个字符");
    }
    let plaintext = format!(
        "rff_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    );
    let digest = hex::encode(Sha256::digest(plaintext.as_bytes()));
    let id = hex::encode(rand::random::<[u8; 8]>());
    let last_four = plaintext
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    Ok((
        FlowToken {
            id,
            label,
            sha256: digest,
            last_four,
            created_at_ms: now_ms(),
        },
        plaintext,
    ))
}

pub fn token_matches(spec: &FlowSpec, plaintext: &str) -> bool {
    let digest = Sha256::digest(plaintext.as_bytes());
    spec.tokens.iter().any(|token| {
        hex::decode(&token.sha256)
            .ok()
            .is_some_and(|expected| constant_time_eq(&digest, &expected))
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

pub async fn create_run(
    node: &Node,
    flow: &str,
    run_key: Option<&str>,
    trigger: &str,
    input: Value,
) -> Result<FlowRun> {
    let (view, spec) = flow_record(node, flow).context("Flow 不存在")?;
    if spec.suspended {
        bail!("Flow 已暂停：{}", spec.suspend_reason);
    }
    if !matches!(trigger, "manual" | "webhook" | "cron" | "subflow" | "retry") {
        bail!("Flow 触发来源无效");
    }
    validate_run_key(run_key)?;
    validate_json_size(&input, MAX_RUN_INPUT_BYTES, "Flow 输入")?;
    ensure_schema(node, flow).await?;
    if let Some(key) = run_key {
        if let Some(existing) = run_by_key(node, flow, key).await? {
            return Ok(existing);
        }
    }
    let id = new_id("flr");
    let now = now_ms();
    let graph_json = serde_json::to_string(&spec.graph)?;
    let inserted = exec(
        node,
        flow,
        r#"INSERT OR IGNORE INTO flow_runs
           (id,run_key,trigger,status,input_json,graph_json,graph_version,
            due_at_ms,created_at_ms,updated_at_ms)
           SELECT ?1,?2,?3,'queued',?4,?5,?6,?7,?7,?7
           WHERE ?8=0 OR (
             SELECT COUNT(*) FROM flow_runs WHERE status IN ('queued','running')
           )<?8"#,
        json!([
            id,
            run_key,
            trigger,
            serde_json::to_string(&input)?,
            graph_json,
            view.resource.version,
            now,
            spec.max_concurrent_runs
        ]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    let run = if inserted == 1 {
        run(node, flow, &id)
            .await?
            .context("Flow 运行创建后不可见")?
    } else if let Some(key) = run_key {
        run_by_key(node, flow, key)
            .await?
            .context("Flow 幂等运行创建冲突，或并发上限已达到")?
    } else {
        bail!("Flow 已达到最大并发运行数");
    };
    if inserted == 1 {
        append_event(
            node,
            flow,
            &run.id,
            "created",
            json!({ "trigger": trigger }),
        )
        .await?;
    }
    Ok(run)
}

pub async fn run(node: &Node, flow: &str, id: &str) -> Result<Option<FlowRun>> {
    ensure_schema(node, flow).await?;
    rows(
        exec(
            node,
            flow,
            &format!("SELECT {RUN_FIELDS} FROM flow_runs WHERE id=?1"),
            json!([id]),
        )
        .await?,
    )
    .first()
    .map(row_to_run)
    .transpose()
}

/// Wait for a durable run to become terminal without taking ownership of its
/// lease. The normal decentralized driver keeps advancing the run, so this is
/// safe to use for request/response webhooks as well as local API clients.
pub async fn wait_run(node: &Node, flow: &str, id: &str, timeout: Duration) -> Result<FlowRun> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let current = run(node, flow, id).await?.context("Flow 运行不存在")?;
        if matches!(current.status.as_str(), "complete" | "failed" | "cancelled")
            || tokio::time::Instant::now() >= deadline
        {
            return Ok(current);
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

async fn run_by_key(node: &Node, flow: &str, key: &str) -> Result<Option<FlowRun>> {
    rows(
        exec(
            node,
            flow,
            &format!("SELECT {RUN_FIELDS} FROM flow_runs WHERE run_key=?1"),
            json!([key]),
        )
        .await?,
    )
    .first()
    .map(row_to_run)
    .transpose()
}

pub async fn runs(
    node: &Node,
    flow: &str,
    status: Option<&str>,
    limit: usize,
) -> Result<Vec<FlowRun>> {
    ensure_schema(node, flow).await?;
    let (filter, params) = if let Some(status) = status {
        validate_run_status(status)?;
        (" WHERE status=?1", json!([status]))
    } else {
        ("", json!([]))
    };
    rows(
        exec(
            node,
            flow,
            &format!(
                "SELECT {RUN_FIELDS} FROM flow_runs{filter} ORDER BY created_at_ms DESC LIMIT {}",
                limit.clamp(1, 1_000)
            ),
            params,
        )
        .await?,
    )
    .iter()
    .map(row_to_run)
    .collect()
}

pub async fn run_steps(node: &Node, flow: &str, run_id: &str) -> Result<Vec<FlowRunStep>> {
    ensure_schema(node, flow).await?;
    rows(
        exec(
            node,
            flow,
            r#"SELECT node_id,node_type,iteration,seq,status,route_status,taken,
                      input_json,output_json,error,started_at_ms,finished_at_ms
               FROM flow_steps WHERE run_id=?1 ORDER BY seq,iteration"#,
            json!([run_id]),
        )
        .await?,
    )
    .iter()
    .map(row_to_step)
    .collect()
}

pub async fn run_events(node: &Node, flow: &str, run_id: &str, limit: usize) -> Result<Vec<Value>> {
    ensure_schema(node, flow).await?;
    let mut events = rows(
        exec(
            node,
            flow,
            &format!(
                "SELECT seq,kind,detail_json,created_at_ms FROM flow_events WHERE run_id=?1 ORDER BY seq DESC LIMIT {}",
                limit.clamp(1, 1_000)
            ),
            json!([run_id]),
        )
        .await?,
    );
    events.reverse();
    for event in &mut events {
        event["detail"] = event
            .get("detail_json")
            .and_then(Value::as_str)
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_else(|| json!({}));
        if let Some(object) = event.as_object_mut() {
            object.remove("detail_json");
        }
    }
    Ok(events)
}

pub async fn stats(node: &Node, flow: &str) -> Result<FlowStats> {
    ensure_schema(node, flow).await?;
    let row = rows(
        exec(
            node,
            flow,
            r#"SELECT
               SUM(CASE WHEN status='queued' THEN 1 ELSE 0 END) queued,
               SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) running,
               SUM(CASE WHEN status='complete' THEN 1 ELSE 0 END) complete,
               SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) failed,
               SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) cancelled
               FROM flow_runs"#,
            json!([]),
        )
        .await?,
    )
    .into_iter()
    .next()
    .unwrap_or_else(|| json!({}));
    Ok(FlowStats {
        queued: u64_field(&row, "queued"),
        running: u64_field(&row, "running"),
        complete: u64_field(&row, "complete"),
        failed: u64_field(&row, "failed"),
        cancelled: u64_field(&row, "cancelled"),
    })
}

pub async fn cancel(node: &Node, flow: &str, id: &str) -> Result<bool> {
    ensure_schema(node, flow).await?;
    let now = now_ms();
    let changed = exec(
        node,
        flow,
        r#"UPDATE flow_runs SET status='cancelled',lease_token=NULL,lease_until_ms=NULL,
           finished_at_ms=?2,updated_at_ms=?2
           WHERE id=?1 AND status IN ('queued','running')"#,
        json!([id, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0)
        == 1;
    if changed {
        append_event(node, flow, id, "cancelled", json!({})).await?;
    }
    Ok(changed)
}

pub async fn retry(node: &Node, flow: &str, id: &str) -> Result<FlowRun> {
    let previous = run(node, flow, id).await?.context("Flow 运行不存在")?;
    if !matches!(
        previous.status.as_str(),
        "failed" | "cancelled" | "complete"
    ) {
        bail!("只有终态 Flow 运行可以重试");
    }
    let key = format!("retry:{}:{}", previous.id, new_id("attempt"));
    let retried = create_run(node, flow, Some(&key), "retry", previous.input.clone()).await?;
    exec(
        node,
        flow,
        "UPDATE flow_runs SET retry_of=?2 WHERE id=?1",
        json!([retried.id, previous.id]),
    )
    .await?;
    run(node, flow, &retried.id)
        .await?
        .context("Flow 重试运行不可见")
}

async fn ensure_schema(node: &Node, flow: &str) -> Result<()> {
    let database = database_name(flow);
    d1::ensure_database(node, &database)?;
    if node.flow_schema_ready(&database) {
        return Ok(());
    }
    for sql in [
        r#"CREATE TABLE IF NOT EXISTS flow_runs (
             id TEXT PRIMARY KEY,
             run_key TEXT UNIQUE,
             trigger TEXT NOT NULL,
             status TEXT NOT NULL,
             input_json TEXT NOT NULL,
             output_json TEXT,
             error TEXT,
             graph_json TEXT NOT NULL,
             graph_version INTEGER NOT NULL,
             retry_of TEXT,
             due_at_ms INTEGER NOT NULL,
             lease_token TEXT,
             lease_until_ms INTEGER,
             started_at_ms INTEGER,
             finished_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL
           )"#,
        "CREATE INDEX IF NOT EXISTS flow_runs_due ON flow_runs(status,due_at_ms,created_at_ms)",
        "CREATE INDEX IF NOT EXISTS flow_runs_created ON flow_runs(created_at_ms DESC)",
        r#"CREATE TABLE IF NOT EXISTS flow_steps (
             run_id TEXT NOT NULL,
             node_id TEXT NOT NULL,
             node_type TEXT NOT NULL,
             iteration INTEGER NOT NULL DEFAULT 0,
             seq INTEGER NOT NULL,
             status TEXT NOT NULL,
             route_status TEXT NOT NULL,
             taken TEXT,
             input_json TEXT,
             output_json TEXT,
             error TEXT,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER NOT NULL,
             PRIMARY KEY(run_id,node_id,iteration),
             UNIQUE(run_id,seq),
             FOREIGN KEY(run_id) REFERENCES flow_runs(id) ON DELETE CASCADE
           )"#,
        "CREATE INDEX IF NOT EXISTS flow_steps_seq ON flow_steps(run_id,seq)",
        r#"CREATE TABLE IF NOT EXISTS flow_events (
             run_id TEXT NOT NULL,
             seq INTEGER NOT NULL,
             kind TEXT NOT NULL,
             detail_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             PRIMARY KEY(run_id,seq),
             FOREIGN KEY(run_id) REFERENCES flow_runs(id) ON DELETE CASCADE
           )"#,
    ] {
        exec_database(node, &database, sql, json!([])).await?;
    }
    node.mark_flow_schema_ready(database);
    Ok(())
}

async fn append_event(
    node: &Node,
    flow: &str,
    run_id: &str,
    kind: &str,
    detail: Value,
) -> Result<()> {
    let affected = exec(
        node,
        flow,
        r#"INSERT INTO flow_events(run_id,seq,kind,detail_json,created_at_ms)
           SELECT ?1,COALESCE(MAX(seq),0)+1,?2,?3,?4
           FROM flow_events WHERE run_id=?1"#,
        json!([run_id, kind, serde_json::to_string(&detail)?, now_ms()]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if affected != 1 {
        bail!("Flow 审计事件未能持久化");
    }
    Ok(())
}

/// Start the decentralized Flow scheduler. Every node evaluates signed Flow
/// definitions, while the D1 lease on each run fences execution cluster-wide.
pub fn spawn_driver(node: Arc<Node>) {
    tokio::spawn(async move {
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RUNS));
        let mut last_minute = 0u64;
        let mut last_gc = 0u64;
        loop {
            let now = now_ms();
            let minute = now / 60_000;
            let records = flow_records(&node);
            for (view, spec) in &records {
                let flow = view.resource.name.clone();
                if minute != last_minute && spec.trigger == FlowTrigger::Cron && !spec.suspended {
                    if let Some(source) = spec.cron.as_deref() {
                        if rf_core::cron::CronExpr::parse(source)
                            .is_ok_and(|expr| expr.matches(minute * 60))
                        {
                            let key = format!("cron:{minute}");
                            if let Err(error) = create_run(
                                &node,
                                &flow,
                                Some(&key),
                                "cron",
                                json!({ "scheduledAtMs": minute * 60_000, "cron": source }),
                            )
                            .await
                            {
                                tracing::warn!(flow, "Flow Cron 触发失败：{error}");
                            }
                        }
                    }
                }
                if let Err(error) = recover_expired(&node, &flow).await {
                    tracing::warn!(flow, "Flow 过期租约恢复失败：{error}");
                    continue;
                }
                if spec.suspended {
                    continue;
                }
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    break;
                };
                match claim_run(&node, &flow).await {
                    Ok(Some(claimed)) => {
                        let node = node.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(error) = advance_run(&node, &flow, claimed).await {
                                tracing::warn!(flow, "Flow 运行推进失败：{error}");
                            }
                        });
                    }
                    Ok(None) => drop(permit),
                    Err(error) => {
                        drop(permit);
                        tracing::warn!(flow, "Flow 运行领取失败：{error}");
                    }
                }
            }
            if minute != last_minute {
                last_minute = minute;
            }
            if now.saturating_sub(last_gc) >= 60 * 60 * 1_000 {
                last_gc = now;
                for (view, spec) in &records {
                    if let Err(error) =
                        gc_runs(&node, &view.resource.name, spec.retention_days).await
                    {
                        tracing::warn!(flow = view.resource.name, "Flow 历史清理失败：{error}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(DRIVER_INTERVAL_MS)).await;
        }
    });
}

async fn recover_expired(node: &Node, flow: &str) -> Result<()> {
    ensure_schema(node, flow).await?;
    let now = now_ms();
    exec(
        node,
        flow,
        r#"UPDATE flow_runs SET status='queued',lease_token=NULL,lease_until_ms=NULL,
           due_at_ms=?1,updated_at_ms=?1
           WHERE status='running' AND lease_until_ms IS NOT NULL AND lease_until_ms<?1"#,
        json!([now]),
    )
    .await?;
    Ok(())
}

async fn claim_run(node: &Node, flow: &str) -> Result<Option<ClaimedRun>> {
    ensure_schema(node, flow).await?;
    let now = now_ms();
    let candidate = rows(
        exec(
            node,
            flow,
            "SELECT id FROM flow_runs WHERE status='queued' AND due_at_ms<=?1 ORDER BY due_at_ms,created_at_ms LIMIT 1",
            json!([now]),
        )
        .await?,
    )
    .into_iter()
    .next();
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let id = string_field(&candidate, "id")?.to_string();
    let lease = new_id("lease");
    let changed = exec(
        node,
        flow,
        r#"UPDATE flow_runs SET status='running',lease_token=?2,lease_until_ms=?3,
           started_at_ms=COALESCE(started_at_ms,?1),updated_at_ms=?1
           WHERE id=?4 AND status='queued' AND due_at_ms<=?1"#,
        json!([now, lease, now.saturating_add(LEASE_MS), id]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if changed != 1 {
        return Ok(None);
    }
    let row = rows(
        exec(
            node,
            flow,
            &format!(
                "SELECT {RUN_FIELDS},graph_json FROM flow_runs WHERE id=?1 AND lease_token=?2"
            ),
            json!([id, lease]),
        )
        .await?,
    )
    .into_iter()
    .next()
    .context("Flow 租约成功后运行不可见")?;
    let graph: FlowGraph = serde_json::from_str(string_field(&row, "graph_json")?)?;
    validate_graph(&graph)?;
    Ok(Some(ClaimedRun {
        run: row_to_run(&row)?,
        graph,
        lease,
    }))
}

async fn advance_run(node: &Node, flow: &str, claimed: ClaimedRun) -> Result<()> {
    let mut states = HashMap::<String, StepState>::new();
    for step in run_steps(node, flow, &claimed.run.id).await? {
        if step.iteration == 0 {
            states.insert(
                step.node_id,
                StepState {
                    route_status: step.route_status,
                    output: step.output.unwrap_or(Value::Null),
                    taken: step.taken,
                },
            );
        }
    }
    let mut completed_this_lease = 0usize;
    loop {
        if completed_this_lease >= MAX_NODES_PER_ADVANCE {
            requeue_claim(node, flow, &claimed.run.id, &claimed.lease).await?;
            return Ok(());
        }
        let mut progressed = false;
        for graph_node in &claimed.graph.nodes {
            if states.contains_key(&graph_node.id) {
                continue;
            }
            let incoming: Vec<&FlowEdge> = claimed
                .graph
                .edges
                .iter()
                .filter(|edge| edge.target == graph_node.id)
                .collect();
            if incoming
                .iter()
                .any(|edge| !states.contains_key(&edge.source))
            {
                continue;
            }
            let live: Vec<&FlowEdge> = incoming
                .iter()
                .copied()
                .filter(|edge| edge_is_live(edge, &states))
                .collect();
            if !incoming.is_empty() && live.is_empty() {
                let result = ExecResult {
                    status: "skipped".into(),
                    route_status: "skipped".into(),
                    output: Value::Null,
                    taken: None,
                    error: None,
                };
                persist_step(node, flow, &claimed, graph_node, Value::Null, &result).await?;
                states.insert(
                    graph_node.id.clone(),
                    StepState {
                        route_status: "skipped".into(),
                        output: Value::Null,
                        taken: None,
                    },
                );
                progressed = true;
                completed_this_lease += 1;
                break;
            }
            let step_input = collect_input(&claimed.run.input, &live, &states);
            let context = ExecContext {
                input: step_input.clone(),
                // Match the visual Flow contract: `trigger` is always the
                // original webhook/manual/cron payload.
                trigger: claimed.run.input.clone(),
                nodes: node_context(&claimed.graph, &states),
                item: None,
                depth: 0,
            };
            let result = if graph_node.data.node_type == "loop" {
                execute_loop(node, flow, &claimed, graph_node, &context, &states).await
            } else {
                execute_with_retries(node, flow, graph_node, &context).await
            };
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    let message = safe_error(&error);
                    match graph_node.data.on_error.as_str() {
                        "continue" => ExecResult {
                            status: "failed".into(),
                            route_status: "continued".into(),
                            output: json!({ "error": message }),
                            taken: None,
                            error: Some(message),
                        },
                        "branch" => ExecResult {
                            status: "failed".into(),
                            route_status: "error".into(),
                            output: json!({ "error": message }),
                            taken: Some("error".into()),
                            error: Some(message),
                        },
                        _ => {
                            let result = ExecResult {
                                status: "failed".into(),
                                route_status: "failed".into(),
                                output: Value::Null,
                                taken: None,
                                error: Some(message.clone()),
                            };
                            persist_step(node, flow, &claimed, graph_node, step_input, &result)
                                .await?;
                            fail_claim(node, flow, &claimed, &message).await?;
                            send_failure_alert(node, flow, &claimed.run, graph_node, &message)
                                .await;
                            return Ok(());
                        }
                    }
                }
            };
            if let Err(error) =
                validate_json_size(&result.output, MAX_NODE_RESULT_BYTES, "Flow 节点输出")
            {
                let message = safe_error(&error);
                let failed = ExecResult {
                    status: "failed".into(),
                    route_status: "failed".into(),
                    output: Value::Null,
                    taken: None,
                    error: Some(message.clone()),
                };
                persist_step(node, flow, &claimed, graph_node, step_input, &failed).await?;
                fail_claim(node, flow, &claimed, &message).await?;
                return Ok(());
            }
            persist_step(node, flow, &claimed, graph_node, step_input, &result).await?;
            states.insert(
                graph_node.id.clone(),
                StepState {
                    route_status: result.route_status.clone(),
                    output: result.output,
                    taken: result.taken,
                },
            );
            progressed = true;
            completed_this_lease += 1;
            break;
        }
        if progressed {
            continue;
        }
        if states.len() != claimed.graph.nodes.len() {
            let message = "Flow 图无法继续推进；请检查节点依赖和路由条件";
            fail_claim(node, flow, &claimed, message).await?;
            return Ok(());
        }
        let output = final_output(&claimed.graph, &states);
        complete_claim(node, flow, &claimed, output).await?;
        return Ok(());
    }
}

impl ExecResult {
    fn success(output: Value) -> Self {
        Self {
            status: "complete".into(),
            route_status: "success".into(),
            output,
            taken: None,
            error: None,
        }
    }
}

fn edge_is_live(edge: &FlowEdge, states: &HashMap<String, StepState>) -> bool {
    let Some(source) = states.get(&edge.source) else {
        return false;
    };
    if matches!(source.route_status.as_str(), "failed" | "skipped") {
        return false;
    }
    match &source.taken {
        Some(taken) => edge.source_handle.as_deref().unwrap_or("default") == taken,
        None => edge
            .source_handle
            .as_deref()
            .is_none_or(|handle| handle == "default"),
    }
}

fn collect_input(root: &Value, live: &[&FlowEdge], states: &HashMap<String, StepState>) -> Value {
    match live {
        [] => root.clone(),
        [edge] => states
            .get(&edge.source)
            .map(|state| state.output.clone())
            .unwrap_or(Value::Null),
        many => Value::Object(
            many.iter()
                .filter_map(|edge| {
                    states
                        .get(&edge.source)
                        .map(|state| (edge.source.clone(), state.output.clone()))
                })
                .collect(),
        ),
    }
}

fn final_output(graph: &FlowGraph, states: &HashMap<String, StepState>) -> Value {
    let sinks: Vec<&FlowNode> = graph
        .nodes
        .iter()
        .filter(|node| !graph.edges.iter().any(|edge| edge.source == node.id))
        .filter(|node| {
            states
                .get(&node.id)
                .is_some_and(|state| state.route_status != "skipped")
        })
        .collect();
    if let [sink] = sinks.as_slice() {
        return states
            .get(&sink.id)
            .map(|state| state.output.clone())
            .unwrap_or(Value::Null);
    }
    Value::Object(
        sinks
            .into_iter()
            .filter_map(|sink| {
                states.get(&sink.id).map(|state| {
                    let key = if sink.data.label.is_empty() {
                        sink.id.clone()
                    } else {
                        sink.data.label.clone()
                    };
                    (key, state.output.clone())
                })
            })
            .collect(),
    )
}

fn node_context(graph: &FlowGraph, states: &HashMap<String, StepState>) -> BTreeMap<String, Value> {
    let mut context = BTreeMap::new();
    for graph_node in &graph.nodes {
        if let Some(state) = states.get(&graph_node.id) {
            context.insert(graph_node.id.clone(), state.output.clone());
            if !graph_node.data.label.is_empty() {
                context.insert(graph_node.data.label.clone(), state.output.clone());
            }
        }
    }
    context
}

async fn persist_step(
    node: &Node,
    flow: &str,
    claimed: &ClaimedRun,
    graph_node: &FlowNode,
    input: Value,
    result: &ExecResult,
) -> Result<()> {
    let now = now_ms();
    let changed = exec(
        node,
        flow,
        r#"INSERT OR IGNORE INTO flow_steps
           (run_id,node_id,node_type,iteration,seq,status,route_status,taken,
            input_json,output_json,error,started_at_ms,finished_at_ms)
           SELECT ?1,?2,?3,0,COALESCE((SELECT MAX(seq)+1 FROM flow_steps WHERE run_id=?1),1),
                  ?4,?5,?6,?7,?8,?9,?10,?10
           WHERE EXISTS (SELECT 1 FROM flow_runs WHERE id=?1 AND status='running' AND lease_token=?11)"#,
        json!([
            claimed.run.id,
            graph_node.id,
            graph_node.data.node_type,
            result.status,
            result.route_status,
            result.taken,
            serde_json::to_string(&input)?,
            serde_json::to_string(&result.output)?,
            result.error,
            now,
            claimed.lease
        ]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if changed != 1 {
        bail!("Flow 步骤提交失败：租约可能已转移");
    }
    exec(
        node,
        flow,
        "UPDATE flow_runs SET lease_until_ms=?3,updated_at_ms=?2 WHERE id=?1 AND lease_token=?4",
        json!([
            claimed.run.id,
            now,
            now.saturating_add(LEASE_MS),
            claimed.lease
        ]),
    )
    .await?;
    Ok(())
}

async fn requeue_claim(node: &Node, flow: &str, id: &str, lease: &str) -> Result<()> {
    let now = now_ms();
    exec(
        node,
        flow,
        r#"UPDATE flow_runs SET status='queued',due_at_ms=?3,lease_token=NULL,
           lease_until_ms=NULL,updated_at_ms=?3 WHERE id=?1 AND lease_token=?2"#,
        json!([id, lease, now]),
    )
    .await?;
    Ok(())
}

async fn fail_claim(node: &Node, flow: &str, claimed: &ClaimedRun, error: &str) -> Result<()> {
    let now = now_ms();
    let changed = exec(
        node,
        flow,
        r#"UPDATE flow_runs SET status='failed',error=?3,finished_at_ms=?4,
           updated_at_ms=?4,lease_token=NULL,lease_until_ms=NULL
           WHERE id=?1 AND lease_token=?2"#,
        json!([claimed.run.id, claimed.lease, error, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if changed == 1 {
        append_event(
            node,
            flow,
            &claimed.run.id,
            "failed",
            json!({ "error": error }),
        )
        .await?;
    }
    Ok(())
}

async fn complete_claim(
    node: &Node,
    flow: &str,
    claimed: &ClaimedRun,
    output: Value,
) -> Result<()> {
    validate_json_size(&output, MAX_NODE_RESULT_BYTES, "Flow 最终输出")?;
    let now = now_ms();
    let changed = exec(
        node,
        flow,
        r#"UPDATE flow_runs SET status='complete',output_json=?3,error=NULL,
           finished_at_ms=?4,updated_at_ms=?4,lease_token=NULL,lease_until_ms=NULL
           WHERE id=?1 AND lease_token=?2"#,
        json!([
            claimed.run.id,
            claimed.lease,
            serde_json::to_string(&output)?,
            now
        ]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if changed == 1 {
        append_event(node, flow, &claimed.run.id, "completed", json!({})).await?;
    }
    Ok(())
}

async fn gc_runs(node: &Node, flow: &str, retention_days: u16) -> Result<()> {
    ensure_schema(node, flow).await?;
    let threshold = now_ms().saturating_sub(retention_days as u64 * 86_400_000);
    exec(
        node,
        flow,
        "DELETE FROM flow_runs WHERE status IN ('complete','failed','cancelled') AND finished_at_ms<?1",
        json!([threshold]),
    )
    .await?;
    Ok(())
}

async fn execute_loop(
    node: &Node,
    flow: &str,
    claimed: &ClaimedRun,
    loop_node: &FlowNode,
    context: &ExecContext,
    outer_states: &HashMap<String, StepState>,
) -> Result<ExecResult> {
    let (body_ids, entry_ids) = loop_body(&loop_node.id, &claimed.graph);
    let body_nodes: Vec<&FlowNode> = claimed
        .graph
        .nodes
        .iter()
        .filter(|node| body_ids.contains(&node.id))
        .collect();
    let body_edges: Vec<&FlowEdge> = claimed
        .graph
        .edges
        .iter()
        .filter(|edge| body_ids.contains(&edge.source) && body_ids.contains(&edge.target))
        .collect();
    let max = loop_node
        .data
        .config
        .get("maxIterations")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, MAX_LOOP_ITEMS as u64) as usize;
    let items = if loop_node.data.config.get("mode").and_then(Value::as_str) == Some("count") {
        let count = loop_node
            .data
            .config
            .get("count")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .min(max as u64);
        (0..count).map(|index| json!(index)).collect::<Vec<_>>()
    } else {
        let value = if let Some(expression) = loop_node
            .data
            .config
            .get("items")
            .or_else(|| loop_node.data.config.get("itemsPath"))
            .and_then(Value::as_str)
        {
            eval_expression(expression, context)?
        } else {
            context.input.clone()
        };
        match value {
            Value::Array(mut values) => {
                values.truncate(max);
                values
            }
            Value::Null => vec![],
            value => vec![value],
        }
    };
    let persisted = run_steps(node, flow, &claimed.run.id).await?;
    let mut results = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        let iteration = index as u32 + 1;
        let mut states = persisted
            .iter()
            .filter(|step| step.iteration == iteration && body_ids.contains(&step.node_id))
            .map(|step| {
                (
                    step.node_id.clone(),
                    StepState {
                        route_status: step.route_status.clone(),
                        output: step.output.clone().unwrap_or(Value::Null),
                        taken: step.taken.clone(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        loop {
            let mut progressed = false;
            for body_node in &body_nodes {
                if states.contains_key(&body_node.id) {
                    continue;
                }
                let incoming: Vec<&FlowEdge> = body_edges
                    .iter()
                    .copied()
                    .filter(|edge| edge.target == body_node.id)
                    .collect();
                if incoming
                    .iter()
                    .any(|edge| !states.contains_key(&edge.source))
                {
                    continue;
                }
                let live: Vec<&FlowEdge> = incoming
                    .iter()
                    .copied()
                    .filter(|edge| edge_is_live(edge, &states))
                    .collect();
                if !incoming.is_empty() && live.is_empty() {
                    let skipped = ExecResult {
                        status: "skipped".into(),
                        route_status: "skipped".into(),
                        output: Value::Null,
                        taken: None,
                        error: None,
                    };
                    persist_iteration_step(
                        node,
                        flow,
                        claimed,
                        body_node,
                        iteration,
                        Value::Null,
                        &skipped,
                    )
                    .await?;
                    states.insert(
                        body_node.id.clone(),
                        StepState {
                            route_status: "skipped".into(),
                            output: Value::Null,
                            taken: None,
                        },
                    );
                    progressed = true;
                    break;
                }
                let input = if entry_ids.contains(&body_node.id) || incoming.is_empty() {
                    item.clone()
                } else {
                    collect_input(&item, &live, &states)
                };
                let mut nodes_context = node_context(&claimed.graph, outer_states);
                for node in &body_nodes {
                    if let Some(state) = states.get(&node.id) {
                        nodes_context.insert(node.id.clone(), state.output.clone());
                        if !node.data.label.is_empty() {
                            nodes_context.insert(node.data.label.clone(), state.output.clone());
                        }
                    }
                }
                let body_context = ExecContext {
                    input: input.clone(),
                    trigger: context.trigger.clone(),
                    nodes: nodes_context,
                    item: Some(item.clone()),
                    depth: context.depth,
                };
                let executed = if body_node.data.node_type == "loop" {
                    Err(anyhow::anyhow!("Flow 暂不允许嵌套 loop 节点"))
                } else {
                    execute_with_retries(node, flow, body_node, &body_context).await
                };
                let result = match executed {
                    Ok(result) => result,
                    Err(error) => {
                        let message = safe_error(&error);
                        match body_node.data.on_error.as_str() {
                            "continue" => ExecResult {
                                status: "failed".into(),
                                route_status: "continued".into(),
                                output: json!({ "error": message }),
                                taken: None,
                                error: Some(message),
                            },
                            "branch" => ExecResult {
                                status: "failed".into(),
                                route_status: "error".into(),
                                output: json!({ "error": message }),
                                taken: Some("error".into()),
                                error: Some(message),
                            },
                            _ => {
                                let failed = ExecResult {
                                    status: "failed".into(),
                                    route_status: "failed".into(),
                                    output: Value::Null,
                                    taken: None,
                                    error: Some(message.clone()),
                                };
                                persist_iteration_step(
                                    node, flow, claimed, body_node, iteration, input, &failed,
                                )
                                .await?;
                                bail!("Flow loop 第 {iteration} 次迭代失败：{message}");
                            }
                        }
                    }
                };
                validate_json_size(&result.output, MAX_NODE_RESULT_BYTES, "Flow loop 节点输出")?;
                persist_iteration_step(node, flow, claimed, body_node, iteration, input, &result)
                    .await?;
                states.insert(
                    body_node.id.clone(),
                    StepState {
                        route_status: result.route_status,
                        output: result.output,
                        taken: result.taken,
                    },
                );
                progressed = true;
                break;
            }
            if !progressed {
                break;
            }
        }
        if states.len() != body_nodes.len() {
            bail!("Flow loop 第 {iteration} 次迭代的子图无法继续推进");
        }
        if body_nodes.is_empty() {
            results.push(item);
        } else {
            let body_graph = FlowGraph {
                nodes: body_nodes.iter().map(|node| (*node).clone()).collect(),
                edges: body_edges.iter().map(|edge| (*edge).clone()).collect(),
            };
            results.push(final_output(&body_graph, &states));
        }
    }
    Ok(ExecResult {
        status: "complete".into(),
        route_status: "success".into(),
        output: Value::Array(results),
        taken: Some("done".into()),
        error: None,
    })
}

fn loop_body(loop_id: &str, graph: &FlowGraph) -> (HashSet<String>, HashSet<String>) {
    let each = graph
        .edges
        .iter()
        .filter(|edge| edge.source == loop_id && edge.source_handle.as_deref() == Some("each"))
        .map(|edge| edge.target.clone())
        .collect::<HashSet<_>>();
    let done = graph
        .edges
        .iter()
        .filter(|edge| edge.source == loop_id && edge.source_handle.as_deref() == Some("done"))
        .map(|edge| edge.target.clone())
        .collect::<HashSet<_>>();
    let mut stop = done.clone();
    let mut queue = done.iter().cloned().collect::<VecDeque<_>>();
    while let Some(source) = queue.pop_front() {
        for edge in graph.edges.iter().filter(|edge| edge.source == source) {
            if edge.target != loop_id && stop.insert(edge.target.clone()) {
                queue.push_back(edge.target.clone());
            }
        }
    }
    stop.insert(loop_id.to_string());
    let mut body = HashSet::new();
    let mut queue = each.iter().cloned().collect::<VecDeque<_>>();
    while let Some(source) = queue.pop_front() {
        if stop.contains(&source) || !body.insert(source.clone()) {
            continue;
        }
        for edge in graph.edges.iter().filter(|edge| edge.source == source) {
            queue.push_back(edge.target.clone());
        }
    }
    let entries = each
        .into_iter()
        .filter(|target| body.contains(target))
        .collect();
    (body, entries)
}

async fn persist_iteration_step(
    node: &Node,
    flow: &str,
    claimed: &ClaimedRun,
    graph_node: &FlowNode,
    iteration: u32,
    input: Value,
    result: &ExecResult,
) -> Result<()> {
    let now = now_ms();
    let changed = exec(
        node,
        flow,
        r#"INSERT OR IGNORE INTO flow_steps
           (run_id,node_id,node_type,iteration,seq,status,route_status,taken,
            input_json,output_json,error,started_at_ms,finished_at_ms)
           SELECT ?1,?2,?3,?4,COALESCE((SELECT MAX(seq)+1 FROM flow_steps WHERE run_id=?1),1),
                  ?5,?6,?7,?8,?9,?10,?11,?11
           WHERE EXISTS (SELECT 1 FROM flow_runs WHERE id=?1 AND status='running' AND lease_token=?12)"#,
        json!([
            claimed.run.id,
            graph_node.id,
            graph_node.data.node_type,
            iteration,
            result.status,
            result.route_status,
            result.taken,
            serde_json::to_string(&input)?,
            serde_json::to_string(&result.output)?,
            result.error,
            now,
            claimed.lease
        ]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if changed != 1 {
        bail!("Flow loop 步骤提交失败：租约可能已转移");
    }
    exec(
        node,
        flow,
        "UPDATE flow_runs SET lease_until_ms=?3,updated_at_ms=?2 WHERE id=?1 AND lease_token=?4",
        json!([
            claimed.run.id,
            now,
            now.saturating_add(LEASE_MS),
            claimed.lease
        ]),
    )
    .await?;
    Ok(())
}

async fn execute_with_retries(
    node: &Node,
    flow: &str,
    graph_node: &FlowNode,
    context: &ExecContext,
) -> Result<ExecResult> {
    let retries = graph_node
        .data
        .config
        .get("retries")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(10);
    let delay = graph_node
        .data
        .config
        .get("retryDelayMs")
        .and_then(Value::as_u64)
        .unwrap_or(1_000)
        .min(60_000);
    let mut attempt = 0u64;
    loop {
        match execute_node(node, flow, graph_node, context).await {
            Ok(result) => return Ok(result),
            Err(_error) if attempt < retries => {
                attempt += 1;
                let backoff = delay.saturating_mul(1 << (attempt - 1).min(6));
                tokio::time::sleep(Duration::from_millis(backoff.min(60_000))).await;
            }
            Err(error) => return Err(error),
        }
    }
}

const MAX_SUBFLOW_DEPTH: u8 = 3;

/// Execute a referenced signed Flow as an encapsulated reusable module. The
/// boxed future is intentional: subflows may contain subflow nodes, and the
/// allocation gives the recursive async chain a finite type. Child steps are
/// not written into the parent ledger, matching the exported graph/module
/// model; the parent step durably records the final child output.
fn execute_subflow_inline<'a>(
    node: &'a Node,
    current_flow: String,
    target_flow: String,
    input: Value,
    depth: u8,
) -> BoxFuture<'a, Result<ExecResult>> {
    Box::pin(async move {
        if target_flow == current_flow {
            bail!("Flow 不能直接触发自身；请拆分公共子流程");
        }
        if depth >= MAX_SUBFLOW_DEPTH {
            bail!("子 Flow 嵌套不得超过 {MAX_SUBFLOW_DEPTH} 层");
        }
        let (_, spec) = flow_record(node, &target_flow).context("子 Flow 不存在")?;
        if spec.suspended {
            bail!("子 Flow 已暂停：{}", spec.suspend_reason);
        }
        let graph = spec.graph;
        let mut states = HashMap::<String, StepState>::new();
        loop {
            let mut progressed = false;
            for graph_node in &graph.nodes {
                if states.contains_key(&graph_node.id) {
                    continue;
                }
                let incoming = graph
                    .edges
                    .iter()
                    .filter(|edge| edge.target == graph_node.id)
                    .collect::<Vec<_>>();
                if incoming
                    .iter()
                    .any(|edge| !states.contains_key(&edge.source))
                {
                    continue;
                }
                let live = incoming
                    .iter()
                    .copied()
                    .filter(|edge| edge_is_live(edge, &states))
                    .collect::<Vec<_>>();
                if !incoming.is_empty() && live.is_empty() {
                    states.insert(
                        graph_node.id.clone(),
                        StepState {
                            route_status: "skipped".into(),
                            output: Value::Null,
                            taken: None,
                        },
                    );
                    progressed = true;
                    break;
                }
                let step_input = collect_input(&input, &live, &states);
                let context = ExecContext {
                    input: step_input,
                    trigger: input.clone(),
                    nodes: node_context(&graph, &states),
                    item: None,
                    depth: depth + 1,
                };
                let executed = if graph_node.data.node_type == "loop" {
                    // This is also the reference implementation's deliberate
                    // module boundary: durable loops belong to top-level runs.
                    Ok(ExecResult {
                        status: "skipped".into(),
                        route_status: "skipped".into(),
                        output: Value::Null,
                        taken: None,
                        error: None,
                    })
                } else {
                    execute_with_retries(node, &target_flow, graph_node, &context).await
                };
                let result = match executed {
                    Ok(result) => result,
                    Err(error) => {
                        let message = safe_error(&error);
                        match graph_node.data.on_error.as_str() {
                            "continue" => ExecResult {
                                status: "failed".into(),
                                route_status: "continued".into(),
                                output: json!({ "error": message }),
                                taken: None,
                                error: Some(message),
                            },
                            "branch" => ExecResult {
                                status: "failed".into(),
                                route_status: "error".into(),
                                output: json!({ "error": message }),
                                taken: Some("error".into()),
                                error: Some(message),
                            },
                            _ => bail!("子 Flow 节点 {} 失败：{message}", graph_node.id),
                        }
                    }
                };
                validate_json_size(&result.output, MAX_NODE_RESULT_BYTES, "子 Flow 节点输出")?;
                states.insert(
                    graph_node.id.clone(),
                    StepState {
                        route_status: result.route_status,
                        output: result.output,
                        taken: result.taken,
                    },
                );
                progressed = true;
                break;
            }
            if progressed {
                continue;
            }
            if states.len() != graph.nodes.len() {
                bail!("子 Flow 图无法继续推进；请检查节点依赖和路由条件");
            }
            return Ok(ExecResult::success(final_output(&graph, &states)));
        }
    })
}

async fn execute_node(
    node: &Node,
    current_flow: &str,
    graph_node: &FlowNode,
    context: &ExecContext,
) -> Result<ExecResult> {
    let config = render_config(&graph_node.data.config, context)?;
    match graph_node.data.node_type.as_str() {
        "trigger" => Ok(ExecResult::success(context.input.clone())),
        "transform" => {
            let output = if let Some(template) = config.get("template") {
                template.clone()
            } else if let Some(expression) = graph_node
                .data
                .config
                .get("expression")
                .and_then(Value::as_str)
            {
                eval_expression(expression, context)?
            } else {
                context.input.clone()
            };
            Ok(ExecResult::success(output))
        }
        "branch" => {
            let result = if let Some(expression) = graph_node
                .data
                .config
                .get("condition")
                .and_then(Value::as_str)
            {
                eval_condition(expression, context)?
            } else {
                eval_reference_branch(graph_node, &config, context)?
            };
            Ok(ExecResult {
                status: "complete".into(),
                route_status: "success".into(),
                output: context.input.clone(),
                taken: Some(if result { "true" } else { "false" }.into()),
                error: None,
            })
        }
        "loop" => {
            let items = if let Some(expression) =
                graph_node.data.config.get("items").and_then(Value::as_str)
            {
                eval_expression(expression, context)?
            } else {
                context.input.clone()
            };
            let values = items.as_array().context("Flow loop 节点输入必须是数组")?;
            if values.len() > MAX_LOOP_ITEMS {
                bail!("Flow loop 一次最多处理 1000 个项目");
            }
            Ok(ExecResult {
                status: "complete".into(),
                route_status: "success".into(),
                output: json!({ "items": values, "count": values.len() }),
                taken: Some(if values.is_empty() { "done" } else { "each" }.into()),
                error: None,
            })
        }
        "worker" => execute_worker(node, &config, context).await,
        "http" => execute_http(&config, context).await,
        "kv" => execute_kv(node, &config, context),
        "d1" => execute_d1(node, &config).await,
        "queue" => execute_queue(node, &config, context).await,
        "analytics" => execute_analytics(node, &config, context).await,
        "workflow" => execute_workflow(node, &config, context).await,
        "r2" => execute_r2(node, &config, context).await,
        "pipeline" => execute_pipeline(node, &config, context).await,
        "subflow" => {
            let target = required_string_alias(&config, &["flow", "flowId"], "子 Flow 名称")?;
            let input = config
                .get("input")
                .cloned()
                .unwrap_or_else(|| context.input.clone());
            execute_subflow_inline(
                node,
                current_flow.to_string(),
                target.to_string(),
                input,
                context.depth,
            )
            .await
        }
        "email" => execute_email(node, &config, context).await,
        kind => bail!("尚不支持的 Flow 节点类型：{kind}"),
    }
}

fn execute_kv(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let namespace = required_string_alias(config, &["namespace", "namespaceId"], "KV 命名空间")?;
    let action = config
        .get("action")
        .or_else(|| config.get("op"))
        .and_then(Value::as_str)
        .unwrap_or("get");
    match action {
        "get" => {
            let key = required_string(config, "key", "KV 键")?;
            let output = match node.kv_get(namespace, key) {
                Some(bytes) => bytes_output(bytes),
                None => Value::Null,
            };
            Ok(ExecResult::success(output))
        }
        "put" => {
            let key = required_string(config, "key", "KV 键")?;
            let value = config.get("value").unwrap_or(&context.input);
            let bytes = value_bytes(value, config.get("valueBase64"))?;
            let expires = config
                .get("ttlSeconds")
                .or_else(|| config.get("ttl"))
                .and_then(Value::as_u64)
                .map(|seconds| now_ms().saturating_add(seconds.saturating_mul(1_000)));
            node.kv_put(namespace, key, Some(bytes), expires)?;
            Ok(ExecResult::success(json!({ "ok": true, "key": key })))
        }
        "delete" => {
            let key = required_string(config, "key", "KV 键")?;
            node.kv_put(namespace, key, None, None)?;
            Ok(ExecResult::success(json!({ "deleted": true, "key": key })))
        }
        "list" => {
            let prefix = config.get("prefix").and_then(Value::as_str).unwrap_or("");
            let limit = config.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize;
            Ok(ExecResult::success(json!({
                "keys": node.kv_list(namespace, prefix, limit.clamp(1, 1_000))
            })))
        }
        _ => bail!("Flow KV action 只允许 get、put、delete 或 list"),
    }
}

async fn execute_d1(node: &Node, config: &Map<String, Value>) -> Result<ExecResult> {
    let database = required_string_alias(config, &["database", "databaseId"], "D1 数据库")?;
    let sql = required_string(config, "sql", "D1 SQL")?;
    let params = config.get("params").cloned().unwrap_or_else(|| json!([]));
    if !params.is_array() {
        bail!("Flow D1 参数必须是 JSON 数组");
    }
    d1::ensure_database(node, database)?;
    let output = exec_database(node, database, sql, params).await?;
    Ok(ExecResult::success(output))
}

async fn execute_queue(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let queue = required_string_alias(config, &["queue", "queueId"], "队列名称")?;
    let action = config
        .get("action")
        .or_else(|| config.get("op"))
        .and_then(Value::as_str)
        .unwrap_or("send");
    if action == "receive" {
        let message = crate::queue::receive_one(node, queue).await?;
        return Ok(ExecResult::success(
            message.map(|message| message.body).unwrap_or(Value::Null),
        ));
    }
    if action != "send" {
        bail!("Flow 队列 action 只允许 send 或 receive");
    }
    let delay_seconds = config
        .get("delaySeconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let bodies = config
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            vec![config
                .get("body")
                .cloned()
                .unwrap_or_else(|| context.input.clone())]
        });
    let messages = bodies
        .into_iter()
        .map(|body| crate::queue::SendMessage {
            body,
            delay_seconds,
            ..Default::default()
        })
        .collect();
    let ids = crate::queue::enqueue(node, queue, messages).await?;
    Ok(ExecResult::success(json!({ "messageIds": ids })))
}

async fn execute_analytics(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let dataset = required_string_alias(config, &["dataset", "datasetId"], "Analytics 数据集")?;
    let source = config
        .get("points")
        .or_else(|| config.get("point"))
        .cloned()
        .unwrap_or_else(|| context.input.clone());
    let values = if let Some(values) = source.as_array() {
        values.clone()
    } else {
        vec![source]
    };
    let points = values
        .into_iter()
        .map(serde_json::from_value::<DataPoint>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Flow Analytics 数据点格式无效")?;
    let written = crate::analytics::write(node, dataset, points).await?;
    Ok(ExecResult::success(json!({ "written": written })))
}

async fn execute_workflow(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let workflow = required_string_alias(config, &["workflow", "workflowId"], "Workflow 名称")?;
    let input = config
        .get("input")
        .cloned()
        .unwrap_or_else(|| context.input.clone());
    let key = optional_string(config, "instanceKey")?;
    let instance = crate::workflow::create_instance(node, workflow, key.as_deref(), input).await?;
    Ok(ExecResult::success(serde_json::to_value(instance)?))
}

async fn execute_r2(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let bucket = required_string_alias(config, &["bucket", "bucketId"], "R2 bucket")?;
    let action = config
        .get("action")
        .or_else(|| config.get("op"))
        .and_then(Value::as_str)
        .unwrap_or("get");
    match action {
        "get" => {
            let key = required_string(config, "key", "R2 对象键")?;
            let output = match crate::r2::get_object(node, bucket, key).await? {
                Some((metadata, bytes)) => json!({
                    "metadata": metadata,
                    "body": bytes_output(bytes),
                }),
                None => Value::Null,
            };
            Ok(ExecResult::success(output))
        }
        "put" => {
            let key = required_string(config, "key", "R2 对象键")?;
            let body = config.get("body").unwrap_or(&context.input);
            let bytes = value_bytes(body, config.get("bodyBase64"))?;
            let options = crate::r2::PutOptions {
                content_type: optional_string(config, "contentType")?,
                custom_metadata: config
                    .get("customMetadata")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default(),
                ..Default::default()
            };
            let object = crate::r2::put_object(node, bucket, key, &bytes, options).await?;
            Ok(ExecResult::success(serde_json::to_value(object)?))
        }
        "delete" => {
            let key = required_string(config, "key", "R2 对象键")?;
            let deleted = crate::r2::delete_object(node, bucket, key).await?;
            Ok(ExecResult::success(
                json!({ "deleted": deleted, "key": key }),
            ))
        }
        "list" => {
            let prefix = config.get("prefix").and_then(Value::as_str).unwrap_or("");
            let cursor = optional_string(config, "cursor")?;
            let limit = config.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize;
            let objects =
                crate::r2::list_objects(node, bucket, prefix, cursor.as_deref(), limit).await?;
            Ok(ExecResult::success(serde_json::to_value(objects)?))
        }
        _ => bail!("Flow R2 action 只允许 get、put、delete 或 list"),
    }
}

async fn execute_pipeline(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let pipeline = required_string_alias(config, &["pipeline", "pipelineId"], "Pipeline 名称")?;
    let source = config
        .get("events")
        .or_else(|| config.get("event"))
        .cloned()
        .unwrap_or_else(|| context.input.clone());
    let events = source.as_array().cloned().unwrap_or_else(|| vec![source]);
    let accepted = crate::pipeline::ingest(node, pipeline, events).await?;
    Ok(ExecResult::success(json!({ "accepted": accepted })))
}

async fn execute_email(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let domain = required_string_alias(config, &["domain", "domainId"], "邮件域资源名称")?;
    let mail_from = required_string_alias(config, &["from", "mailFrom"], "信封发件人")?;
    if mail_from.contains(['\r', '\n']) {
        bail!("Flow 邮件发件人不得包含换行符");
    }
    let recipient_value = config
        .get("recipients")
        .or_else(|| config.get("to"))
        .context("Flow 邮件节点缺少收件人")?;
    let recipients = match recipient_value {
        Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>(),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .context("Flow 邮件收件人数组只能包含字符串")
                    .map(str::to_string)
            })
            .collect::<Result<Vec<_>>>()?,
        _ => bail!("Flow 邮件收件人必须是字符串或字符串数组"),
    };
    if recipients.is_empty() || recipients.iter().any(|value| value.contains(['\r', '\n'])) {
        bail!("Flow 邮件节点必须包含至少一个有效收件人");
    }
    let raw = if let Some(raw) = config.get("raw").and_then(Value::as_str) {
        raw.as_bytes().to_vec()
    } else {
        let subject = config
            .get("subject")
            .and_then(Value::as_str)
            .unwrap_or("RandallFlare Flow 通知");
        if subject.contains(['\r', '\n']) {
            bail!("Flow 邮件主题不得包含换行符");
        }
        let body = config.get("body").unwrap_or(&context.input);
        let body = body.as_str().map(str::to_string).unwrap_or_else(|| {
            serde_json::to_string_pretty(body).unwrap_or_else(|_| "null".into())
        });
        format!(
            "From: {mail_from}\r\nTo: {}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{body}\r\n",
            recipients.join(", ")
        )
        .into_bytes()
    };
    let queued = crate::email::queue_outbound(node, domain, mail_from, &recipients, &raw).await?;
    Ok(ExecResult::success(json!({
        "queued": queued,
        "count": recipients.len(),
    })))
}

async fn execute_worker(
    node: &Node,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let worker = required_string_alias(config, &["worker", "workerId"], "Worker 名称")?;
    let port = node
        .worker_port(worker)
        .context("目标 Worker 当前没有本地运行实例")?;
    let method = request_method(config)?;
    let path = config.get("path").and_then(Value::as_str).unwrap_or("/");
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        bail!("Flow Worker 请求路径无效");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let url = format!("http://127.0.0.1:{port}{path}");
    execute_request(client, method, &url, config, context).await
}

async fn execute_http(config: &Map<String, Value>, context: &ExecContext) -> Result<ExecResult> {
    let url = required_string(config, "url", "HTTP URL")?;
    let parsed = reqwest::Url::parse(url).context("Flow HTTP URL 无效")?;
    let client = safe_http_client(&parsed).await?;
    execute_request(client, request_method(config)?, url, config, context).await
}

async fn execute_request(
    client: reqwest::Client,
    method: reqwest::Method,
    url: &str,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<ExecResult> {
    let mut request = client.request(method.clone(), url);
    if let Some(env_name) = config.get("credentialEnv").and_then(Value::as_str) {
        request = apply_credential(request, env_name)?;
    }
    if let Some(headers) = config.get("headers") {
        let headers = match headers {
            Value::Object(headers) => headers.clone(),
            Value::String(raw) if raw.trim().is_empty() => Map::new(),
            Value::String(raw) => serde_json::from_str::<Map<String, Value>>(raw)
                .context("Flow HTTP headers 必须是 JSON 对象")?,
            _ => bail!("Flow HTTP headers 必须是 JSON 对象"),
        };
        for (name, value) in &headers {
            let value = value.as_str().context("Flow HTTP 请求头值必须是字符串")?;
            request = request.header(name, value);
        }
    }
    let body_mode = config
        .get("bodyMode")
        .and_then(Value::as_str)
        .unwrap_or("input");
    if !matches!(method, reqwest::Method::GET | reqwest::Method::HEAD) && body_mode != "none" {
        let body = if body_mode == "input" {
            &context.input
        } else {
            config.get("body").unwrap_or(&context.input)
        };
        request = request.json(body);
    }
    let response = request.send().await.context("Flow HTTP 请求失败")?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = response.bytes().await.context("Flow HTTP 响应读取失败")?;
    if bytes.len() > MAX_NODE_RESULT_BYTES {
        bail!("Flow HTTP 响应超过 4 MiB 限制");
    }
    let body = if content_type.contains("json") {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| bytes_output(bytes.to_vec()))
    } else {
        bytes_output(bytes.to_vec())
    };
    if !status.is_success() {
        bail!("Flow HTTP 上游返回状态码 {}", status.as_u16());
    }
    Ok(ExecResult::success(body))
}

fn request_method(config: &Map<String, Value>) -> Result<reqwest::Method> {
    let source = config
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("POST");
    let method = reqwest::Method::from_bytes(source.as_bytes()).context("Flow HTTP 方法无效")?;
    if matches!(method, reqwest::Method::CONNECT | reqwest::Method::TRACE) {
        bail!("Flow HTTP 不允许 CONNECT 或 TRACE 方法");
    }
    Ok(method)
}

fn apply_credential(
    mut request: reqwest::RequestBuilder,
    env_name: &str,
) -> Result<reqwest::RequestBuilder> {
    validate_secret_env(env_name)?;
    let raw =
        std::env::var(env_name).with_context(|| format!("Flow 凭据环境变量 {env_name} 未配置"))?;
    let credential: Value = serde_json::from_str(&raw).context("Flow 凭据必须是 JSON")?;
    let kind = credential
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("bearer");
    request = match kind {
        "bearer" => request.bearer_auth(
            credential
                .get("value")
                .and_then(Value::as_str)
                .context("Flow bearer 凭据缺少 value")?,
        ),
        "basic" => request.basic_auth(
            credential
                .get("username")
                .and_then(Value::as_str)
                .context("Flow basic 凭据缺少 username")?,
            credential.get("password").and_then(Value::as_str),
        ),
        "header" => request.header(
            credential
                .get("name")
                .and_then(Value::as_str)
                .context("Flow header 凭据缺少 name")?,
            credential
                .get("value")
                .and_then(Value::as_str)
                .context("Flow header 凭据缺少 value")?,
        ),
        _ => bail!("Flow 凭据 kind 只允许 bearer、basic 或 header"),
    };
    Ok(request)
}

async fn safe_http_client(url: &reqwest::Url) -> Result<reqwest::Client> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("Flow HTTP 仅允许不含用户信息的 http/https URL");
    }
    let host = url.host_str().context("Flow HTTP URL 缺少主机名")?;
    let port = url
        .port_or_known_default()
        .context("Flow HTTP URL 端口无效")?;
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .context("Flow HTTP 域名解析失败")?
        .collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        bail!("Flow HTTP 拒绝访问本机、内网、链路本地或特殊地址");
    }
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, addresses[0])
        .build()
        .context("Flow HTTP 客户端创建失败")
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || octets[0] == 0
                || octets[0] >= 224
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && matches!(octets[1], 18 | 19)))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80)
        }
    }
}

async fn send_failure_alert(
    node: &Node,
    flow: &str,
    run: &FlowRun,
    graph_node: &FlowNode,
    message: &str,
) {
    let Some((_, spec)) = flow_record(node, flow) else {
        return;
    };
    let Some(env_name) = spec.alert_webhook_env else {
        return;
    };
    let Ok(url) = std::env::var(&env_name) else {
        tracing::warn!(flow, env = env_name, "Flow 失败告警环境变量未配置");
        return;
    };
    let Ok(parsed) = reqwest::Url::parse(&url) else {
        tracing::warn!(flow, env = env_name, "Flow 失败告警 URL 无效");
        return;
    };
    let Ok(client) = safe_http_client(&parsed).await else {
        tracing::warn!(flow, env = env_name, "Flow 失败告警 URL 未通过安全检查");
        return;
    };
    let payload = json!({
        "event": "flow.run.failed",
        "flow": flow,
        "runId": run.id,
        "nodeId": graph_node.id,
        "nodeType": graph_node.data.node_type,
        "error": message,
        "atMs": now_ms(),
    });
    if client.post(url).json(&payload).send().await.is_err() {
        tracing::warn!(flow, env = env_name, "Flow 失败告警投递失败");
    }
}

fn render_config(
    config: &BTreeMap<String, Value>,
    context: &ExecContext,
) -> Result<Map<String, Value>> {
    config
        .iter()
        .map(|(key, value)| Ok((key.clone(), render_value(value, context)?)))
        .collect()
}

fn render_value(value: &Value, context: &ExecContext) -> Result<Value> {
    match value {
        Value::String(source) => render_string(source, context),
        Value::Array(values) => values
            .iter()
            .map(|value| render_value(value, context))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| Ok((key.clone(), render_value(value, context)?)))
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
        _ => Ok(value.clone()),
    }
}

fn render_string(source: &str, context: &ExecContext) -> Result<Value> {
    let trimmed = source.trim();
    if trimmed.starts_with("{{") && trimmed.ends_with("}}") && trimmed.matches("{{").count() == 1 {
        return eval_expression(trimmed[2..trimmed.len() - 2].trim(), context);
    }
    let mut output = String::new();
    let mut remaining = source;
    while let Some(start) = remaining.find("{{") {
        output.push_str(&remaining[..start]);
        let tail = &remaining[start + 2..];
        let end = tail.find("}}").context("Flow 模板表达式缺少 }}")?;
        let value = eval_expression(tail[..end].trim(), context)?;
        match value {
            Value::String(value) => output.push_str(&value),
            value => output.push_str(&serde_json::to_string(&value)?),
        }
        remaining = &tail[end + 2..];
    }
    output.push_str(remaining);
    Ok(Value::String(output))
}

fn eval_expression(source: &str, context: &ExecContext) -> Result<Value> {
    let source = source.trim();
    if source.is_empty() {
        return Ok(Value::Null);
    }
    if source == "$" {
        return Ok(context.input.clone());
    }
    if source == "$now" || source == "now" {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?;
        return Ok(Value::String(now));
    }
    if let Ok(value) = serde_json::from_str::<Value>(source) {
        return Ok(value);
    }
    if !legacy_path_expression(source) {
        return eval_jsonata_expression(source, context);
    }
    let normalized = source
        .replace("[\"", ".")
        .replace("['", ".")
        .replace("\"]", "")
        .replace("']", "")
        .replace('[', ".")
        .replace(']', "");
    let path = normalized
        .strip_prefix("$.")
        .unwrap_or(&normalized)
        .strip_prefix('$')
        .unwrap_or(&normalized);
    let mut parts = path.split('.');
    let root = parts.next().unwrap_or_default();
    let mut value = match root {
        "input" | "json" => context.input.clone(),
        "trigger" => context.trigger.clone(),
        "node" | "nodes" => Value::Object(context.nodes.clone().into_iter().collect()),
        "item" => context.item.clone().unwrap_or(Value::Null),
        _ => context
            .input
            .get(root)
            .cloned()
            .with_context(|| format!("Flow 表达式找不到 {root}"))?,
    };
    for part in parts {
        value = match &value {
            Value::Object(map) => map.get(part).cloned(),
            Value::Array(values) => part
                .parse::<usize>()
                .ok()
                .and_then(|index| values.get(index).cloned()),
            _ => None,
        }
        .with_context(|| format!("Flow 表达式路径不存在：{source}"))?;
    }
    Ok(value)
}

fn eval_condition(source: &str, context: &ExecContext) -> Result<bool> {
    for operator in ["==", "!=", ">=", "<=", ">", "<"] {
        if let Some((left, right)) = source.split_once(operator) {
            if legacy_expression_operand(left) && legacy_expression_operand(right) {
                let left = eval_expression(left, context)?;
                let right = eval_expression(right, context)?;
                return compare_values(&left, &right, operator);
            }
        }
    }
    Ok(truthy(&eval_jsonata_expression(source, context)?))
}

fn legacy_expression_operand(source: &str) -> bool {
    let source = source.trim();
    serde_json::from_str::<Value>(source).is_ok() || legacy_path_expression(source)
}

fn legacy_path_expression(source: &str) -> bool {
    source
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
        && source.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'$' | b'.' | b'[' | b']' | b'\'' | b'"' | b'-')
        })
}

fn eval_jsonata_expression(source: &str, context: &ExecContext) -> Result<Value> {
    if source.len() > MAX_JSONATA_EXPRESSION_BYTES {
        bail!(
            "Flow JSONata 表达式不得超过 {} KiB",
            MAX_JSONATA_EXPRESSION_BYTES / 1024
        );
    }
    let ast = jsonata_parser::parse(source)
        .map_err(|error| anyhow::anyhow!("Flow JSONata 语法错误：{error}"))?;
    let mut bindings = JsonataContext::new();
    bindings.bind("json".into(), JValue::from(context.input.clone()));
    bindings.bind("input".into(), JValue::from(context.input.clone()));
    bindings.bind(
        "node".into(),
        JValue::from(Value::Object(context.nodes.clone().into_iter().collect())),
    );
    bindings.bind(
        "nodes".into(),
        JValue::from(Value::Object(context.nodes.clone().into_iter().collect())),
    );
    bindings.bind("trigger".into(), JValue::from(context.trigger.clone()));
    bindings.bind(
        "item".into(),
        JValue::from(context.item.clone().unwrap_or(Value::Null)),
    );
    let now =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    bindings.bind("now".into(), JValue::from(Value::String(now)));

    let mut evaluator = JsonataEvaluator::with_options(
        bindings,
        JsonataEvaluatorOptions {
            timeout_ms: Some(JSONATA_TIMEOUT_MS),
            max_stack_depth: Some(JSONATA_MAX_STACK_DEPTH),
            max_sequence_length: Some(MAX_JSONATA_SEQUENCE_ITEMS),
        },
    );
    let input = JValue::from(context.input.clone());
    let output = evaluator
        .evaluate(&ast, &input)
        .map_err(|error| anyhow::anyhow!("Flow JSONata 执行失败：{error}"))?;
    Ok(Value::from(&output))
}

fn eval_reference_branch(
    node: &FlowNode,
    config: &Map<String, Value>,
    context: &ExecContext,
) -> Result<bool> {
    let path = node
        .data
        .config
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("$");
    let value = eval_expression(path, context)?;
    let target = config.get("value").cloned().unwrap_or(Value::Null);
    let operation = config.get("op").and_then(Value::as_str).unwrap_or("truthy");
    match operation {
        "truthy" => Ok(truthy(&value)),
        "eq" => Ok(string_comparison_value(&value) == string_comparison_value(&target)),
        "ne" => Ok(string_comparison_value(&value) != string_comparison_value(&target)),
        "gt" => compare_values(&value, &target, ">"),
        "lt" => compare_values(&value, &target, "<"),
        "contains" => {
            Ok(string_comparison_value(&value).contains(&string_comparison_value(&target)))
        }
        _ => bail!("Flow branch op 只允许 truthy、eq、ne、gt、lt 或 contains"),
    }
}

fn string_comparison_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        value => value.to_string(),
    }
}

fn compare_values(left: &Value, right: &Value, operator: &str) -> Result<bool> {
    let result = match operator {
        "==" => left == right,
        "!=" => left != right,
        ">" | ">=" | "<" | "<=" => {
            let left = left.as_f64().context("Flow 条件左值不是数字")?;
            let right = right.as_f64().context("Flow 条件右值不是数字")?;
            match operator {
                ">" => left > right,
                ">=" => left >= right,
                "<" => left < right,
                _ => left <= right,
            }
        }
        _ => false,
    };
    Ok(result)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn required_string<'a>(config: &'a Map<String, Value>, key: &str, label: &str) -> Result<&'a str> {
    config
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("Flow 节点缺少{label}"))
}

fn required_string_alias<'a>(
    config: &'a Map<String, Value>,
    keys: &[&str],
    label: &str,
) -> Result<&'a str> {
    keys.iter()
        .find_map(|key| {
            config
                .get(*key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .with_context(|| format!("Flow 节点缺少{label}"))
}

fn optional_string(config: &Map<String, Value>, key: &str) -> Result<Option<String>> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("Flow 节点字段 {key} 必须是字符串"),
    }
}

fn value_bytes(value: &Value, encoded: Option<&Value>) -> Result<Vec<u8>> {
    if let Some(encoded) = encoded.and_then(Value::as_str) {
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("Flow Base64 数据无效");
    }
    Ok(match value {
        Value::String(value) => value.as_bytes().to_vec(),
        value => serde_json::to_vec(value)?,
    })
}

fn bytes_output(bytes: Vec<u8>) -> Value {
    match String::from_utf8(bytes.clone()) {
        Ok(text) => json!({ "text": text }),
        Err(_) => json!({ "base64": base64::engine::general_purpose::STANDARD.encode(bytes) }),
    }
}

fn safe_error(error: &anyhow::Error) -> String {
    let mut message = error.to_string();
    if message.len() > 2_000 {
        message.truncate(2_000);
    }
    message
}

async fn exec(node: &Node, flow: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &database_name(flow), sql, params).await
}

async fn exec_database(node: &Node, database: &str, sql: &str, params: Value) -> Result<Value> {
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let listen = node.cfg.peer_api.listen;
    let base = if listen.is_ipv6() {
        format!("[::1]:{}", listen.port())
    } else {
        format!("127.0.0.1:{}", listen.port())
    };
    client.d1_exec(&base, database, sql, params).await
}

const RUN_FIELDS: &str = "id,run_key,trigger,status,input_json,output_json,error,graph_version,retry_of,started_at_ms,finished_at_ms,created_at_ms,updated_at_ms";

fn rows(result: Value) -> Vec<Value> {
    result["rows"].as_array().cloned().unwrap_or_default()
}

fn row_to_run(row: &Value) -> Result<FlowRun> {
    Ok(FlowRun {
        id: string_field(row, "id")?.into(),
        run_key: optional_string_field(row, "run_key"),
        trigger: string_field(row, "trigger")?.into(),
        status: string_field(row, "status")?.into(),
        input: json_string_field(row, "input_json")?.context("Flow 输入为空")?,
        output: json_string_field(row, "output_json")?,
        error: optional_string_field(row, "error"),
        graph_version: u64_field(row, "graph_version"),
        retry_of: optional_string_field(row, "retry_of"),
        started_at_ms: optional_u64_field(row, "started_at_ms"),
        finished_at_ms: optional_u64_field(row, "finished_at_ms"),
        created_at_ms: u64_field(row, "created_at_ms"),
        updated_at_ms: u64_field(row, "updated_at_ms"),
    })
}

fn row_to_step(row: &Value) -> Result<FlowRunStep> {
    Ok(FlowRunStep {
        node_id: string_field(row, "node_id")?.into(),
        node_type: string_field(row, "node_type")?.into(),
        iteration: u64_field(row, "iteration") as u32,
        seq: u64_field(row, "seq"),
        status: string_field(row, "status")?.into(),
        route_status: string_field(row, "route_status")?.into(),
        taken: optional_string_field(row, "taken"),
        input: json_string_field(row, "input_json")?,
        output: json_string_field(row, "output_json")?,
        error: optional_string_field(row, "error"),
        started_at_ms: u64_field(row, "started_at_ms"),
        finished_at_ms: u64_field(row, "finished_at_ms"),
    })
}

fn string_field<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Flow 数据库行缺少 {field}"))
}

fn optional_string_field(row: &Value, field: &str) -> Option<String> {
    row.get(field).and_then(Value::as_str).map(str::to_string)
}

fn u64_field(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn optional_u64_field(row: &Value, field: &str) -> Option<u64> {
    row.get(field).and_then(Value::as_u64)
}

fn json_string_field(row: &Value, field: &str) -> Result<Option<Value>> {
    row.get(field)
        .and_then(Value::as_str)
        .map(serde_json::from_str)
        .transpose()
        .with_context(|| format!("Flow 数据库字段 {field} 不是有效 JSON"))
}

fn validate_run_status(status: &str) -> Result<()> {
    if !matches!(
        status,
        "queued" | "running" | "complete" | "failed" | "cancelled"
    ) {
        bail!("Flow 运行状态筛选无效");
    }
    Ok(())
}

fn new_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
    )
}

fn validate_graph(graph: &FlowGraph) -> Result<()> {
    if graph.nodes.is_empty() {
        bail!("Flow 至少需要一个节点");
    }
    if graph.nodes.len() > MAX_NODES || graph.edges.len() > MAX_EDGES {
        bail!("Flow 图最多包含 500 个节点和 2000 条连线");
    }
    if serde_json::to_vec(graph)?.len() > MAX_GRAPH_BYTES {
        bail!("Flow 图不得超过 768 KiB");
    }
    let mut ids = HashSet::new();
    let mut labels = HashSet::new();
    let mut trigger_nodes = 0usize;
    for node in &graph.nodes {
        validate_graph_id(&node.id, "节点")?;
        if !ids.insert(node.id.as_str()) {
            bail!("Flow 节点 ID 重复：{}", node.id);
        }
        if node.data.label.len() > 128 {
            bail!("Flow 节点标签不得超过 128 个字符");
        }
        if !node.data.label.is_empty() && !labels.insert(node.data.label.as_str()) {
            bail!("Flow 节点标签必须唯一：{}", node.data.label);
        }
        if !node.position.x.is_finite()
            || !node.position.y.is_finite()
            || node.position.x.abs() > 1_000_000.0
            || node.position.y.abs() > 1_000_000.0
        {
            bail!("Flow 节点坐标无效：{}", node.id);
        }
        if !matches!(
            node.data.on_error.as_str(),
            "" | "stop" | "continue" | "branch"
        ) {
            bail!("Flow 节点 onError 只允许 stop、continue 或 branch");
        }
        validate_node_config(node)?;
        if node.data.node_type == "trigger" {
            trigger_nodes += 1;
        }
    }
    if trigger_nodes != 1 {
        bail!("Flow 必须且只能包含一个 trigger 节点");
    }
    let mut edge_ids = HashSet::new();
    let mut pairs = HashSet::new();
    for edge in &graph.edges {
        validate_graph_id(&edge.id, "连线")?;
        if !edge_ids.insert(edge.id.as_str()) {
            bail!("Flow 连线 ID 重复：{}", edge.id);
        }
        if edge.source == edge.target
            || !ids.contains(edge.source.as_str())
            || !ids.contains(edge.target.as_str())
        {
            bail!("Flow 连线引用无效节点：{}", edge.id);
        }
        let pair = (
            edge.source.as_str(),
            edge.target.as_str(),
            edge.source_handle.as_deref().unwrap_or(""),
        );
        if !pairs.insert(pair) {
            bail!("Flow 存在重复连线：{} → {}", edge.source, edge.target);
        }
    }
    // A loop is represented as a split node with `each` and `done` handles,
    // not a graph cycle. Keeping the stored graph acyclic makes replay and
    // dead-branch propagation deterministic.
    let mut indegree: HashMap<&str, usize> = ids.iter().map(|id| (*id, 0)).collect();
    let mut outgoing: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in &graph.edges {
        *indegree.entry(&edge.target).or_default() += 1;
        outgoing.entry(&edge.source).or_default().push(&edge.target);
    }
    let mut ready: VecDeque<&str> = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect();
    let mut visited = 0usize;
    while let Some(id) = ready.pop_front() {
        visited += 1;
        for target in outgoing.get(id).into_iter().flatten() {
            let degree = indegree.get_mut(target).context("Flow 拓扑索引损坏")?;
            *degree -= 1;
            if *degree == 0 {
                ready.push_back(target);
            }
        }
    }
    if visited != graph.nodes.len() {
        bail!("Flow 图必须是无环 DAG；循环请使用 loop 节点");
    }
    Ok(())
}

fn validate_node_config(node: &FlowNode) -> Result<()> {
    const KINDS: &[&str] = &[
        "trigger",
        "worker",
        "http",
        "branch",
        "loop",
        "transform",
        "subflow",
        "kv",
        "d1",
        "queue",
        "analytics",
        "workflow",
        "r2",
        "pipeline",
        "email",
    ];
    if !KINDS.contains(&node.data.node_type.as_str()) {
        bail!("Flow 节点类型无效：{}", node.data.node_type);
    }
    if node.data.config.len() > 64 {
        bail!("Flow 单个节点配置字段不得超过 64 个");
    }
    let bytes = serde_json::to_vec(&node.data.config)?;
    if bytes.len() > 128 * 1024 {
        bail!("Flow 单个节点配置不得超过 128 KiB");
    }
    for (key, value) in &node.data.config {
        if key.len() > 128 || key.contains(['\r', '\n', '\0']) {
            bail!("Flow 节点配置键无效");
        }
        let lower = key.to_ascii_lowercase();
        if [
            "secret",
            "password",
            "token",
            "authorization",
            "apikey",
            "api_key",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
            && lower != "credentialenv"
        {
            bail!("Flow 图不得携带明文凭据；请改用 credentialEnv 指向节点本地环境变量");
        }
        reject_nested_secret(value)?;
    }
    if let Some(Value::String(name)) = node.data.config.get("credentialEnv") {
        validate_secret_env(name)?;
    }
    for field in ["expression", "condition", "items", "itemsPath"] {
        if node
            .data
            .config
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|source| source.len() > MAX_JSONATA_EXPRESSION_BYTES)
        {
            bail!(
                "Flow 节点 {} 的 {field} 表达式不得超过 {} KiB",
                node.id,
                MAX_JSONATA_EXPRESSION_BYTES / 1024
            );
        }
    }
    Ok(())
}

fn reject_nested_secret(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if [
                    "secret",
                    "password",
                    "token",
                    "authorization",
                    "apikey",
                    "api_key",
                ]
                .iter()
                .any(|needle| lower.contains(needle))
                {
                    bail!("Flow 图不得嵌入明文凭据");
                }
                reject_nested_secret(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_nested_secret(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_secret_env(name: &str) -> Result<()> {
    if !name.starts_with("RF_FLOW_CREDENTIAL_")
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("Flow 凭据环境变量必须使用 RF_FLOW_CREDENTIAL_ 前缀和大写安全字符");
    }
    Ok(())
}

fn validate_graph_id(value: &str, kind: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("Flow {kind} ID 无效");
    }
    Ok(())
}

fn validate_run_key(key: Option<&str>) -> Result<()> {
    if key.is_some_and(|key| {
        key.is_empty()
            || key.len() > 256
            || key.contains(['\r', '\n', '\0'])
            || key.chars().any(char::is_control)
    }) {
        bail!("Flow 幂等键必须是 1 至 256 个安全字符");
    }
    Ok(())
}

fn validate_json_size(value: &Value, limit: usize, label: &str) -> Result<()> {
    if serde_json::to_vec(value)?.len() > limit {
        bail!("{label}不得超过 {} MiB", limit / 1024 / 1024);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> FlowGraph {
        FlowGraph {
            nodes: vec![
                FlowNode {
                    id: "start".into(),
                    render_type: "flowNode".into(),
                    position: FlowPosition::default(),
                    data: FlowNodeData {
                        node_type: "trigger".into(),
                        label: "开始".into(),
                        on_error: String::new(),
                        config: BTreeMap::new(),
                    },
                },
                FlowNode {
                    id: "shape".into(),
                    render_type: "flowNode".into(),
                    position: FlowPosition { x: 220.0, y: 0.0 },
                    data: FlowNodeData {
                        node_type: "transform".into(),
                        label: "整理".into(),
                        on_error: "stop".into(),
                        config: BTreeMap::from([("expression".into(), json!("input.order"))]),
                    },
                },
            ],
            edges: vec![FlowEdge {
                id: "start-shape".into(),
                source: "start".into(),
                target: "shape".into(),
                source_handle: None,
                target_handle: None,
            }],
        }
    }

    #[test]
    fn graph_validation_rejects_cycles_and_embedded_secrets() {
        let mut valid = graph();
        assert!(validate_graph(&valid).is_ok());
        valid.edges.push(FlowEdge {
            id: "back".into(),
            source: "shape".into(),
            target: "start".into(),
            source_handle: None,
            target_handle: None,
        });
        assert!(validate_graph(&valid).is_err());
        let mut secret = graph();
        secret.nodes[1]
            .data
            .config
            .insert("apiToken".into(), json!("must-not-replicate"));
        assert!(validate_graph(&secret).is_err());
    }

    #[test]
    fn token_hashes_are_one_way() {
        let (token, plaintext) = mint_token("Webhook").unwrap();
        let spec = FlowSpec {
            graph: graph(),
            trigger: FlowTrigger::Webhook,
            tokens: vec![token],
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
        assert!(token_matches(&spec, &plaintext));
        assert!(!token_matches(&spec, "rff_wrong"));
        assert!(!serde_json::to_string(&spec).unwrap().contains(&plaintext));
    }

    #[test]
    fn database_names_are_stable_and_private() {
        assert_eq!(database_name("orders"), database_name("orders"));
        assert_ne!(database_name("orders"), database_name("billing"));
        assert!(!database_name("orders").contains("orders"));
    }

    #[test]
    fn templates_preserve_typed_values_and_interpolate_strings() {
        let context = ExecContext {
            input: json!({ "order": { "id": "RF-42", "amount": 19.5 } }),
            trigger: json!({ "requestId": "req-1" }),
            nodes: BTreeMap::from([("lookup".into(), json!({ "risk": 7 }))]),
            item: Some(json!({ "sku": "A-1" })),
            depth: 0,
        };
        assert_eq!(
            render_string("{{ input.order.amount }}", &context).unwrap(),
            json!(19.5)
        );
        assert_eq!(
            render_string("order={{ input.order.id }}/{{ item.sku }}", &context).unwrap(),
            json!("order=RF-42/A-1")
        );
        assert!(eval_condition("nodes.lookup.risk >= 5", &context).unwrap());
        assert_eq!(
            render_string("{{ trigger.requestId }}", &context).unwrap(),
            json!("req-1")
        );
    }

    #[test]
    fn jsonata_transforms_use_full_run_context_and_resource_limits() {
        let context = ExecContext {
            input: json!({
                "orders": [
                    { "sku": "A-1", "price": 12.5, "qty": 2 },
                    { "sku": "B-2", "price": 4, "qty": 3 }
                ]
            }),
            trigger: json!({ "requestId": "req-jsonata" }),
            nodes: BTreeMap::from([("lookup".into(), json!({ "risk": 7 }))]),
            item: Some(json!({ "sku": "A-1" })),
            depth: 0,
        };

        assert_eq!(
            eval_expression(
                r#"$input.orders[price >= 10].{"sku": sku, "total": price * qty}"#,
                &context,
            )
            .unwrap(),
            json!({ "sku": "A-1", "total": 25.0 })
        );
        assert_eq!(
            eval_expression(r#"$sum($input.orders.(price * qty))"#, &context).unwrap(),
            json!(37.0)
        );
        let enriched = eval_expression(
            r#"{"request": $trigger.requestId, "risk": $nodes.lookup.risk, "sku": $item.sku, "at": $now}"#,
            &context,
        )
        .unwrap();
        assert_eq!(enriched["request"], "req-jsonata");
        assert_eq!(enriched["risk"], 7.0);
        assert_eq!(enriched["sku"], "A-1");
        assert!(enriched["at"]
            .as_str()
            .is_some_and(|value| value.ends_with('Z')));
        assert!(eval_condition(
            r#"$sum($input.orders.price) >= 16 and $contains($item.sku, "A-")"#,
            &context,
        )
        .unwrap());

        let oversized = "x".repeat(MAX_JSONATA_EXPRESSION_BYTES + 1);
        assert!(eval_expression(&format!("$uppercase(\"{oversized}\")"), &context).is_err());
        let sequence_error = eval_expression("[1..20000]", &context).unwrap_err();
        assert!(
            sequence_error
                .to_string()
                .contains("maximum sequence length"),
            "unexpected JSONata sequence guard error: {sequence_error}"
        );
    }

    #[test]
    fn loop_body_stops_before_done_branch() {
        let graph: FlowGraph = serde_json::from_value(json!({
            "nodes": [
                {"id":"loop","position":{"x":0,"y":0},"data":{"nodeType":"loop"}},
                {"id":"body","position":{"x":0,"y":0},"data":{"nodeType":"transform"}},
                {"id":"body2","position":{"x":0,"y":0},"data":{"nodeType":"kv"}},
                {"id":"done","position":{"x":0,"y":0},"data":{"nodeType":"transform"}},
                {"id":"after","position":{"x":0,"y":0},"data":{"nodeType":"transform"}}
            ],
            "edges": [
                {"id":"each","source":"loop","target":"body","sourceHandle":"each"},
                {"id":"body-next","source":"body","target":"body2"},
                {"id":"done","source":"loop","target":"done","sourceHandle":"done"},
                {"id":"after","source":"done","target":"after"}
            ]
        }))
        .unwrap();
        let (body, entries) = loop_body("loop", &graph);
        assert_eq!(entries, HashSet::from(["body".into()]));
        assert_eq!(body, HashSet::from(["body".into(), "body2".into()]));
    }

    #[test]
    fn ssrf_filter_rejects_private_and_mapped_addresses() {
        for source in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(source.parse().unwrap()), "{source}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
