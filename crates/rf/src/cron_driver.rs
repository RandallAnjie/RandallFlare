//! Durable Worker Cron execution.
//!
//! Every node evaluates the same signed schedule. A cluster claim selects one
//! live runtime for each `(worker, expression, minute)`; that node invokes the
//! generated, token-protected scheduled-event adapter. Attempts and DLQ state
//! are stored in a per-Worker D1 micro-quorum, so history remains available
//! without a central control plane.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use rf_core::cron::CronExpr;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const MAX_ATTEMPTS: u16 = 3;
const BASE_BACKOFF_SECONDS: u64 = 30;
const SUCCESS_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAX_ERROR_BRIEF_BYTES: usize = 400;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRun {
    pub id: String,
    pub worker: String,
    pub expression: String,
    pub scheduled_at_ms: u64,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub attempt: u16,
    pub status: String,
    pub status_code: Option<u16>,
    pub error_brief: Option<String>,
    pub dlq: bool,
    pub replay_of: Option<String>,
    pub replayed_at_ms: Option<u64>,
    pub node: String,
}

struct FireResult {
    started_at_ms: u64,
    finished_at_ms: u64,
    status_code: Option<u16>,
    error_brief: Option<String>,
}

impl FireResult {
    fn success(&self) -> bool {
        self.status_code
            .is_some_and(|status| (200..300).contains(&status))
            && self.error_brief.is_none()
    }
}

/// How long after claiming we wait for gossip to converge before checking the
/// winner. Roughly two gossip rounds.
fn settle_delay(node: &Node) -> Duration {
    Duration::from_millis((node.cfg.gossip.interval_ms * 2).clamp(500, 5_000))
}

pub fn spawn(node: Arc<Node>) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest client");
        loop {
            let now = now_ms();
            let next_minute = (now / 60_000 + 1) * 60_000;
            let jitter = rand::random::<u64>() % 500;
            tokio::time::sleep(Duration::from_millis(next_minute - now + jitter)).await;

            let minute_epoch_secs = next_minute / 1_000;
            for manifest in node.live_manifests() {
                // Only a node with the current local runtime may race for the
                // tick. This keeps DO-placement followers from winning a task
                // they cannot execute.
                if node.worker_port(&manifest.name).is_none() {
                    continue;
                }
                for expression in &manifest.crons {
                    let Ok(parsed) = CronExpr::parse(expression) else {
                        continue;
                    };
                    if !parsed.matches(minute_epoch_secs) {
                        continue;
                    }
                    let task = cron_task_id(&manifest.name, expression, minute_epoch_secs / 60);
                    if !matches!(node.claim_try(&task, 180_000), Ok(true)) {
                        continue;
                    }
                    let node = node.clone();
                    let client = client.clone();
                    let worker = manifest.name.clone();
                    let expression = expression.clone();
                    let delay = settle_delay(&node);
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        if !node.holds(&task) {
                            return;
                        }
                        if let Err(error) =
                            fire_with_retries(&node, &client, &worker, &expression, next_minute)
                                .await
                        {
                            tracing::warn!("Cron {worker} ({expression}) 执行记录失败：{error:#}");
                        }
                        let _ = node.claim_renew(&task, true);
                    });
                }
            }
        }
    });
}

pub fn cron_task_id(worker: &str, expression: &str, minute: u64) -> String {
    let digest = Sha256::digest(expression.as_bytes());
    format!("cron/{worker}/{}/{minute}", hex::encode(&digest[..4]))
}

pub fn database_name(worker: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("cron/{worker}").as_bytes()));
    format!("cron-{}", &digest[..32])
}

pub async fn list_runs(
    node: &Node,
    worker: &str,
    dlq_only: bool,
    limit: usize,
) -> Result<Vec<CronRun>> {
    validate_worker_name(worker)?;
    ensure_schema(node, worker).await?;
    cleanup_history(node, worker).await?;
    let sql = if dlq_only {
        r#"SELECT id, expression, scheduled_at_ms, started_at_ms, finished_at_ms,
                  attempt, status, status_code, error_brief, dlq, replay_of,
                  replayed_at_ms, node_id
           FROM cron_runs WHERE dlq = 1
           ORDER BY started_at_ms DESC, id DESC LIMIT ?1"#
    } else {
        r#"SELECT id, expression, scheduled_at_ms, started_at_ms, finished_at_ms,
                  attempt, status, status_code, error_brief, dlq, replay_of,
                  replayed_at_ms, node_id
           FROM cron_runs WHERE dlq = 0
           ORDER BY started_at_ms DESC, id DESC LIMIT ?1"#
    };
    rows(exec(node, worker, sql, json!([limit.clamp(1, 1_000)])).await?)
        .iter()
        .map(|row| row_to_run(worker, row))
        .collect()
}

pub async fn fire_now(node: &Node, worker: &str, expression: Option<&str>) -> Result<CronRun> {
    let manifest = node.manifest(worker).context("Worker 不存在")?;
    if manifest.main.is_empty() {
        bail!("纯静态 Worker 没有 scheduled() 运行时");
    }
    let expression = expression.unwrap_or("manual").trim();
    if expression != "manual" && !manifest.crons.iter().any(|value| value == expression) {
        bail!("只能手动触发当前签名清单中的 Cron 表达式");
    }
    ensure_schema(node, worker).await?;
    cleanup_history(node, worker).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let scheduled_at_ms = now_ms();
    let result = fire_once(node, &client, worker, expression, scheduled_at_ms, None).await;
    let run = build_run(node, worker, expression, scheduled_at_ms, 1, result);
    record_run(node, &run).await?;
    append_run_log(node, &manifest, &run);
    Ok(run)
}

pub async fn replay_dlq(node: &Node, worker: &str, id: &str) -> Result<Option<CronRun>> {
    validate_worker_name(worker)?;
    validate_run_id(id)?;
    let manifest = node.manifest(worker).context("Worker 不存在")?;
    ensure_schema(node, worker).await?;
    let source = rows(
        exec(
            node,
            worker,
            "SELECT expression FROM cron_runs WHERE id = ?1 AND dlq = 1 LIMIT 1",
            json!([id]),
        )
        .await?,
    )
    .into_iter()
    .next();
    let Some(source) = source else {
        return Ok(None);
    };
    let expression = string_field(&source, "expression")?.to_string();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let scheduled_at_ms = now_ms();
    let result = fire_once(
        node,
        &client,
        worker,
        &expression,
        scheduled_at_ms,
        Some(id),
    )
    .await;
    let mut run = build_run(node, worker, &expression, scheduled_at_ms, 1, result);
    run.replay_of = Some(id.to_string());
    record_run(node, &run).await?;
    exec(
        node,
        worker,
        "UPDATE cron_runs SET replayed_at_ms = ?1 WHERE id = ?2 AND dlq = 1",
        json!([now_ms(), id]),
    )
    .await?;
    append_run_log(node, &manifest, &run);
    Ok(Some(run))
}

pub async fn delete_dlq(node: &Node, worker: &str, id: &str) -> Result<bool> {
    validate_worker_name(worker)?;
    validate_run_id(id)?;
    ensure_schema(node, worker).await?;
    let result = exec(
        node,
        worker,
        "DELETE FROM cron_runs WHERE id = ?1 AND dlq = 1",
        json!([id]),
    )
    .await?;
    Ok(result["rows_affected"].as_u64().unwrap_or(0) > 0)
}

async fn fire_with_retries(
    node: &Node,
    client: &reqwest::Client,
    worker: &str,
    expression: &str,
    scheduled_at_ms: u64,
) -> Result<()> {
    let manifest = node.manifest(worker).context("Worker 不存在")?;
    ensure_schema(node, worker).await?;
    cleanup_history(node, worker).await?;
    for attempt in 1..=MAX_ATTEMPTS {
        let result = fire_once(node, client, worker, expression, scheduled_at_ms, None).await;
        let success = result.success();
        let dlq = !success && attempt == MAX_ATTEMPTS;
        let mut run = build_run(node, worker, expression, scheduled_at_ms, attempt, result);
        run.dlq = dlq;
        record_run(node, &run).await?;
        append_run_log(node, &manifest, &run);
        if success || dlq {
            return Ok(());
        }
        let seconds = BASE_BACKOFF_SECONDS * (1u64 << (attempt - 1));
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }
    Ok(())
}

async fn fire_once(
    node: &Node,
    client: &reqwest::Client,
    worker: &str,
    expression: &str,
    scheduled_at_ms: u64,
    replay_of: Option<&str>,
) -> FireResult {
    let started_at_ms = now_ms();
    let Some(port) = node.worker_port(worker) else {
        return FireResult {
            started_at_ms,
            finished_at_ms: now_ms(),
            status_code: None,
            error_brief: Some("Worker 当前未在此节点运行".into()),
        };
    };
    let Some(token) = node.worker_event_token(worker) else {
        return FireResult {
            started_at_ms,
            finished_at_ms: now_ms(),
            status_code: None,
            error_brief: Some("Worker 内部事件令牌不可用".into()),
        };
    };
    let mut request = client
        .post(format!("http://127.0.0.1:{port}/.rf/internal/cron"))
        .header("x-rf-internal-event", token)
        .header("x-edge-cron-expression", expression)
        .header("x-edge-cron-time", (scheduled_at_ms / 1_000).to_string());
    if let Some(source) = replay_of {
        request = request.header("x-edge-cron-replay", source);
    }
    match request.send().await {
        Ok(mut response) => {
            let status = response.status().as_u16();
            let error_brief = if response.status().is_success() {
                None
            } else {
                let mut body = Vec::new();
                while let Ok(Some(chunk)) = response.chunk().await {
                    let remaining = MAX_ERROR_BRIEF_BYTES.saturating_sub(body.len());
                    if remaining == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    if body.len() >= MAX_ERROR_BRIEF_BYTES {
                        break;
                    }
                }
                let brief = String::from_utf8_lossy(&body).trim().to_string();
                Some(truncate_brief(if brief.is_empty() {
                    format!("Worker 返回 HTTP {status}")
                } else {
                    brief
                }))
            };
            FireResult {
                started_at_ms,
                finished_at_ms: now_ms(),
                status_code: Some(status),
                error_brief,
            }
        }
        Err(error) => FireResult {
            started_at_ms,
            finished_at_ms: now_ms(),
            status_code: None,
            error_brief: Some(truncate_brief(format!("触发请求失败：{error}"))),
        },
    }
}

fn build_run(
    node: &Node,
    worker: &str,
    expression: &str,
    scheduled_at_ms: u64,
    attempt: u16,
    result: FireResult,
) -> CronRun {
    CronRun {
        id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()),
        worker: worker.to_string(),
        expression: expression.to_string(),
        scheduled_at_ms,
        started_at_ms: result.started_at_ms,
        finished_at_ms: result.finished_at_ms,
        attempt,
        status: if result.success() {
            "success"
        } else {
            "failed"
        }
        .into(),
        status_code: result.status_code,
        error_brief: result.error_brief,
        dlq: false,
        replay_of: None,
        replayed_at_ms: None,
        node: node.id_hex(),
    }
}

fn append_run_log(node: &Node, manifest: &rf_core::manifest::WorkerManifest, run: &CronRun) {
    let suffix = run
        .status_code
        .map(|status| format!("HTTP {status}"))
        .or_else(|| run.error_brief.clone())
        .unwrap_or_else(|| run.status.clone());
    node.append_runtime_log(
        &manifest.name,
        manifest.version,
        "cron",
        &format!(
            "{} · 第 {} 次尝试 · {}{}",
            run.expression,
            run.attempt,
            suffix,
            if run.dlq { " · 已进入 DLQ" } else { "" }
        ),
    );
}

async fn record_run(node: &Node, run: &CronRun) -> Result<()> {
    exec(
        node,
        &run.worker,
        r#"INSERT INTO cron_runs
           (id, expression, scheduled_at_ms, started_at_ms, finished_at_ms,
            attempt, status, status_code, error_brief, dlq, replay_of,
            replayed_at_ms, node_id)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"#,
        json!([
            run.id,
            run.expression,
            run.scheduled_at_ms,
            run.started_at_ms,
            run.finished_at_ms,
            run.attempt,
            run.status,
            run.status_code,
            run.error_brief,
            if run.dlq { 1 } else { 0 },
            run.replay_of,
            run.replayed_at_ms,
            run.node,
        ]),
    )
    .await?;
    Ok(())
}

async fn cleanup_history(node: &Node, worker: &str) -> Result<()> {
    exec(
        node,
        worker,
        "DELETE FROM cron_runs WHERE dlq = 0 AND started_at_ms < ?1",
        json!([now_ms().saturating_sub(SUCCESS_RETENTION_MS)]),
    )
    .await?;
    Ok(())
}

async fn ensure_schema(node: &Node, worker: &str) -> Result<()> {
    let database = database_name(worker);
    d1::ensure_database(node, &database)?;
    if node.cron_schema_ready(&database) {
        return Ok(());
    }
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS cron_runs (
             id TEXT PRIMARY KEY,
             expression TEXT NOT NULL,
             scheduled_at_ms INTEGER NOT NULL,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER NOT NULL,
             attempt INTEGER NOT NULL,
             status TEXT NOT NULL,
             status_code INTEGER,
             error_brief TEXT,
             dlq INTEGER NOT NULL DEFAULT 0,
             replay_of TEXT,
             replayed_at_ms INTEGER,
             node_id TEXT NOT NULL
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        "CREATE INDEX IF NOT EXISTS cron_runs_recent ON cron_runs(started_at_ms DESC)",
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        "CREATE INDEX IF NOT EXISTS cron_runs_dlq ON cron_runs(dlq, started_at_ms DESC)",
        json!([]),
    )
    .await?;
    node.mark_cron_schema_ready(database);
    Ok(())
}

async fn exec(node: &Node, worker: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &database_name(worker), sql, params).await
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

fn rows(result: Value) -> Vec<Value> {
    result["rows"].as_array().cloned().unwrap_or_default()
}

fn row_to_run(worker: &str, row: &Value) -> Result<CronRun> {
    Ok(CronRun {
        id: string_field(row, "id")?.to_string(),
        worker: worker.to_string(),
        expression: string_field(row, "expression")?.to_string(),
        scheduled_at_ms: u64_field(row, "scheduled_at_ms"),
        started_at_ms: u64_field(row, "started_at_ms"),
        finished_at_ms: u64_field(row, "finished_at_ms"),
        attempt: u64_field(row, "attempt").min(u16::MAX as u64) as u16,
        status: string_field(row, "status")?.to_string(),
        status_code: row
            .get("status_code")
            .and_then(Value::as_u64)
            .map(|value| value.min(u16::MAX as u64) as u16),
        error_brief: row
            .get("error_brief")
            .and_then(Value::as_str)
            .map(str::to_string),
        dlq: u64_field(row, "dlq") != 0,
        replay_of: row
            .get("replay_of")
            .and_then(Value::as_str)
            .map(str::to_string),
        replayed_at_ms: row.get("replayed_at_ms").and_then(Value::as_u64),
        node: string_field(row, "node_id")?.to_string(),
    })
}

fn string_field<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Cron 数据库行缺少 {field}"))
}

fn u64_field(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn validate_worker_name(worker: &str) -> Result<()> {
    if !rf_core::manifest::valid_name(worker) {
        bail!("Worker 名称无效");
    }
    Ok(())
}

fn validate_run_id(id: &str) -> Result<()> {
    if id.len() != 22
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("Cron 运行 ID 无效");
    }
    Ok(())
}

fn truncate_brief(mut value: String) -> String {
    if value.len() <= MAX_ERROR_BRIEF_BYTES {
        return value;
    }
    let mut end = MAX_ERROR_BRIEF_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_and_database_ids_are_stable_and_distinct() {
        let first = cron_task_id("w", "* * * * *", 100);
        assert_eq!(first, cron_task_id("w", "* * * * *", 100));
        assert_ne!(first, cron_task_id("w", "*/5 * * * *", 100));
        assert_ne!(first, cron_task_id("w", "* * * * *", 101));
        assert_eq!(database_name("worker-a"), database_name("worker-a"));
        assert_ne!(database_name("worker-a"), database_name("worker-b"));
    }

    #[test]
    fn run_ids_and_error_briefs_are_bounded() {
        let id =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
        assert!(validate_run_id(&id).is_ok());
        assert!(validate_run_id("../../bad").is_err());
        let brief = truncate_brief("错".repeat(200));
        assert!(brief.len() <= MAX_ERROR_BRIEF_BYTES);
        assert!(brief.is_char_boundary(brief.len()));
    }
}
