//! Durable, decentralized Worker Workflows.
//!
//! Definitions are operator-signed resources. Every Workflow owns a small D1
//! quorum containing its instances, replayable step log, signals and audit
//! events. Any node may claim an instance, execute the entrypoint in its local
//! workerd, and renew the fenced lease while user code is running. A node crash
//! therefore releases work through lease expiry; completed steps replay from
//! D1 and are never executed again.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

pub const WORKFLOW_KIND: &str = "workflow";
pub const INTERNAL_WORKFLOW_PATH: &str = "/.rf/internal/workflow";
pub const INTERNAL_EVENT_HEADER: &str = "x-rf-internal-event";
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;
const LEASE_MS: u64 = 5 * 60 * 1_000;
const HEARTBEAT_MS: u64 = 60 * 1_000;
const DRIVER_INTERVAL_MS: u64 = 250;
const MAX_CONCURRENT_ADVANCES: usize = 32;

fn default_retention_days() -> u16 {
    30
}

fn default_instance_retries() -> u16 {
    3
}

fn default_instance_timeout_seconds() -> u64 {
    25 * 60
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSpec {
    #[serde(default)]
    pub description: String,
    pub worker: String,
    #[serde(default = "default_entrypoint")]
    pub entrypoint: String,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub suspend_reason: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: u16,
    #[serde(default = "default_instance_retries")]
    pub instance_retries: u16,
    #[serde(default = "default_instance_timeout_seconds")]
    pub instance_timeout_seconds: u64,
}

fn default_entrypoint() -> String {
    "MyWorkflow".into()
}

impl WorkflowSpec {
    pub fn validate(&self) -> Result<()> {
        if self.description.len() > 2_000 || self.suspend_reason.len() > 2_000 {
            bail!("Workflow 描述或暂停原因不得超过 2000 个字符");
        }
        if !rf_core::manifest::valid_name(&self.worker) {
            bail!("Workflow 执行 Worker 名称无效");
        }
        if !valid_identifier(&self.entrypoint) {
            bail!("Workflow 入口类必须是有效的 JavaScript 标识符");
        }
        if !(1..=365).contains(&self.retention_days) {
            bail!("Workflow 执行记录保留期必须介于 1 和 365 天之间");
        }
        if self.instance_retries > 100 {
            bail!("Workflow 实例系统重试次数不得超过 100");
        }
        if !(30..=12 * 60 * 60).contains(&self.instance_timeout_seconds) {
            bail!("Workflow 单次推进超时必须介于 30 秒和 12 小时之间");
        }
        Ok(())
    }
}

impl Default for WorkflowSpec {
    fn default() -> Self {
        Self {
            description: String::new(),
            worker: "worker".into(),
            entrypoint: default_entrypoint(),
            suspended: false,
            suspend_reason: String::new(),
            retention_days: default_retention_days(),
            instance_retries: default_instance_retries(),
            instance_timeout_seconds: default_instance_timeout_seconds(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstance {
    pub id: String,
    pub instance_key: Option<String>,
    pub input: Value,
    pub output: Option<Value>,
    pub status: String,
    pub waiting_for: Option<String>,
    pub sleep_until_ms: Option<u64>,
    pub last_error: Option<String>,
    pub retry_count: u16,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    pub seq: u64,
    pub kind: String,
    pub status: String,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub wake_at_ms: Option<u64>,
    pub attempts: u16,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSignal {
    pub id: String,
    pub name: String,
    pub payload: Value,
    pub delivered_at_ms: Option<u64>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEvent {
    pub seq: u64,
    pub kind: String,
    pub detail: Value,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStats {
    pub queued: u64,
    pub running: u64,
    pub waiting: u64,
    pub paused: u64,
    pub complete: u64,
    pub failed: u64,
    pub terminated: u64,
}

#[derive(Debug, Clone)]
struct Claim {
    instance: WorkflowInstance,
    lease: String,
}

#[derive(Debug, Clone, Serialize)]
struct AdvanceRequest {
    workflow: String,
    instance_id: String,
    input: Value,
    entrypoint: String,
    lease: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum AdvanceResponse {
    Complete { output: Value },
    Parked,
    Failed { error: String },
}

pub fn workflow_record(node: &Node, name: &str) -> Option<(ResourceView, WorkflowSpec)> {
    let view = resource::head(node, WORKFLOW_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = workflow_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn workflow_records(node: &Node) -> Vec<(ResourceView, WorkflowSpec)> {
    resource::heads(node, Some(WORKFLOW_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| workflow_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn workflow_spec(record: &ResourceRecord) -> Result<WorkflowSpec> {
    if record.kind != WORKFLOW_KIND {
        bail!("平台资源不是 Workflow");
    }
    let spec: WorkflowSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn prepare_workflow_after(
    name: &str,
    spec: WorkflowSpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.validate()?;
    resource::prepare_after(
        WORKFLOW_KIND,
        name,
        serde_json::to_value(spec)?,
        deleted,
        head,
    )
}

pub fn database_name(workflow: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("workflow/{workflow}").as_bytes()));
    format!("workflow-{}", &digest[..32])
}

pub async fn create_instance(
    node: &Node,
    workflow: &str,
    instance_key: Option<&str>,
    input: Value,
) -> Result<WorkflowInstance> {
    let (_, spec) = workflow_record(node, workflow).context("Workflow 不存在")?;
    if spec.suspended {
        bail!("Workflow 已暂停：{}", spec.suspend_reason);
    }
    validate_instance_key(instance_key)?;
    validate_json_size(&input, MAX_INPUT_BYTES, "Workflow 输入")?;
    ensure_schema(node, workflow).await?;
    if let Some(key) = instance_key {
        if let Some(existing) = instance_by_key(node, workflow, key).await? {
            return Ok(existing);
        }
    }
    let id = new_id("wfi");
    let now = now_ms();
    let input_json = serde_json::to_string(&input)?;
    let inserted = exec(
        node,
        workflow,
        r#"INSERT OR IGNORE INTO workflow_instances
           (id, instance_key, input_json, status, sleep_until_ms, retry_count,
            started_at_ms, updated_at_ms)
           VALUES (?1,?2,?3,'queued',?4,0,?4,?4)"#,
        json!([id, instance_key, input_json, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    let instance = if inserted == 1 {
        instance(node, workflow, &id)
            .await?
            .context("Workflow 实例创建后不可见")?
    } else if let Some(key) = instance_key {
        instance_by_key(node, workflow, key)
            .await?
            .context("Workflow 幂等实例创建冲突")?
    } else {
        bail!("Workflow 实例 ID 冲突");
    };
    if inserted == 1 {
        append_event(node, workflow, &instance.id, "created", json!({})).await?;
    }
    Ok(instance)
}

pub async fn instance(node: &Node, workflow: &str, id: &str) -> Result<Option<WorkflowInstance>> {
    ensure_schema(node, workflow).await?;
    rows(
        exec(
            node,
            workflow,
            &format!("SELECT {INSTANCE_FIELDS} FROM workflow_instances WHERE id=?1"),
            json!([id]),
        )
        .await?,
    )
    .first()
    .map(row_to_instance)
    .transpose()
}

async fn instance_by_key(
    node: &Node,
    workflow: &str,
    key: &str,
) -> Result<Option<WorkflowInstance>> {
    rows(
        exec(
            node,
            workflow,
            &format!("SELECT {INSTANCE_FIELDS} FROM workflow_instances WHERE instance_key=?1"),
            json!([key]),
        )
        .await?,
    )
    .first()
    .map(row_to_instance)
    .transpose()
}

pub async fn instances(
    node: &Node,
    workflow: &str,
    status: Option<&str>,
    limit: usize,
) -> Result<Vec<WorkflowInstance>> {
    ensure_schema(node, workflow).await?;
    let (where_sql, params) = if let Some(status) = status {
        validate_status(status)?;
        (" WHERE status=?1", json!([status]))
    } else {
        ("", json!([]))
    };
    rows(
        exec(
            node,
            workflow,
            &format!(
                "SELECT {INSTANCE_FIELDS} FROM workflow_instances{where_sql} ORDER BY started_at_ms DESC LIMIT {}",
                limit.clamp(1, 1_000)
            ),
            params,
        )
        .await?,
    )
    .iter()
    .map(row_to_instance)
    .collect()
}

pub async fn steps(node: &Node, workflow: &str, instance_id: &str) -> Result<Vec<WorkflowStep>> {
    ensure_schema(node, workflow).await?;
    rows(
        exec(
            node,
            workflow,
            r#"SELECT name, seq, kind, status, result_json, error, wake_at_ms,
                      attempts, started_at_ms, finished_at_ms
               FROM workflow_steps WHERE instance_id=?1 ORDER BY seq"#,
            json!([instance_id]),
        )
        .await?,
    )
    .iter()
    .map(row_to_step)
    .collect()
}

pub async fn signals(
    node: &Node,
    workflow: &str,
    instance_id: &str,
) -> Result<Vec<WorkflowSignal>> {
    ensure_schema(node, workflow).await?;
    rows(
        exec(
            node,
            workflow,
            r#"SELECT id, name, payload_json, delivered_at_ms, created_at_ms
               FROM workflow_signals WHERE instance_id=?1 ORDER BY created_at_ms, id"#,
            json!([instance_id]),
        )
        .await?,
    )
    .iter()
    .map(row_to_signal)
    .collect()
}

pub async fn events(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    limit: usize,
) -> Result<Vec<WorkflowEvent>> {
    ensure_schema(node, workflow).await?;
    let mut events = rows(
        exec(
            node,
            workflow,
            &format!(
                r#"SELECT seq, kind, detail_json, created_at_ms FROM workflow_events
                    WHERE instance_id=?1 ORDER BY seq DESC LIMIT {}"#,
                limit.clamp(1, 1_000)
            ),
            json!([instance_id]),
        )
        .await?,
    )
    .iter()
    .map(row_to_event)
    .collect::<Result<Vec<_>>>()?;
    events.reverse();
    Ok(events)
}

pub async fn stats(node: &Node, workflow: &str) -> Result<WorkflowStats> {
    ensure_schema(node, workflow).await?;
    let row = rows(
        exec(
            node,
            workflow,
            r#"SELECT
               SUM(CASE WHEN status='queued' THEN 1 ELSE 0 END) queued,
               SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) running,
               SUM(CASE WHEN status='waiting' THEN 1 ELSE 0 END) waiting,
               SUM(CASE WHEN status='paused' THEN 1 ELSE 0 END) paused,
               SUM(CASE WHEN status='complete' THEN 1 ELSE 0 END) complete,
               SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) failed,
               SUM(CASE WHEN status='terminated' THEN 1 ELSE 0 END) terminated
               FROM workflow_instances"#,
            json!([]),
        )
        .await?,
    )
    .into_iter()
    .next()
    .unwrap_or_else(|| json!({}));
    Ok(WorkflowStats {
        queued: u64_field(&row, "queued"),
        running: u64_field(&row, "running"),
        waiting: u64_field(&row, "waiting"),
        paused: u64_field(&row, "paused"),
        complete: u64_field(&row, "complete"),
        failed: u64_field(&row, "failed"),
        terminated: u64_field(&row, "terminated"),
    })
}

pub async fn pause(node: &Node, workflow: &str, id: &str) -> Result<bool> {
    transition(
        node,
        workflow,
        id,
        "paused",
        "status IN ('queued','running','waiting')",
        "paused",
    )
    .await
}

pub async fn resume(node: &Node, workflow: &str, id: &str) -> Result<bool> {
    transition(node, workflow, id, "queued", "status='paused'", "resumed").await
}

pub async fn terminate(node: &Node, workflow: &str, id: &str) -> Result<bool> {
    let changed = exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status='terminated', waiting_for=NULL,
           sleep_until_ms=NULL, lease_token=NULL, lease_until_ms=NULL,
           finished_at_ms=?2, updated_at_ms=?2
           WHERE id=?1 AND status IN ('queued','running','waiting','paused')"#,
        json!([id, now_ms()]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0)
        == 1;
    if changed {
        append_event(node, workflow, id, "terminated", json!({})).await?;
    }
    Ok(changed)
}

pub async fn restart(node: &Node, workflow: &str, id: &str) -> Result<bool> {
    ensure_schema(node, workflow).await?;
    let now = now_ms();
    // A terminal instance cannot be claimed by the driver, so clear its
    // failed/in-flight boundary before making it runnable again. This keeps
    // the reset atomic from the driver's point of view: it can only observe
    // the old terminal state or the fully-reset queued state.
    exec(
        node,
        workflow,
        r#"DELETE FROM workflow_steps
           WHERE instance_id=?1 AND status IN ('failed','pending')
             AND EXISTS (
               SELECT 1 FROM workflow_instances
               WHERE id=?1 AND status IN ('failed','terminated','complete')
             )"#,
        json!([id]),
    )
    .await?;
    let changed = exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status='queued', output_json=NULL,
           waiting_for=NULL, sleep_until_ms=?2, lease_token=NULL, lease_until_ms=NULL,
           last_error=NULL, finished_at_ms=NULL, updated_at_ms=?2
           WHERE id=?1 AND status IN ('failed','terminated','complete')"#,
        json!([id, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0)
        == 1;
    if changed {
        append_event(node, workflow, id, "restarted", json!({})).await?;
    }
    Ok(changed)
}

pub async fn send_signal(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    name: &str,
    payload: Value,
) -> Result<String> {
    validate_step_name(name)?;
    validate_json_size(&payload, MAX_RESULT_BYTES, "Workflow 信号")?;
    let instance = instance(node, workflow, instance_id)
        .await?
        .context("Workflow 实例不存在")?;
    if matches!(
        instance.status.as_str(),
        "complete" | "failed" | "terminated"
    ) {
        bail!("终态 Workflow 实例不能接收信号");
    }
    let id = new_id("sig");
    let now = now_ms();
    let inserted = exec(
        node,
        workflow,
        r#"INSERT INTO workflow_signals
           (id, instance_id, name, payload_json, created_at_ms)
           SELECT ?1,?2,?3,?4,?5 FROM workflow_instances
           WHERE id=?2 AND status NOT IN ('complete','failed','terminated')"#,
        json!([id, instance_id, name, serde_json::to_string(&payload)?, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if inserted != 1 {
        bail!("Workflow 实例不存在或已进入终态");
    }
    exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status='queued', waiting_for=NULL,
           sleep_until_ms=?2, updated_at_ms=?2
           WHERE id=?1 AND status='waiting' AND (waiting_for=?3 OR waiting_for IS NULL)"#,
        json!([instance_id, now, name]),
    )
    .await?;
    append_event(
        node,
        workflow,
        instance_id,
        "signal_received",
        json!({ "name": name, "signal_id": id }),
    )
    .await?;
    Ok(id)
}

async fn transition(
    node: &Node,
    workflow: &str,
    id: &str,
    target: &str,
    guard: &str,
    event: &str,
) -> Result<bool> {
    ensure_schema(node, workflow).await?;
    let now = now_ms();
    let affected = exec(
        node,
        workflow,
        &format!(
            "UPDATE workflow_instances SET status=?2, sleep_until_ms=CASE WHEN ?2='queued' THEN ?3 ELSE sleep_until_ms END, lease_token=NULL, lease_until_ms=NULL, updated_at_ms=?3 WHERE id=?1 AND {guard}"
        ),
        json!([id, target, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if affected == 1 {
        append_event(node, workflow, id, event, json!({})).await?;
    }
    Ok(affected == 1)
}

pub(crate) async fn step_lookup(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    lease: &str,
    name: &str,
) -> Result<Value> {
    validate_step_request(node, workflow, instance_id, lease, name).await?;
    let existing = rows(
        exec(
            node,
            workflow,
            "SELECT status, result_json, error FROM workflow_steps WHERE instance_id=?1 AND name=?2",
            json!([instance_id, name]),
        )
        .await?,
    )
    .into_iter()
    .next();
    let Some(row) = existing else {
        return Ok(json!({ "cached": false }));
    };
    match string_field(&row, "status")? {
        "ok" => Ok(json!({
            "cached": true,
            "result": json_string_field(&row, "result_json")?.unwrap_or(Value::Null),
        })),
        "failed" => Ok(json!({
            "cached": false,
            "already_failed": true,
            "error": row["error"].as_str().unwrap_or("未知步骤错误"),
        })),
        _ => Ok(json!({ "cached": false })),
    }
}

pub(crate) struct StepOutcome<'a> {
    pub status: &'a str,
    pub result: Option<Value>,
    pub error: Option<&'a str>,
    pub attempts: u16,
}

pub(crate) async fn step_record(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    lease: &str,
    name: &str,
    outcome: StepOutcome<'_>,
) -> Result<()> {
    let StepOutcome {
        status,
        result,
        error,
        attempts,
    } = outcome;
    validate_step_request(node, workflow, instance_id, lease, name).await?;
    if !matches!(status, "ok" | "failed") {
        bail!("Workflow 步骤状态无效");
    }
    if let Some(result) = &result {
        validate_json_size(result, MAX_RESULT_BYTES, "Workflow 步骤结果")?;
    }
    let now = now_ms();
    let error = error.map(truncate_error);
    let result_json = result.as_ref().map(serde_json::to_string).transpose()?;
    let affected = exec(
        node,
        workflow,
        r#"INSERT INTO workflow_steps
           (instance_id,name,seq,kind,status,result_json,error,attempts,started_at_ms,finished_at_ms)
           SELECT ?1,?2,COALESCE(MAX(seq),0)+1,'do',?3,?4,?5,?6,?7,?7
           FROM workflow_steps WHERE instance_id=?1
           HAVING EXISTS (SELECT 1 FROM workflow_instances
                          WHERE id=?1 AND status='running' AND lease_token=?8)
           ON CONFLICT(instance_id,name) DO UPDATE SET
             status=excluded.status, result_json=excluded.result_json,
             error=excluded.error, attempts=excluded.attempts,
             finished_at_ms=excluded.finished_at_ms
           WHERE workflow_steps.status!='ok'"#,
        json!([
            instance_id,
            name,
            status,
            result_json,
            error,
            attempts,
            now,
            lease
        ]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if affected == 0 {
        // A committed response may be retried after its HTTP response was
        // lost. Treat that exact durable boundary as success, but reject a
        // stale lease or an attempt to reuse a step name for new data.
        let existing = rows(
            exec(
                node,
                workflow,
                "SELECT status,result_json,error FROM workflow_steps WHERE instance_id=?1 AND name=?2",
                json!([instance_id, name]),
            )
            .await?,
        )
        .into_iter()
        .next();
        let idempotent = existing.as_ref().is_some_and(|row| {
            row["status"].as_str() == Some(status)
                && row["result_json"].as_str() == result_json.as_deref()
                && row["error"].as_str() == error.as_deref()
        });
        if idempotent {
            return Ok(());
        }
        bail!("Workflow 推进租约已失效，或步骤名称已被其他结果占用");
    }
    append_event(
        node,
        workflow,
        instance_id,
        if status == "ok" {
            "step_complete"
        } else {
            "step_failed"
        },
        json!({ "name": name, "attempts": attempts }),
    )
    .await?;
    Ok(())
}

pub(crate) async fn step_sleep(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    lease: &str,
    name: &str,
    duration_ms: u64,
) -> Result<Value> {
    validate_step_request(node, workflow, instance_id, lease, name).await?;
    let proposed_wake = now_ms().saturating_add(duration_ms.min(365 * 24 * 60 * 60 * 1_000));
    exec(
        node,
        workflow,
        r#"INSERT INTO workflow_steps
           (instance_id,name,seq,kind,status,wake_at_ms,attempts,started_at_ms)
           SELECT ?1,?2,COALESCE(MAX(seq),0)+1,'sleep','slept',?3,1,?4
           FROM workflow_steps WHERE instance_id=?1
           HAVING EXISTS (SELECT 1 FROM workflow_instances
                          WHERE id=?1 AND status='running' AND lease_token=?5)
           ON CONFLICT(instance_id,name) DO NOTHING"#,
        json!([instance_id, name, proposed_wake, now_ms(), lease]),
    )
    .await?;
    let row = rows(
        exec(
            node,
            workflow,
            "SELECT kind,status,wake_at_ms FROM workflow_steps WHERE instance_id=?1 AND name=?2",
            json!([instance_id, name]),
        )
        .await?,
    )
    .into_iter()
    .next()
    .context("Workflow 推进租约已失效")?;
    if string_field(&row, "kind")? != "sleep" || string_field(&row, "status")? != "slept" {
        bail!("Workflow 步骤名称已被其他类型占用");
    }
    let wake_at = optional_u64_field(&row, "wake_at_ms").context("睡眠步骤缺少唤醒时间")?;
    if wake_at <= now_ms() {
        exec(
            node,
            workflow,
            "UPDATE workflow_steps SET finished_at_ms=?3 WHERE instance_id=?1 AND name=?2",
            json!([instance_id, name, now_ms()]),
        )
        .await?;
        return Ok(json!({ "status": "wake" }));
    }
    let parked = park(
        node,
        workflow,
        instance_id,
        lease,
        "waiting",
        Some(wake_at),
        Some(name),
    )
    .await?;
    if !parked {
        bail!("Workflow 推进租约已失效");
    }
    append_event(
        node,
        workflow,
        instance_id,
        "sleep",
        json!({ "name": name, "wake_at_ms": wake_at }),
    )
    .await?;
    Ok(json!({ "status": "sleep", "wake_at_ms": wake_at }))
}

pub(crate) async fn step_signal(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    lease: &str,
    name: &str,
) -> Result<Value> {
    validate_step_request(node, workflow, instance_id, lease, name).await?;
    loop {
        let signal = rows(
            exec(
                node,
                workflow,
                r#"SELECT id,payload_json FROM workflow_signals
                   WHERE instance_id=?1 AND name=?2 AND delivered_at_ms IS NULL
                   ORDER BY created_at_ms,id LIMIT 1"#,
                json!([instance_id, name]),
            )
            .await?,
        )
        .into_iter()
        .next();
        let Some(signal) = signal else {
            let parked = park(
                node,
                workflow,
                instance_id,
                lease,
                "waiting",
                None,
                Some(name),
            )
            .await?;
            if !parked {
                bail!("Workflow 推进租约已失效");
            }
            // Close the classic signal-before-park race. A sender may have
            // committed the signal after our SELECT but while the instance
            // was still running, in which case it could not wake a `waiting`
            // row. Re-check inside the quorum ledger after parking; a sender
            // racing after this UPDATE will itself observe `waiting` and wake
            // the instance, so every interleaving is covered.
            let woke = exec(
                node,
                workflow,
                r#"UPDATE workflow_instances SET status='queued',waiting_for=NULL,
                   sleep_until_ms=?3,updated_at_ms=?3
                   WHERE id=?1 AND status='waiting' AND waiting_for=?2
                     AND EXISTS (SELECT 1 FROM workflow_signals
                                 WHERE instance_id=?1 AND name=?2
                                   AND delivered_at_ms IS NULL)"#,
                json!([instance_id, name, now_ms()]),
            )
            .await?["rows_affected"]
                .as_u64()
                .unwrap_or(0)
                == 1;
            append_event(
                node,
                workflow,
                instance_id,
                "signal_wait",
                json!({ "name": name }),
            )
            .await?;
            if woke {
                append_event(
                    node,
                    workflow,
                    instance_id,
                    "signal_ready",
                    json!({ "name": name }),
                )
                .await?;
            }
            return Ok(json!({ "status": "wait" }));
        };
        let signal_id = string_field(&signal, "id")?;
        let delivered = exec(
            node,
            workflow,
            r#"UPDATE workflow_signals SET delivered_at_ms=?2
               WHERE id=?1 AND delivered_at_ms IS NULL
                 AND EXISTS (SELECT 1 FROM workflow_instances
                             WHERE id=?3 AND status='running' AND lease_token=?4)"#,
            json!([signal_id, now_ms(), instance_id, lease]),
        )
        .await?["rows_affected"]
            .as_u64()
            .unwrap_or(0);
        if delivered == 0 {
            validate_step_request(node, workflow, instance_id, lease, name).await?;
            continue;
        }
        let payload = json_string_field(&signal, "payload_json")?.unwrap_or(Value::Null);
        append_event(
            node,
            workflow,
            instance_id,
            "signal_delivered",
            json!({ "name": name, "signal_id": signal_id }),
        )
        .await?;
        return Ok(json!({ "status": "delivered", "payload": payload }));
    }
}

async fn validate_step_request(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    lease: &str,
    name: &str,
) -> Result<()> {
    validate_step_name(name)?;
    let valid = !rows(
        exec(
            node,
            workflow,
            "SELECT 1 AS valid FROM workflow_instances WHERE id=?1 AND status='running' AND lease_token=?2",
            json!([instance_id, lease]),
        )
        .await?,
    )
    .is_empty();
    if !valid {
        bail!("Workflow 推进租约已失效");
    }
    Ok(())
}

async fn park(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    lease: &str,
    status: &str,
    sleep_until_ms: Option<u64>,
    waiting_for: Option<&str>,
) -> Result<bool> {
    Ok(exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status=?3, sleep_until_ms=?4,
           waiting_for=?5, lease_token=NULL, lease_until_ms=NULL, updated_at_ms=?6
           WHERE id=?1 AND status='running' AND lease_token=?2"#,
        json!([
            instance_id,
            lease,
            status,
            sleep_until_ms,
            waiting_for,
            now_ms()
        ]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0)
        == 1)
}

async fn claim_one(node: &Node, workflow: &str) -> Result<Option<Claim>> {
    ensure_schema(node, workflow).await?;
    let now = now_ms();
    // An expired runner is safe to replay because every completed step is
    // durable. Paused/terminated rows are deliberately untouched.
    exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status='queued', lease_token=NULL,
           lease_until_ms=NULL, sleep_until_ms=?1, updated_at_ms=?1
           WHERE status='running' AND lease_until_ms<=?1"#,
        json!([now]),
    )
    .await?;
    let candidate = rows(
        exec(
            node,
            workflow,
            r#"SELECT id FROM workflow_instances
               WHERE status IN ('queued','waiting')
                 AND sleep_until_ms IS NOT NULL AND sleep_until_ms<=?1
               ORDER BY sleep_until_ms,started_at_ms LIMIT 1"#,
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
    let claimed = exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status='running', waiting_for=NULL,
           lease_token=?2, lease_until_ms=?3, updated_at_ms=?4
           WHERE id=?1 AND status IN ('queued','waiting')
             AND sleep_until_ms IS NOT NULL AND sleep_until_ms<=?4"#,
        json!([id, lease, now.saturating_add(LEASE_MS), now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if claimed != 1 {
        return Ok(None);
    }
    let instance = instance(node, workflow, &id)
        .await?
        .context("已认领的 Workflow 实例不可见")?;
    append_event(
        node,
        workflow,
        &id,
        "advance_claimed",
        json!({ "node": node.id().to_string() }),
    )
    .await?;
    Ok(Some(Claim { instance, lease }))
}

async fn renew(node: &Node, workflow: &str, id: &str, lease: &str) -> Result<bool> {
    Ok(exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET lease_until_ms=?3,updated_at_ms=?4
           WHERE id=?1 AND status='running' AND lease_token=?2"#,
        json!([id, lease, now_ms().saturating_add(LEASE_MS), now_ms()]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0)
        == 1)
}

async fn finish(node: &Node, workflow: &str, id: &str, lease: &str, output: Value) -> Result<()> {
    validate_json_size(&output, MAX_RESULT_BYTES, "Workflow 输出")?;
    let now = now_ms();
    let changed = exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status='complete',output_json=?3,
           waiting_for=NULL,sleep_until_ms=NULL,lease_token=NULL,lease_until_ms=NULL,
           last_error=NULL,finished_at_ms=?4,updated_at_ms=?4
           WHERE id=?1 AND status='running' AND lease_token=?2"#,
        json!([id, lease, serde_json::to_string(&output)?, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if changed == 1 {
        append_event(node, workflow, id, "complete", json!({})).await?;
    }
    Ok(())
}

async fn fail_terminal(
    node: &Node,
    workflow: &str,
    id: &str,
    lease: &str,
    error: &str,
) -> Result<()> {
    let error = truncate_error(error);
    let now = now_ms();
    let changed = exec(
        node,
        workflow,
        r#"UPDATE workflow_instances SET status='failed',last_error=?3,
           waiting_for=NULL,sleep_until_ms=NULL,lease_token=NULL,lease_until_ms=NULL,
           finished_at_ms=?4,updated_at_ms=?4
           WHERE id=?1 AND status='running' AND lease_token=?2"#,
        json!([id, lease, error, now]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if changed == 1 {
        append_event(node, workflow, id, "failed", json!({ "error": error })).await?;
    }
    Ok(())
}

async fn fail_system(
    node: &Node,
    workflow: &str,
    spec: &WorkflowSpec,
    id: &str,
    lease: &str,
    error: &str,
) -> Result<()> {
    let current = instance(node, workflow, id)
        .await?
        .context("Workflow 实例不存在")?;
    let error = truncate_error(error);
    let now = now_ms();
    if current.retry_count < spec.instance_retries {
        let retry_count = current.retry_count + 1;
        let backoff = (1u64 << retry_count.min(8)) * 1_000;
        let changed = exec(
            node,
            workflow,
            r#"UPDATE workflow_instances SET status='queued',retry_count=?3,
               last_error=?4,sleep_until_ms=?5,lease_token=NULL,lease_until_ms=NULL,
               updated_at_ms=?6
               WHERE id=?1 AND status='running' AND lease_token=?2"#,
            json!([
                id,
                lease,
                retry_count,
                error,
                now.saturating_add(backoff),
                now
            ]),
        )
        .await?["rows_affected"]
            .as_u64()
            .unwrap_or(0);
        if changed == 1 {
            append_event(
                node,
                workflow,
                id,
                "system_retry",
                json!({ "error": error, "retry": retry_count, "backoff_ms": backoff }),
            )
            .await?;
        }
    } else {
        fail_terminal(node, workflow, id, lease, &error).await?;
    }
    Ok(())
}

async fn advance(node: Arc<Node>, workflow: String, spec: WorkflowSpec, claim: Claim) {
    let result = dispatch(&node, &workflow, &spec, &claim).await;
    match result {
        Ok(AdvanceResponse::Complete { output }) => {
            if let Err(error) =
                finish(&node, &workflow, &claim.instance.id, &claim.lease, output).await
            {
                tracing::warn!(
                    "完成 Workflow {workflow}/{} 失败：{error:#}",
                    claim.instance.id
                );
            }
        }
        Ok(AdvanceResponse::Parked) => {
            // The step operation already moved the instance to waiting and
            // released its lease. If it did not, release it as a system retry.
            if instance(&node, &workflow, &claim.instance.id)
                .await
                .ok()
                .flatten()
                .is_some_and(|instance| instance.status == "running")
            {
                let _ = fail_system(
                    &node,
                    &workflow,
                    &spec,
                    &claim.instance.id,
                    &claim.lease,
                    "Workflow 返回 parked，但没有持久化等待边界",
                )
                .await;
            }
        }
        Ok(AdvanceResponse::Failed { error }) => {
            let _ = fail_terminal(&node, &workflow, &claim.instance.id, &claim.lease, &error).await;
        }
        Err(error) => {
            let _ = fail_system(
                &node,
                &workflow,
                &spec,
                &claim.instance.id,
                &claim.lease,
                &format!("{error:#}"),
            )
            .await;
        }
    }
}

async fn dispatch(
    node: &Arc<Node>,
    workflow: &str,
    spec: &WorkflowSpec,
    claim: &Claim,
) -> Result<AdvanceResponse> {
    let port = node
        .worker_port(&spec.worker)
        .context("Workflow 执行 Worker 未在当前节点运行")?;
    let event_token = node
        .worker_event_token(&spec.worker)
        .context("Workflow 执行 Worker 内部事件令牌未就绪")?;
    let request = AdvanceRequest {
        workflow: workflow.into(),
        instance_id: claim.instance.id.clone(),
        input: claim.instance.input.clone(),
        entrypoint: spec.entrypoint.clone(),
        lease: claim.lease.clone(),
    };
    let timeout = Duration::from_secs(spec.instance_timeout_seconds);
    let client = reqwest::Client::builder().timeout(timeout).build()?;
    let (done_tx, mut done_rx) = tokio::sync::watch::channel(false);
    let heartbeat_node = node.clone();
    let heartbeat_workflow = workflow.to_string();
    let heartbeat_id = claim.instance.id.clone();
    let heartbeat_lease = claim.lease.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)) => {
                    match renew(&heartbeat_node, &heartbeat_workflow, &heartbeat_id, &heartbeat_lease).await {
                        Ok(true) => {}
                        _ => break,
                    }
                }
                changed = done_rx.changed() => {
                    if changed.is_err() || *done_rx.borrow() { break; }
                }
            }
        }
    });
    let response = client
        .post(format!("http://127.0.0.1:{port}{INTERNAL_WORKFLOW_PATH}"))
        .header(INTERNAL_EVENT_HEADER, event_token)
        .json(&request)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let _ = done_tx.send(true);
            heartbeat.abort();
            return Err(error.into());
        }
    };
    let status = response.status();
    let body = response.bytes().await;
    let _ = done_tx.send(true);
    heartbeat.abort();
    let body = body?;
    if body.len() > MAX_RESULT_BYTES + 64 * 1024 {
        bail!("Workflow 执行响应超过 4 MiB");
    }
    if !status.is_success() {
        bail!(
            "Workflow workerd 返回 {status}：{}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(4_000)
                .collect::<String>()
        );
    }
    serde_json::from_slice(&body).context("Workflow workerd 响应无效")
}

pub fn spawn_driver(node: Arc<Node>) {
    tokio::spawn(async move {
        let advances = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_ADVANCES));
        let mut last_gc = 0u64;
        loop {
            for (view, spec) in workflow_records(&node) {
                if spec.suspended || node.worker_port(&spec.worker).is_none() {
                    continue;
                }
                let Ok(permit) = advances.clone().try_acquire_owned() else {
                    break;
                };
                match claim_one(&node, &view.resource.name).await {
                    Ok(Some(claim)) => {
                        let node = node.clone();
                        let workflow = view.resource.name;
                        tokio::spawn(async move {
                            let _permit = permit;
                            advance(node, workflow, spec, claim).await;
                        });
                    }
                    Ok(None) => drop(permit),
                    Err(error) => {
                        drop(permit);
                        tracing::debug!("认领 Workflow {} 失败：{error:#}", view.resource.name);
                    }
                }
            }
            if now_ms().saturating_sub(last_gc) >= 60 * 60 * 1_000 {
                last_gc = now_ms();
                for (view, spec) in workflow_records(&node) {
                    let cutoff = now_ms().saturating_sub(spec.retention_days as u64 * 86_400_000);
                    let _ = exec(
                        &node,
                        &view.resource.name,
                        "DELETE FROM workflow_instances WHERE finished_at_ms IS NOT NULL AND finished_at_ms<?1",
                        json!([cutoff]),
                    )
                    .await;
                }
            }
            tokio::time::sleep(Duration::from_millis(DRIVER_INTERVAL_MS)).await;
        }
    });
}

async fn append_event(
    node: &Node,
    workflow: &str,
    instance_id: &str,
    kind: &str,
    detail: Value,
) -> Result<()> {
    let result = exec(
        node,
        workflow,
        r#"INSERT INTO workflow_events(instance_id,seq,kind,detail_json,created_at_ms)
           SELECT ?1,COALESCE(MAX(seq),0)+1,?2,?3,?4
           FROM workflow_events WHERE instance_id=?1"#,
        json!([instance_id, kind, serde_json::to_string(&detail)?, now_ms()]),
    )
    .await?;
    if result["rows_affected"].as_u64().unwrap_or(0) != 1 {
        bail!("Workflow 审计事件未能持久化");
    }
    Ok(())
}

async fn ensure_schema(node: &Node, workflow: &str) -> Result<()> {
    let database = database_name(workflow);
    d1::ensure_database(node, &database)?;
    if node.workflow_schema_ready(&database) {
        return Ok(());
    }
    for sql in [
        r#"CREATE TABLE IF NOT EXISTS workflow_instances (
             id TEXT PRIMARY KEY,
             instance_key TEXT UNIQUE,
             input_json TEXT NOT NULL,
             output_json TEXT,
             status TEXT NOT NULL,
             waiting_for TEXT,
             sleep_until_ms INTEGER,
             lease_token TEXT,
             lease_until_ms INTEGER,
             last_error TEXT,
             retry_count INTEGER NOT NULL DEFAULT 0,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER,
             updated_at_ms INTEGER NOT NULL
           )"#,
        "CREATE INDEX IF NOT EXISTS workflow_instances_due ON workflow_instances(status,sleep_until_ms,started_at_ms)",
        "CREATE INDEX IF NOT EXISTS workflow_instances_started ON workflow_instances(started_at_ms DESC)",
        r#"CREATE TABLE IF NOT EXISTS workflow_steps (
             instance_id TEXT NOT NULL,
             name TEXT NOT NULL,
             seq INTEGER NOT NULL,
             kind TEXT NOT NULL,
             status TEXT NOT NULL,
             result_json TEXT,
             error TEXT,
             wake_at_ms INTEGER,
             attempts INTEGER NOT NULL DEFAULT 1,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER,
             PRIMARY KEY(instance_id,name),
             UNIQUE(instance_id,seq),
             FOREIGN KEY(instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE
           )"#,
        "CREATE INDEX IF NOT EXISTS workflow_steps_seq ON workflow_steps(instance_id,seq)",
        r#"CREATE TABLE IF NOT EXISTS workflow_signals (
             id TEXT PRIMARY KEY,
             instance_id TEXT NOT NULL,
             name TEXT NOT NULL,
             payload_json TEXT NOT NULL,
             delivered_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE
           )"#,
        "CREATE INDEX IF NOT EXISTS workflow_signals_ready ON workflow_signals(instance_id,name,delivered_at_ms,created_at_ms)",
        r#"CREATE TABLE IF NOT EXISTS workflow_events (
             instance_id TEXT NOT NULL,
             seq INTEGER NOT NULL,
             kind TEXT NOT NULL,
             detail_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             PRIMARY KEY(instance_id,seq),
             FOREIGN KEY(instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE
           )"#,
    ] {
        exec_database(node, &database, sql, json!([])).await?;
    }
    node.mark_workflow_schema_ready(database);
    Ok(())
}

async fn exec(node: &Node, workflow: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &database_name(workflow), sql, params).await
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

const INSTANCE_FIELDS: &str = "id,instance_key,input_json,output_json,status,waiting_for,sleep_until_ms,last_error,retry_count,started_at_ms,finished_at_ms,updated_at_ms";

fn rows(result: Value) -> Vec<Value> {
    result["rows"].as_array().cloned().unwrap_or_default()
}

fn row_to_instance(row: &Value) -> Result<WorkflowInstance> {
    Ok(WorkflowInstance {
        id: string_field(row, "id")?.into(),
        instance_key: optional_string_field(row, "instance_key"),
        input: json_string_field(row, "input_json")?.context("Workflow 输入为空")?,
        output: json_string_field(row, "output_json")?,
        status: string_field(row, "status")?.into(),
        waiting_for: optional_string_field(row, "waiting_for"),
        sleep_until_ms: optional_u64_field(row, "sleep_until_ms"),
        last_error: optional_string_field(row, "last_error"),
        retry_count: u64_field(row, "retry_count") as u16,
        started_at_ms: u64_field(row, "started_at_ms"),
        finished_at_ms: optional_u64_field(row, "finished_at_ms"),
        updated_at_ms: u64_field(row, "updated_at_ms"),
    })
}

fn row_to_step(row: &Value) -> Result<WorkflowStep> {
    Ok(WorkflowStep {
        name: string_field(row, "name")?.into(),
        seq: u64_field(row, "seq"),
        kind: string_field(row, "kind")?.into(),
        status: string_field(row, "status")?.into(),
        result: json_string_field(row, "result_json")?,
        error: optional_string_field(row, "error"),
        wake_at_ms: optional_u64_field(row, "wake_at_ms"),
        attempts: u64_field(row, "attempts") as u16,
        started_at_ms: u64_field(row, "started_at_ms"),
        finished_at_ms: optional_u64_field(row, "finished_at_ms"),
    })
}

fn row_to_signal(row: &Value) -> Result<WorkflowSignal> {
    Ok(WorkflowSignal {
        id: string_field(row, "id")?.into(),
        name: string_field(row, "name")?.into(),
        payload: json_string_field(row, "payload_json")?.unwrap_or(Value::Null),
        delivered_at_ms: optional_u64_field(row, "delivered_at_ms"),
        created_at_ms: u64_field(row, "created_at_ms"),
    })
}

fn row_to_event(row: &Value) -> Result<WorkflowEvent> {
    Ok(WorkflowEvent {
        seq: u64_field(row, "seq"),
        kind: string_field(row, "kind")?.into(),
        detail: json_string_field(row, "detail_json")?.unwrap_or_else(|| json!({})),
        created_at_ms: u64_field(row, "created_at_ms"),
    })
}

fn string_field<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Workflow 数据库行缺少 {field}"))
}

fn optional_string_field(row: &Value, field: &str) -> Option<String> {
    row.get(field).and_then(Value::as_str).map(str::to_string)
}

fn json_string_field(row: &Value, field: &str) -> Result<Option<Value>> {
    row.get(field)
        .and_then(Value::as_str)
        .map(serde_json::from_str)
        .transpose()
        .with_context(|| format!("Workflow 字段 {field} 不是有效 JSON"))
}

fn u64_field(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn optional_u64_field(row: &Value, field: &str) -> Option<u64> {
    row.get(field).and_then(Value::as_u64)
}

fn new_id(prefix: &str) -> String {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
    format!("{prefix}_{raw}")
}

fn validate_instance_key(key: Option<&str>) -> Result<()> {
    if key.is_some_and(|key| {
        key.is_empty() || key.len() > 256 || key.bytes().any(|byte| byte.is_ascii_control())
    }) {
        bail!("Workflow 幂等键必须介于 1 和 256 个字符之间，且不得包含控制字符");
    }
    Ok(())
}

fn validate_step_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 256 || name.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("Workflow 步骤或信号名称必须介于 1 和 256 个字符之间");
    }
    Ok(())
}

fn validate_status(status: &str) -> Result<()> {
    if !matches!(
        status,
        "queued" | "running" | "waiting" | "paused" | "complete" | "failed" | "terminated"
    ) {
        bail!("Workflow 实例状态筛选无效");
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && value.len() <= 128
}

fn validate_json_size(value: &Value, max: usize, label: &str) -> Result<()> {
    if serde_json::to_vec(value)?.len() > max {
        bail!("{label}不得超过 {} MiB", max / 1024 / 1024);
    }
    Ok(())
}

fn truncate_error(error: &str) -> String {
    error.chars().take(4_000).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_validation_covers_worker_entrypoint_and_limits() {
        let good = WorkflowSpec {
            worker: "orders-worker".into(),
            entrypoint: "OrderWorkflow".into(),
            ..Default::default()
        };
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.entrypoint = "not-a-class".into();
        assert!(bad.validate().is_err());
        bad = good;
        bad.instance_timeout_seconds = 1;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn database_names_are_stable_and_private() {
        assert_eq!(database_name("orders"), database_name("orders"));
        assert_ne!(database_name("orders"), database_name("billing"));
        assert!(database_name("orders").starts_with("workflow-"));
    }

    #[test]
    fn instance_keys_and_names_are_bounded() {
        assert!(validate_instance_key(Some("order-123")).is_ok());
        assert!(validate_instance_key(Some("")).is_err());
        assert!(validate_step_name("charge-card").is_ok());
        assert!(validate_step_name("bad\nname").is_err());
    }
}
