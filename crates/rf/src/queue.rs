//! Decentralized, Cloudflare-shaped message queues.
//!
//! Queue definitions are operator-signed resources. Each queue gets an
//! independent D1 micro-quorum which owns ready/inflight/dead-letter state.
//! Consumers on multiple nodes may race, but a quorum-committed lease means
//! only one delivery receives a given message until its visibility timeout.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

pub const QUEUE_KIND: &str = "queue";
pub const MAX_MESSAGE_BYTES: usize = 128 * 1024;
pub const MAX_BATCH_MESSAGES: usize = 100;
pub const MAX_DELAY_SECONDS: u64 = 12 * 60 * 60;
pub const INTERNAL_QUEUE_PATH: &str = "/.rf/internal/queue";
pub const INTERNAL_EVENT_HEADER: &str = "x-rf-internal-event";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueSpec {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub consumer_worker: Option<String>,
    #[serde(default = "default_batch_size")]
    pub batch_size: u16,
    #[serde(default = "default_max_wait_ms")]
    pub max_wait_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u16,
    #[serde(default = "default_visibility_timeout_ms")]
    pub visibility_timeout_ms: u64,
    #[serde(default = "default_retention_seconds")]
    pub retention_seconds: u64,
    #[serde(default)]
    pub dead_letter_queue: Option<String>,
    #[serde(default)]
    pub suspended: bool,
}

fn default_batch_size() -> u16 {
    10
}
fn default_max_wait_ms() -> u64 {
    5_000
}
fn default_max_retries() -> u16 {
    3
}
fn default_visibility_timeout_ms() -> u64 {
    120_000
}
fn default_retention_seconds() -> u64 {
    7 * 24 * 60 * 60
}

impl Default for QueueSpec {
    fn default() -> Self {
        Self {
            description: String::new(),
            consumer_worker: None,
            batch_size: default_batch_size(),
            max_wait_ms: default_max_wait_ms(),
            max_retries: default_max_retries(),
            visibility_timeout_ms: default_visibility_timeout_ms(),
            retention_seconds: default_retention_seconds(),
            dead_letter_queue: None,
            suspended: false,
        }
    }
}

impl QueueSpec {
    pub fn validate(&self, queue_name: Option<&str>) -> Result<()> {
        if self.description.len() > 2_000 {
            bail!("队列描述不得超过 2000 个字符");
        }
        if let Some(worker) = &self.consumer_worker {
            if !rf_core::manifest::valid_name(worker) {
                bail!("队列消费者 Worker 名称无效");
            }
        }
        if !(1..=MAX_BATCH_MESSAGES as u16).contains(&self.batch_size) {
            bail!("队列批量大小必须介于 1 和 100 之间");
        }
        if !(100..=60_000).contains(&self.max_wait_ms) {
            bail!("队列最长批处理等待时间必须介于 100 毫秒和 60 秒之间");
        }
        if self.max_retries > 100 {
            bail!("队列最大重试次数不得超过 100");
        }
        if !(1_000..=12 * 60 * 60 * 1_000).contains(&self.visibility_timeout_ms) {
            bail!("队列可见性超时必须介于 1 秒和 12 小时之间");
        }
        if !(60..=14 * 24 * 60 * 60).contains(&self.retention_seconds) {
            bail!("队列保留时间必须介于 60 秒和 14 天之间");
        }
        if let Some(dead_letter) = &self.dead_letter_queue {
            if !rf_core::manifest::valid_name(dead_letter) {
                bail!("死信队列名称无效");
            }
            if queue_name == Some(dead_letter) {
                bail!("队列不能把自己设为死信队列");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMessage {
    pub id: String,
    pub body: Value,
    pub produced_at_ms: u64,
    /// Delivery attempt number, starting at one.
    pub attempts: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetter {
    pub id: String,
    pub body: Value,
    pub produced_at_ms: u64,
    pub dead_letter_at_ms: u64,
    pub attempts: u16,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    pub ready: u64,
    pub inflight: u64,
    pub dead_letters: u64,
    pub total_produced: u64,
    pub total_consumed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendMessage {
    pub body: Value,
    #[serde(default)]
    pub delay_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryBatch {
    pub queue: String,
    pub messages: Vec<QueueMessage>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryResult {
    #[serde(default)]
    pub actions: Vec<MessageAction>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAction {
    pub id: String,
    pub action: String,
    #[serde(default)]
    pub delay_seconds: u64,
    #[serde(default)]
    pub error: Option<String>,
}

pub fn queue_record(node: &Node, name: &str) -> Option<(ResourceView, QueueSpec)> {
    let view = resource::head(node, QUEUE_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = queue_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn queue_records(node: &Node) -> Vec<(ResourceView, QueueSpec)> {
    resource::heads(node, Some(QUEUE_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| queue_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn queue_spec(record: &ResourceRecord) -> Result<QueueSpec> {
    if record.kind != QUEUE_KIND {
        bail!("平台资源不是队列");
    }
    let spec: QueueSpec = serde_json::from_value(record.spec()?)?;
    spec.validate(Some(&record.name))?;
    Ok(spec)
}

pub fn prepare_queue(
    node: &Node,
    name: &str,
    spec: QueueSpec,
    deleted: bool,
) -> Result<ResourceRecord> {
    spec.validate(Some(name))?;
    resource::prepare(node, QUEUE_KIND, name, serde_json::to_value(spec)?, deleted)
}

pub fn prepare_queue_after(
    name: &str,
    spec: QueueSpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.validate(Some(name))?;
    resource::prepare_after(QUEUE_KIND, name, serde_json::to_value(spec)?, deleted, head)
}

pub fn database_name(queue: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("queue/{queue}").as_bytes()));
    format!("queue-{}", &digest[..32])
}

pub async fn enqueue(node: &Node, queue: &str, messages: Vec<SendMessage>) -> Result<Vec<String>> {
    let (_, spec) = queue_record(node, queue).context("队列不存在")?;
    if messages.is_empty() || messages.len() > MAX_BATCH_MESSAGES {
        bail!("每次必须发送 1 至 100 条队列消息");
    }
    let now = now_ms();
    let mut entries = Vec::with_capacity(messages.len());
    for message in messages {
        if message.delay_seconds > MAX_DELAY_SECONDS {
            bail!("队列消息延迟不得超过 12 小时");
        }
        validate_body(&message.body)?;
        entries.push((
            new_message_id(),
            message.body,
            now,
            now.saturating_add(message.delay_seconds.saturating_mul(1_000)),
        ));
    }
    ensure_schema(node, queue).await?;
    insert_messages(node, queue, &entries).await?;
    increment_counter(node, queue, "total_produced", entries.len() as u64).await?;
    let _ = spec;
    Ok(entries.into_iter().map(|entry| entry.0).collect())
}

async fn enqueue_existing(
    node: &Node,
    queue: &str,
    id: &str,
    body: Value,
    produced_at_ms: u64,
) -> Result<()> {
    queue_record(node, queue).context("死信目标队列不存在")?;
    validate_body(&body)?;
    ensure_schema(node, queue).await?;
    let inserted = exec(
        node,
        queue,
        r#"INSERT OR IGNORE INTO queue_messages
           (id, body_json, produced_at_ms, available_at_ms, attempts)
           VALUES (?1, ?2, ?3, ?4, 0)"#,
        json!([id, serde_json::to_string(&body)?, produced_at_ms, now_ms()]),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0);
    if inserted > 0 {
        increment_counter(node, queue, "total_produced", 1).await?;
    }
    Ok(())
}

fn validate_body(body: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(body)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        bail!("队列消息编码后不得超过 128 KiB");
    }
    Ok(())
}

fn new_message_id() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

async fn insert_messages(
    node: &Node,
    queue: &str,
    entries: &[(String, Value, u64, u64)],
) -> Result<()> {
    let mut sql = String::from(
        "INSERT INTO queue_messages (id, body_json, produced_at_ms, available_at_ms, attempts) VALUES ",
    );
    let mut params = Vec::with_capacity(entries.len() * 4);
    for (index, (id, body, produced, available)) in entries.iter().enumerate() {
        if index > 0 {
            sql.push(',');
        }
        let offset = index * 4;
        sql.push_str(&format!(
            "(?{},?{},?{},?{},0)",
            offset + 1,
            offset + 2,
            offset + 3,
            offset + 4
        ));
        params.push(Value::String(id.clone()));
        params.push(Value::String(serde_json::to_string(body)?));
        params.push(json!(produced));
        params.push(json!(available));
    }
    exec(node, queue, &sql, Value::Array(params)).await?;
    Ok(())
}

pub async fn stats(node: &Node, queue: &str) -> Result<QueueStats> {
    ensure_schema(node, queue).await?;
    let now = now_ms();
    let rows = rows(
        exec(
            node,
            queue,
            r#"SELECT
                 (SELECT COUNT(*) FROM queue_messages
                    WHERE available_at_ms <= ?1 AND (lease_id IS NULL OR lease_until_ms <= ?1)) AS ready,
                 (SELECT COUNT(*) FROM queue_messages
                    WHERE lease_id IS NOT NULL AND lease_until_ms > ?1) AS inflight,
                 (SELECT COUNT(*) FROM queue_dead_letters) AS dead_letters,
                 total_produced, total_consumed
               FROM queue_counters WHERE singleton = 1"#,
            json!([now]),
        )
        .await?,
    );
    let row = rows.first().context("队列统计行缺失")?;
    Ok(QueueStats {
        ready: u64_field(row, "ready"),
        inflight: u64_field(row, "inflight"),
        dead_letters: u64_field(row, "dead_letters"),
        total_produced: u64_field(row, "total_produced"),
        total_consumed: u64_field(row, "total_consumed"),
    })
}

pub async fn list_dead_letters(node: &Node, queue: &str, limit: usize) -> Result<Vec<DeadLetter>> {
    ensure_schema(node, queue).await?;
    rows(
        exec(
            node,
            queue,
            r#"SELECT id, body_json, produced_at_ms, dead_letter_at_ms, attempts, last_error
               FROM queue_dead_letters ORDER BY dead_letter_at_ms DESC LIMIT ?1"#,
            json!([limit.clamp(1, 1_000)]),
        )
        .await?,
    )
    .iter()
    .map(row_to_dead_letter)
    .collect()
}

pub async fn redrive_dead_letter(node: &Node, queue: &str, id: &str) -> Result<bool> {
    ensure_schema(node, queue).await?;
    let result = rows(
        exec(
            node,
            queue,
            "SELECT body_json, produced_at_ms FROM queue_dead_letters WHERE id=?1",
            json!([id]),
        )
        .await?,
    );
    let Some(row) = result.first() else {
        return Ok(false);
    };
    let body: Value = serde_json::from_str(string_field(row, "body_json")?)?;
    let produced = u64_field(row, "produced_at_ms");
    exec(
        node,
        queue,
        r#"INSERT OR REPLACE INTO queue_messages
           (id, body_json, produced_at_ms, available_at_ms, attempts, lease_id, lease_until_ms, last_error)
           VALUES (?1, ?2, ?3, ?4, 0, NULL, NULL, NULL)"#,
        json!([id, serde_json::to_string(&body)?, produced, now_ms()]),
    )
    .await?;
    exec(
        node,
        queue,
        "DELETE FROM queue_dead_letters WHERE id=?1",
        json!([id]),
    )
    .await?;
    Ok(true)
}

async fn claim_batch(
    node: &Node,
    queue: &str,
    spec: &QueueSpec,
) -> Result<(String, Vec<QueueMessage>)> {
    ensure_schema(node, queue).await?;
    let now = now_ms();
    let expired_before = now.saturating_sub(spec.retention_seconds.saturating_mul(1_000));
    exec(
        node,
        queue,
        "DELETE FROM queue_messages WHERE produced_at_ms < ?1",
        json!([expired_before]),
    )
    .await?;
    exec(
        node,
        queue,
        "DELETE FROM queue_dead_letters WHERE dead_letter_at_ms < ?1",
        json!([now.saturating_sub(30 * 24 * 60 * 60 * 1_000)]),
    )
    .await?;
    let lease = new_message_id();
    exec(
        node,
        queue,
        r#"UPDATE queue_messages
           SET lease_id=?1, lease_until_ms=?2, attempts=attempts+1
           WHERE id IN (
             SELECT id FROM queue_messages
             WHERE available_at_ms <= ?3 AND (lease_id IS NULL OR lease_until_ms <= ?3)
             ORDER BY available_at_ms, id LIMIT ?4
           ) AND (lease_id IS NULL OR lease_until_ms <= ?3)"#,
        json!([
            lease,
            now.saturating_add(spec.visibility_timeout_ms),
            now,
            spec.batch_size
        ]),
    )
    .await?;
    let messages = rows(
        exec(
            node,
            queue,
            r#"SELECT id, body_json, produced_at_ms, attempts FROM queue_messages
               WHERE lease_id=?1 ORDER BY available_at_ms, id"#,
            json!([lease]),
        )
        .await?,
    )
    .iter()
    .map(row_to_message)
    .collect::<Result<Vec<_>>>()?;
    Ok((lease, messages))
}

async fn settle_batch(
    node: &Node,
    queue: &str,
    spec: &QueueSpec,
    lease: &str,
    messages: &[QueueMessage],
    result: Result<DeliveryResult>,
) -> Result<()> {
    let mut actions: HashMap<&str, &MessageAction> = HashMap::new();
    let delivery_error = match &result {
        Ok(delivery) => {
            for action in &delivery.actions {
                actions.insert(&action.id, action);
            }
            None
        }
        Err(error) => Some(format!("{error:#}")),
    };
    let mut consumed = 0u64;
    for message in messages {
        let action = actions.get(message.id.as_str()).copied();
        let should_retry =
            delivery_error.is_some() || action.is_some_and(|item| item.action == "retry");
        if !should_retry {
            let affected = exec(
                node,
                queue,
                "DELETE FROM queue_messages WHERE id=?1 AND lease_id=?2",
                json!([message.id, lease]),
            )
            .await?["rows_affected"]
                .as_u64()
                .unwrap_or(0);
            consumed += affected;
            continue;
        }
        let error = action
            .and_then(|item| item.error.clone())
            .or_else(|| delivery_error.clone())
            .unwrap_or_else(|| "Worker 请求重试".into());
        let delay = action
            .map(|item| item.delay_seconds)
            .unwrap_or(0)
            .min(MAX_DELAY_SECONDS);
        if message.attempts <= spec.max_retries {
            exec(
                node,
                queue,
                r#"UPDATE queue_messages
                   SET lease_id=NULL, lease_until_ms=NULL, available_at_ms=?3, last_error=?4
                   WHERE id=?1 AND lease_id=?2"#,
                json!([
                    message.id,
                    lease,
                    now_ms().saturating_add(delay.saturating_mul(1_000)),
                    truncate_error(&error)
                ]),
            )
            .await?;
            continue;
        }
        move_to_dead_letter(node, queue, spec, lease, message, &error).await?;
    }
    if consumed > 0 {
        increment_counter(node, queue, "total_consumed", consumed).await?;
    }
    Ok(())
}

async fn move_to_dead_letter(
    node: &Node,
    queue: &str,
    spec: &QueueSpec,
    lease: &str,
    message: &QueueMessage,
    error: &str,
) -> Result<()> {
    exec(
        node,
        queue,
        r#"INSERT OR REPLACE INTO queue_dead_letters
           (id, body_json, produced_at_ms, dead_letter_at_ms, attempts, last_error)
           SELECT id, body_json, produced_at_ms, ?3, attempts, ?4
           FROM queue_messages WHERE id=?1 AND lease_id=?2"#,
        json!([message.id, lease, now_ms(), truncate_error(error)]),
    )
    .await?;
    if let Some(target) = &spec.dead_letter_queue {
        enqueue_existing(
            node,
            target,
            &message.id,
            message.body.clone(),
            message.produced_at_ms,
        )
        .await?;
    }
    exec(
        node,
        queue,
        "DELETE FROM queue_messages WHERE id=?1 AND lease_id=?2",
        json!([message.id, lease]),
    )
    .await?;
    Ok(())
}

fn truncate_error(error: &str) -> String {
    error.chars().take(4_000).collect()
}

async fn deliver(node: &Node, worker: &str, batch: &DeliveryBatch) -> Result<DeliveryResult> {
    let port = node
        .worker_port(worker)
        .context("消费者 Worker 未在当前节点运行")?;
    let token = node
        .worker_event_token(worker)
        .context("消费者 Worker 内部事件令牌尚未就绪")?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(12 * 60 * 60))
        .build()?
        .post(format!("http://127.0.0.1:{port}{INTERNAL_QUEUE_PATH}"))
        .header(INTERNAL_EVENT_HEADER, token)
        .json(batch)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let message = response.text().await.unwrap_or_default();
        bail!("队列消费者返回 {status}：{}", truncate_error(&message));
    }
    Ok(response.json().await?)
}

pub fn spawn_dispatcher(node: Arc<Node>) {
    tokio::spawn(async move {
        let mut next_run: BTreeMap<String, u64> = BTreeMap::new();
        // A stalled user handler must not block unrelated queues. The global
        // semaphore also prevents a large cluster backlog from spawning an
        // unbounded number of workerd deliveries on one node.
        let deliveries = Arc::new(tokio::sync::Semaphore::new(32));
        loop {
            let now = now_ms();
            for (view, spec) in queue_records(&node) {
                if spec.suspended || spec.consumer_worker.is_none() {
                    continue;
                }
                let queue = view.resource.name;
                if next_run.get(&queue).is_some_and(|deadline| *deadline > now) {
                    continue;
                }
                next_run.insert(queue.clone(), now.saturating_add(spec.max_wait_ms));
                let worker = spec.consumer_worker.clone().expect("checked");
                if node.worker_port(&worker).is_none() {
                    continue;
                }
                let Ok(permit) = deliveries.clone().try_acquire_owned() else {
                    break;
                };
                let node = node.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match claim_batch(&node, &queue, &spec).await {
                        Ok((_, messages)) if messages.is_empty() => {}
                        Ok((lease, messages)) => {
                            let batch = DeliveryBatch {
                                queue: queue.clone(),
                                messages: messages.clone(),
                            };
                            let delivery = deliver(&node, &worker, &batch).await;
                            if let Err(error) =
                                settle_batch(&node, &queue, &spec, &lease, &messages, delivery)
                                    .await
                            {
                                tracing::warn!("队列 {queue} 完成投递状态时失败：{error:#}");
                            }
                        }
                        Err(error) => tracing::debug!("队列 {queue} 拉取失败：{error:#}"),
                    }
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

async fn ensure_schema(node: &Node, queue: &str) -> Result<()> {
    let database = database_name(queue);
    d1::ensure_database(node, &database)?;
    if node.queue_schema_ready(&database) {
        return Ok(());
    }
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS queue_messages (
             id TEXT PRIMARY KEY,
             body_json TEXT NOT NULL,
             produced_at_ms INTEGER NOT NULL,
             available_at_ms INTEGER NOT NULL,
             attempts INTEGER NOT NULL DEFAULT 0,
             lease_id TEXT,
             lease_until_ms INTEGER,
             last_error TEXT
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        r#"CREATE INDEX IF NOT EXISTS queue_ready
           ON queue_messages(available_at_ms, lease_until_ms)"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS queue_dead_letters (
             id TEXT PRIMARY KEY,
             body_json TEXT NOT NULL,
             produced_at_ms INTEGER NOT NULL,
             dead_letter_at_ms INTEGER NOT NULL,
             attempts INTEGER NOT NULL,
             last_error TEXT
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS queue_counters (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             total_produced INTEGER NOT NULL DEFAULT 0,
             total_consumed INTEGER NOT NULL DEFAULT 0
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        "INSERT OR IGNORE INTO queue_counters(singleton) VALUES (1)",
        json!([]),
    )
    .await?;
    node.mark_queue_schema_ready(database);
    Ok(())
}

async fn increment_counter(node: &Node, queue: &str, field: &str, amount: u64) -> Result<()> {
    if field != "total_produced" && field != "total_consumed" {
        bail!("队列计数器字段无效");
    }
    exec(
        node,
        queue,
        &format!("UPDATE queue_counters SET {field}={field}+?1 WHERE singleton=1"),
        json!([amount]),
    )
    .await?;
    Ok(())
}

async fn exec(node: &Node, queue: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &database_name(queue), sql, params).await
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

fn string_field<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("队列数据库行缺少 {field}"))
}

fn u64_field(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn row_to_message(row: &Value) -> Result<QueueMessage> {
    Ok(QueueMessage {
        id: string_field(row, "id")?.to_string(),
        body: serde_json::from_str(string_field(row, "body_json")?)?,
        produced_at_ms: u64_field(row, "produced_at_ms"),
        attempts: u64_field(row, "attempts").min(u16::MAX as u64) as u16,
    })
}

fn row_to_dead_letter(row: &Value) -> Result<DeadLetter> {
    Ok(DeadLetter {
        id: string_field(row, "id")?.to_string(),
        body: serde_json::from_str(string_field(row, "body_json")?)?,
        produced_at_ms: u64_field(row, "produced_at_ms"),
        dead_letter_at_ms: u64_field(row, "dead_letter_at_ms"),
        attempts: u64_field(row, "attempts").min(u16::MAX as u64) as u16,
        last_error: row
            .get("last_error")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_spec_enforces_delivery_bounds() {
        let spec = QueueSpec::default();
        spec.validate(Some("jobs")).unwrap();
        let mut bad = spec.clone();
        bad.batch_size = 0;
        assert!(bad.validate(Some("jobs")).is_err());
        let mut self_dead_letter = spec;
        self_dead_letter.dead_letter_queue = Some("jobs".into());
        assert!(self_dead_letter.validate(Some("jobs")).is_err());
    }

    #[test]
    fn database_and_message_ids_are_safe_and_stable() {
        assert_eq!(database_name("jobs"), database_name("jobs"));
        assert_ne!(database_name("jobs"), database_name("emails"));
        assert!(rf_core::manifest::valid_name(&database_name("jobs")));
        let id = new_message_id();
        assert_eq!(id.len(), 22);
        assert!(!id.contains(['/', '+', '=']));
    }

    #[test]
    fn body_limit_counts_utf8_bytes() {
        assert!(validate_body(&json!("中".repeat(50_000))).is_err());
        assert!(validate_body(&json!({"ok": true})).is_ok());
    }
}
