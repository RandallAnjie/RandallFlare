//! Durable, decentralized event Pipelines.
//!
//! A Pipeline definition is operator-signed. Accepted events are first stored
//! in a per-Pipeline D1 micro-quorum, then quorum-leased into deterministic
//! gzip JSONL batches and written to a signed R2 bucket. Because R2 delegates
//! bytes to the bucket's configured object store, Pipeline output works with
//! both local replicas and credential-isolated node-local rclone remotes.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write as _};
use std::sync::Arc;

pub const PIPELINE_KIND: &str = "pipeline";
pub const MAX_INGEST_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_EVENTS_PER_REQUEST: usize = 10_000;
pub const DEFAULT_BATCH_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_BATCH_SECONDS: u64 = 60;
pub const MAX_TRANSFORM_SQL_BYTES: usize = 64 * 1024;
const MAX_BATCH_BYTES: u64 = 512 * 1024 * 1024;
const LEASE_MS: u64 = 5 * 60 * 1_000;
const MAX_BATCH_EVENTS: usize = 10_000;

fn default_key_template() -> String {
    "{pipeline}/year={yyyy}/month={mm}/day={dd}/hour={hh}/{agent}-{batchId}.jsonl.gz".into()
}

fn default_batch_bytes() -> u64 {
    DEFAULT_BATCH_BYTES
}

fn default_batch_seconds() -> u64 {
    DEFAULT_BATCH_SECONDS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineToken {
    pub id: String,
    pub label: String,
    /// SHA-256 of the bearer token. The plaintext is shown once and is never
    /// stored in a resource, database, log or node configuration.
    pub sha256: String,
    pub last_four: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineSpec {
    #[serde(default)]
    pub description: String,
    pub output_bucket: String,
    #[serde(default = "default_key_template")]
    pub output_key_template: String,
    #[serde(default = "default_batch_bytes")]
    pub batch_max_bytes: u64,
    #[serde(default = "default_batch_seconds")]
    pub batch_max_seconds: u64,
    #[serde(default)]
    pub schema: Option<Value>,
    /// Optional stateless SQL projection/filter. The accepted shape is either
    /// `SELECT ... FROM events` or Cloudflare's
    /// `INSERT INTO <sink> SELECT ... FROM events` form.
    #[serde(default)]
    pub transform_sql: Option<String>,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub suspend_reason: String,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub tokens: Vec<PipelineToken>,
}

impl PipelineSpec {
    pub fn validate(&self) -> Result<()> {
        if self.description.len() > 2_000 || self.suspend_reason.len() > 2_000 {
            bail!("Pipeline 描述或暂停原因不得超过 2000 个字符");
        }
        if !rf_core::manifest::valid_name(&self.output_bucket) {
            bail!("Pipeline 输出 R2 bucket 名称无效");
        }
        if !(1_024..=MAX_BATCH_BYTES).contains(&self.batch_max_bytes) {
            bail!("Pipeline 批次大小必须介于 1 KiB 和 512 MiB 之间");
        }
        if !(1..=3_600).contains(&self.batch_max_seconds) {
            bail!("Pipeline 批次等待时间必须介于 1 秒和 1 小时之间");
        }
        if self.output_key_template.is_empty()
            || self.output_key_template.len() > crate::r2::MAX_OBJECT_KEY_BYTES
            || !self.output_key_template.contains("{batchId}")
            || self.output_key_template.contains(['\r', '\n', '\\'])
            || self
                .output_key_template
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
        {
            bail!("Pipeline 对象键模板必须安全、非空并包含 {{batchId}}");
        }
        if self.hostnames.len() > 64 {
            bail!("Pipeline 自定义域名不得超过 64 个");
        }
        for hostname in &self.hostnames {
            if !rf_core::manifest::valid_hostname(hostname) {
                bail!("Pipeline 自定义域名无效：{hostname}");
            }
        }
        if self.tokens.len() > 64 {
            bail!("一个 Pipeline 最多允许 64 个接收令牌");
        }
        let mut token_ids = std::collections::BTreeSet::new();
        for token in &self.tokens {
            if token.id.len() != 16
                || !token.id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || token.sha256.len() != 64
                || !token.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || token.last_four.len() != 4
                || token.label.len() > 128
                || !token_ids.insert(&token.id)
            {
                bail!("Pipeline 接收令牌元数据无效");
            }
        }
        if let Some(schema) = &self.schema {
            jsonschema::validator_for(schema)
                .map_err(|error| anyhow::anyhow!("Pipeline JSON Schema 无效：{error}"))?;
        }
        if let Some(sql) = self.transform_sql.as_deref() {
            normalize_transform_sql(sql)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStatus {
    pub queued_events: u64,
    pub queued_bytes: u64,
    pub oldest_event_ms: Option<u64>,
    pub completed_batches: u64,
    pub failed_batches: u64,
    pub last_completed_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineBatch {
    pub id: String,
    pub object_key: Option<String>,
    pub event_count: u64,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub sha256: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub created_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct PendingEvent {
    id: String,
    payload: String,
    bytes: u64,
    received_at_ms: u64,
}

pub fn pipeline_record(node: &Node, name: &str) -> Option<(ResourceView, PipelineSpec)> {
    let view = resource::head(node, PIPELINE_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = pipeline_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn pipeline_records(node: &Node) -> Vec<(ResourceView, PipelineSpec)> {
    resource::heads(node, Some(PIPELINE_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| pipeline_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn pipeline_spec(record: &ResourceRecord) -> Result<PipelineSpec> {
    if record.kind != PIPELINE_KIND {
        bail!("平台资源不是 Pipeline");
    }
    let spec: PipelineSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn prepare_pipeline_after(
    name: &str,
    spec: PipelineSpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.validate()?;
    resource::prepare_after(
        PIPELINE_KIND,
        name,
        serde_json::to_value(spec)?,
        deleted,
        head,
    )
}

pub fn mint_token(label: impl Into<String>) -> Result<(PipelineToken, String)> {
    let label = label.into();
    if label.len() > 128 {
        bail!("Pipeline 令牌标签不得超过 128 个字符");
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let plaintext = format!("rfp_{raw}");
    let digest = Sha256::digest(plaintext.as_bytes());
    let sha256 = hex::encode(digest);
    Ok((
        PipelineToken {
            id: sha256[..16].into(),
            label,
            sha256,
            last_four: plaintext[plaintext.len() - 4..].into(),
            created_at_ms: now_ms(),
        },
        plaintext,
    ))
}

pub fn token_matches(spec: &PipelineSpec, plaintext: &str) -> bool {
    let candidate = Sha256::digest(plaintext.as_bytes());
    spec.tokens.iter().any(|token| {
        let Ok(expected) = hex::decode(&token.sha256) else {
            return false;
        };
        constant_time_eq(&candidate, &expected)
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

pub fn database_name(pipeline: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("pipeline/{pipeline}").as_bytes()));
    format!("pipeline-{}", &digest[..32])
}

pub fn parse_payload(content_type: &str, body: &[u8]) -> Result<Vec<Value>> {
    if body.is_empty() || body.len() > MAX_INGEST_BYTES {
        bail!("Pipeline 请求体必须介于 1 字节和 32 MiB 之间");
    }
    parse_payload_reader(content_type, Cursor::new(body))
}

/// Parse a body that was already streamed into an owned spool file. Keeping
/// network reads and JSON parsing separate prevents slow/chunked senders from
/// retaining their complete request in the async HTTP task.
pub async fn parse_staged_payload(
    content_type: String,
    staged: &crate::objectstore::StagedObjectFile,
) -> Result<Vec<Value>> {
    if staged.size() == 0 || staged.size() > MAX_INGEST_BYTES as u64 {
        bail!("Pipeline 请求体必须介于 1 字节和 32 MiB 之间");
    }
    let path = staged.path().to_owned();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(path).context("无法打开 Pipeline 临时请求体")?;
        parse_payload_reader(&content_type, file)
    })
    .await
    .context("Pipeline 请求体解析任务异常退出")?
}

fn parse_payload_reader<R>(content_type: &str, mut reader: R) -> Result<Vec<Value>>
where
    R: Read + Seek,
{
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if content_type == "application/json" || content_type.ends_with("+json") {
        return expand_json(serde_json::from_reader(reader).context("Pipeline JSON 无效")?);
    }
    if matches!(
        content_type.as_str(),
        "application/x-ndjson" | "application/ndjson" | "application/jsonl"
    ) {
        return parse_lines_reader(BufReader::new(reader), false);
    }
    if content_type == "text/plain" {
        return parse_lines_reader(BufReader::new(reader), true);
    }
    if let Ok(value) = serde_json::from_reader(&mut reader) {
        return expand_json(value);
    }
    reader
        .seek(SeekFrom::Start(0))
        .context("无法重新读取 Pipeline 请求体")?;
    parse_lines_reader(BufReader::new(reader), false)
}

fn expand_json(value: Value) -> Result<Vec<Value>> {
    let events = match value {
        Value::Array(events) => events,
        Value::Object(mut object) if object.len() == 1 && object.contains_key("events") => object
            .remove("events")
            .and_then(|events| events.as_array().cloned())
            .context("Pipeline events 字段必须是数组")?,
        event => vec![event],
    };
    validate_event_count(events)
}

fn parse_lines_reader<R: std::io::BufRead>(
    mut reader: R,
    plain_text_fallback: bool,
) -> Result<Vec<Value>> {
    let mut events = Vec::new();
    let mut line = String::new();
    let mut index = 0usize;
    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .context("Pipeline 文本必须是 UTF-8")?;
        if bytes == 0 {
            break;
        }
        index += 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(value) => events.push(value),
            Err(_) if plain_text_fallback => events.push(Value::String(line.into())),
            Err(error) => bail!("Pipeline 第 {index} 行不是有效 JSON：{error}"),
        }
        if events.len() > MAX_EVENTS_PER_REQUEST {
            bail!("Pipeline 每次必须接收 1 至 10000 个事件");
        }
    }
    validate_event_count(events)
}

fn validate_event_count(events: Vec<Value>) -> Result<Vec<Value>> {
    if events.is_empty() || events.len() > MAX_EVENTS_PER_REQUEST {
        bail!("Pipeline 每次必须接收 1 至 10000 个事件");
    }
    Ok(events)
}

fn normalize_transform_sql(sql: &str) -> Result<Option<&str>> {
    if sql.len() > MAX_TRANSFORM_SQL_BYTES || sql.contains('\0') {
        bail!("Pipeline 转换 SQL 不得超过 64 KiB，且不能包含 NUL");
    }
    let sql = sql.trim();
    if sql.is_empty() {
        return Ok(None);
    }
    let sql = sql.strip_suffix(';').unwrap_or(sql).trim_end();
    let query = if let Some(rest) = strip_keyword(sql, "INSERT") {
        let rest =
            strip_keyword(rest, "INTO").context("Pipeline 转换 SQL 的 INSERT 后必须包含 INTO")?;
        let (sink, rest) =
            take_sql_identifier(rest).context("Pipeline 转换 SQL 缺少安全的 sink 名称")?;
        if !sink.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
        }) {
            bail!("Pipeline 转换 SQL 的 sink 名称无效");
        }
        rest.trim_start()
    } else {
        sql
    };
    if strip_keyword(query, "SELECT").is_none() && strip_keyword(query, "WITH").is_none() {
        bail!("Pipeline 转换 SQL 必须是 SELECT，或 INSERT INTO <sink> SELECT");
    }
    Ok(Some(query))
}

fn strip_keyword<'a>(value: &'a str, keyword: &str) -> Option<&'a str> {
    let value = value.trim_start();
    let head = value.get(..keyword.len())?;
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &value[keyword.len()..];
    if rest
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(rest.trim_start())
}

fn take_sql_identifier(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let end = value
        .find(|character: char| character.is_ascii_whitespace())
        .unwrap_or(value.len());
    (end > 0).then(|| (&value[..end], &value[end..]))
}

fn transform_events(events: Vec<Value>, sql: Option<&str>) -> Result<Vec<Value>> {
    let Some(query) = sql.map(normalize_transform_sql).transpose()?.flatten() else {
        return Ok(events);
    };
    let mut columns = std::collections::BTreeSet::new();
    for event in &events {
        if let Value::Object(object) = event {
            for key in object.keys() {
                if key != "__rf_event" {
                    if key.len() > 256 || key.contains('\0') {
                        bail!("Pipeline 事件字段名不得超过 256 字节，且不能包含 NUL");
                    }
                    columns.insert(key.clone());
                }
            }
        }
    }
    if columns.len() > 256 {
        bail!("Pipeline SQL 转换每批最多展开 256 个字段");
    }
    let columns = columns.into_iter().collect::<Vec<_>>();
    let mut connection = rusqlite::Connection::open_in_memory()?;
    let definitions = columns
        .iter()
        .map(|column| quoted_identifier(column))
        .collect::<Vec<_>>();
    let mut create = String::from("CREATE TABLE events (__rf_event TEXT NOT NULL");
    for definition in definitions {
        create.push_str(", ");
        create.push_str(&definition);
    }
    create.push(')');
    connection.execute_batch(&create)?;
    let mut insert = String::from("INSERT INTO events (__rf_event");
    for column in &columns {
        insert.push_str(", ");
        insert.push_str(&quoted_identifier(column));
    }
    insert.push_str(") VALUES (");
    insert.push_str(
        &(1..=columns.len() + 1)
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    insert.push(')');
    let transaction = connection.transaction()?;
    {
        let mut statement = transaction.prepare(&insert)?;
        for event in &events {
            let object = event.as_object();
            let mut values = Vec::with_capacity(columns.len() + 1);
            values.push(rusqlite::types::Value::Text(serde_json::to_string(event)?));
            values.extend(columns.iter().map(|column| {
                object
                    .and_then(|object| object.get(column))
                    .map(json_to_sql_value)
                    .unwrap_or(rusqlite::types::Value::Null)
            }));
            statement.execute(rusqlite::params_from_iter(values.iter()))?;
        }
    }
    transaction.commit()?;
    connection.execute_batch("PRAGMA query_only = ON")?;
    let mut statement = connection
        .prepare(query)
        .context("Pipeline 转换 SQL 无法编译")?;
    if !statement.readonly() || statement.parameter_count() != 0 {
        bail!("Pipeline 转换 SQL 必须是无参数只读查询");
    }
    if statement.column_count() == 0 || statement.column_count() > 256 {
        bail!("Pipeline 转换 SQL 必须输出 1 至 256 列");
    }
    let names = statement
        .column_names()
        .iter()
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    let unique = names.iter().collect::<std::collections::BTreeSet<_>>();
    if unique.len() != names.len() || names.iter().any(|name| name.is_empty()) {
        bail!("Pipeline 转换 SQL 的输出列必须具备唯一、非空的名称");
    }
    let mut output = Vec::new();
    let mut encoded_bytes = 0usize;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if output.len() >= MAX_EVENTS_PER_REQUEST {
            bail!("Pipeline 转换 SQL 输出不得超过 10000 个事件");
        }
        let mut object = Map::new();
        for (index, name) in names.iter().enumerate() {
            object.insert(name.clone(), sql_to_json(row.get_ref(index)?)?);
        }
        let event = Value::Object(object);
        encoded_bytes = encoded_bytes.saturating_add(serde_json::to_vec(&event)?.len() + 1);
        if encoded_bytes > MAX_INGEST_BYTES {
            bail!("Pipeline 转换 SQL 输出不得超过 32 MiB");
        }
        output.push(event);
    }
    Ok(output)
}

fn quoted_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn json_to_sql_value(value: &Value) -> rusqlite::types::Value {
    match value {
        Value::Null => rusqlite::types::Value::Null,
        Value::Bool(value) => rusqlite::types::Value::Integer(i64::from(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(rusqlite::types::Value::Integer)
            .or_else(|| value.as_f64().map(rusqlite::types::Value::Real))
            .unwrap_or_else(|| rusqlite::types::Value::Text(value.to_string())),
        Value::String(value) => rusqlite::types::Value::Text(value.clone()),
        Value::Array(_) | Value::Object(_) => {
            rusqlite::types::Value::Text(serde_json::to_string(value).unwrap_or_default())
        }
    }
}

fn sql_to_json(value: rusqlite::types::ValueRef<'_>) -> Result<Value> {
    Ok(match value {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(value) => json!(value),
        rusqlite::types::ValueRef::Real(value) => json!(value),
        rusqlite::types::ValueRef::Text(value) => {
            Value::String(std::str::from_utf8(value)?.to_string())
        }
        rusqlite::types::ValueRef::Blob(value) => {
            Value::String(base64::engine::general_purpose::STANDARD.encode(value))
        }
    })
}

pub async fn ingest(node: &Node, pipeline: &str, events: Vec<Value>) -> Result<usize> {
    let (_, spec) = pipeline_record(node, pipeline).context("Pipeline 不存在")?;
    if spec.suspended {
        bail!("Pipeline 已暂停：{}", spec.suspend_reason);
    }
    if events.is_empty() || events.len() > MAX_EVENTS_PER_REQUEST {
        bail!("Pipeline 每次必须接收 1 至 10000 个事件");
    }
    let validator = spec
        .schema
        .as_ref()
        .map(jsonschema::validator_for)
        .transpose()
        .map_err(|error| anyhow::anyhow!("Pipeline JSON Schema 无效：{error}"))?;
    for (index, event) in events.iter().enumerate() {
        if let Some(validator) = &validator {
            if let Err(error) = validator.validate(event) {
                bail!(
                    "Pipeline 第 {} 个事件未通过 JSON Schema：{error}",
                    index + 1
                );
            }
        }
    }
    let events = transform_events(events, spec.transform_sql.as_deref())?;
    if events.is_empty() {
        return Ok(0);
    }
    let received_at_ms = now_ms();
    let ingest_id = new_id();
    let mut encoded = Vec::with_capacity(events.len());
    let mut total = 0usize;
    for (index, event) in events.iter().enumerate() {
        let payload = serde_json::to_string(event)?;
        total = total.saturating_add(payload.len()).saturating_add(1);
        if total > MAX_INGEST_BYTES {
            bail!("Pipeline 规范化后的事件不得超过 32 MiB");
        }
        // IDs are random across requests but sortable within one request, so
        // a JSON array/NDJSON upload retains its caller-visible event order
        // even when every event shares the same millisecond timestamp.
        encoded.push((format!("{ingest_id}-{index:05}"), payload));
    }
    ensure_schema(node, pipeline).await?;
    for chunk in encoded.chunks(100) {
        let mut sql = String::from(
            "INSERT INTO pipeline_events (id, payload, bytes, received_at_ms, state) VALUES ",
        );
        let mut params = Vec::with_capacity(chunk.len() * 4);
        for (index, (id, payload)) in chunk.iter().enumerate() {
            if index > 0 {
                sql.push(',');
            }
            let offset = index * 4;
            sql.push_str(&format!(
                "(?{},?{},?{},?{},'queued')",
                offset + 1,
                offset + 2,
                offset + 3,
                offset + 4
            ));
            params.extend([
                json!(id),
                json!(payload),
                json!(payload.len() + 1),
                json!(received_at_ms),
            ]);
        }
        exec(node, pipeline, &sql, Value::Array(params)).await?;
    }
    Ok(encoded.len())
}

pub async fn status(node: &Node, pipeline: &str) -> Result<PipelineStatus> {
    ensure_schema(node, pipeline).await?;
    let pending_rows = rows(
        exec(
            node,
            pipeline,
            r#"SELECT COUNT(*) AS queued_events, COALESCE(SUM(bytes), 0) AS queued_bytes,
                      MIN(received_at_ms) AS oldest_event_ms
               FROM pipeline_events WHERE state IN ('queued','leased')"#,
            json!([]),
        )
        .await?,
    );
    let pending = pending_rows.first().cloned().unwrap_or_else(|| json!({}));
    let batch_rows = rows(
        exec(
            node,
            pipeline,
            r#"SELECT SUM(CASE WHEN state = 'completed' THEN 1 ELSE 0 END) AS completed_batches,
                      SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END) AS failed_batches,
                      MAX(completed_at_ms) AS last_completed_ms
               FROM pipeline_batches"#,
            json!([]),
        )
        .await?,
    );
    let batches = batch_rows.first().cloned().unwrap_or_else(|| json!({}));
    let last_error = rows(
        exec(
            node,
            pipeline,
            "SELECT error FROM pipeline_batches WHERE state = 'failed' ORDER BY created_at_ms DESC LIMIT 1",
            json!([]),
        )
        .await?,
    )
    .first()
    .and_then(|row| row.get("error"))
    .and_then(Value::as_str)
    .map(str::to_string);
    Ok(PipelineStatus {
        queued_events: u64_field(&pending, "queued_events"),
        queued_bytes: u64_field(&pending, "queued_bytes"),
        oldest_event_ms: optional_u64_field(&pending, "oldest_event_ms"),
        completed_batches: u64_field(&batches, "completed_batches"),
        failed_batches: u64_field(&batches, "failed_batches"),
        last_completed_ms: optional_u64_field(&batches, "last_completed_ms"),
        last_error,
    })
}

pub async fn batches(node: &Node, pipeline: &str, limit: usize) -> Result<Vec<PipelineBatch>> {
    ensure_schema(node, pipeline).await?;
    rows(
        exec(
            node,
            pipeline,
            r#"SELECT id, object_key, event_count, uncompressed_bytes, compressed_bytes,
                      sha256, state, error, created_at_ms, completed_at_ms
               FROM pipeline_batches ORDER BY created_at_ms DESC LIMIT ?1"#,
            json!([limit.clamp(1, 1_000)]),
        )
        .await?,
    )
    .iter()
    .map(row_to_batch)
    .collect()
}

/// Flush at most one batch. Returns `None` when the threshold/age has not yet
/// been reached or another node won the quorum lease.
pub async fn flush_once(node: &Node, pipeline: &str, force: bool) -> Result<Option<PipelineBatch>> {
    let (_, spec) = pipeline_record(node, pipeline).context("Pipeline 不存在")?;
    if spec.suspended && !force {
        return Ok(None);
    }
    let (_, output_bucket) = crate::r2::bucket_record(node, &spec.output_bucket)
        .context("Pipeline 输出 R2 bucket 不存在")?;
    if !output_bucket.uses_local_storage()
        && !crate::placement::system_tags(node, &node.id_hex()).contains("rclone")
    {
        if force {
            bail!("当前节点没有 Pipeline 输出 bucket 所需的 rclone 能力");
        }
        return Ok(None);
    }
    ensure_schema(node, pipeline).await?;
    let now = now_ms();
    exec(
        node,
        pipeline,
        "UPDATE pipeline_events SET state='queued', lease_token=NULL, lease_until_ms=NULL WHERE state='leased' AND lease_until_ms <= ?1",
        json!([now]),
    )
    .await?;
    let candidates = rows(
        exec(
            node,
            pipeline,
            r#"SELECT id, payload, bytes, received_at_ms FROM pipeline_events
               WHERE state='queued' ORDER BY received_at_ms, id LIMIT ?1"#,
            json!([MAX_BATCH_EVENTS]),
        )
        .await?,
    );
    let mut selected = Vec::new();
    let mut bytes = 0u64;
    for row in candidates {
        let event = row_to_pending(&row)?;
        if !selected.is_empty() && bytes.saturating_add(event.bytes) > spec.batch_max_bytes {
            break;
        }
        bytes = bytes.saturating_add(event.bytes);
        selected.push(event);
    }
    let Some(oldest) = selected.first().map(|event| event.received_at_ms) else {
        return Ok(None);
    };
    let due = force
        || bytes >= spec.batch_max_bytes
        || now.saturating_sub(oldest) >= spec.batch_max_seconds * 1_000;
    if !due {
        return Ok(None);
    }
    let batch_id = batch_id(&selected);
    let lease_until = now.saturating_add(LEASE_MS);
    let placeholders = (0..selected.len())
        .map(|index| format!("?{}", index + 3))
        .collect::<Vec<_>>()
        .join(",");
    let mut params = vec![json!(batch_id), json!(lease_until)];
    params.extend(selected.iter().map(|event| json!(event.id)));
    let claimed = exec(
        node,
        pipeline,
        &format!(
            "UPDATE pipeline_events SET state='leased', lease_token=?1, lease_until_ms=?2 WHERE state='queued' AND id IN ({placeholders})"
        ),
        Value::Array(params),
    )
    .await?["rows_affected"]
        .as_u64()
        .unwrap_or(0) as usize;
    if claimed != selected.len() {
        exec(
            node,
            pipeline,
            "UPDATE pipeline_events SET state='queued', lease_token=NULL, lease_until_ms=NULL WHERE lease_token=?1",
            json!([batch_id]),
        )
        .await?;
        return Ok(None);
    }

    if let Some(existing) = batch_by_id(node, pipeline, &batch_id).await? {
        if existing.state == "completed" {
            delete_leased(node, pipeline, &batch_id).await?;
            return Ok(Some(existing));
        }
    }

    let created_at_ms = now_ms();
    let mut jsonl = Vec::with_capacity(bytes as usize);
    for event in &selected {
        jsonl.extend_from_slice(event.payload.as_bytes());
        jsonl.push(b'\n');
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&jsonl)?;
    let compressed = encoder.finish()?;
    let object_key = render_key(pipeline, &spec.output_key_template, &batch_id, oldest)?;
    let sha256 = hex::encode(Sha256::digest(&compressed));
    let options = batch_put_options(pipeline, &batch_id, selected.len(), jsonl.len());
    let upload = upload_batch(node, &spec.output_bucket, &object_key, &compressed, options).await;
    match upload {
        Ok(()) => {
            exec(
                node,
                pipeline,
                r#"INSERT OR REPLACE INTO pipeline_batches
                   (id, object_key, event_count, uncompressed_bytes, compressed_bytes, sha256,
                    state, error, created_at_ms, completed_at_ms)
                   VALUES (?1,?2,?3,?4,?5,?6,'completed',NULL,?7,?8)"#,
                json!([
                    batch_id,
                    object_key,
                    selected.len(),
                    jsonl.len(),
                    compressed.len(),
                    sha256,
                    created_at_ms,
                    now_ms()
                ]),
            )
            .await?;
            delete_leased(node, pipeline, &batch_id).await?;
        }
        Err(error) => {
            let message = format!("{error:#}");
            exec(
                node,
                pipeline,
                r#"INSERT OR REPLACE INTO pipeline_batches
                   (id, object_key, event_count, uncompressed_bytes, compressed_bytes, sha256,
                    state, error, created_at_ms, completed_at_ms)
                   VALUES (?1,?2,?3,?4,?5,NULL,'failed',?6,?7,NULL)"#,
                json!([
                    batch_id,
                    object_key,
                    selected.len(),
                    jsonl.len(),
                    compressed.len(),
                    message,
                    created_at_ms
                ]),
            )
            .await?;
            exec(
                node,
                pipeline,
                "UPDATE pipeline_events SET state='queued', lease_token=NULL, lease_until_ms=NULL WHERE lease_token=?1",
                json!([batch_id]),
            )
            .await?;
            return Err(error);
        }
    }
    batch_by_id(node, pipeline, &batch_id)
        .await?
        .map(Some)
        .context("Pipeline 批次审计记录缺失")
}

async fn upload_batch(
    node: &Node,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    options: crate::r2::PutOptions,
) -> Result<()> {
    if bytes.len() <= crate::r2::MAX_BUFFERED_OBJECT_BYTES {
        crate::r2::put_object(node, bucket, key, bytes, options).await?;
        return Ok(());
    }
    let upload = crate::r2::create_multipart_upload(node, bucket, key, options).await?;
    let mut parts = Vec::new();
    for (index, chunk) in bytes
        .chunks(crate::r2::MAX_BUFFERED_MULTIPART_PART_BYTES)
        .enumerate()
    {
        match crate::r2::upload_part(
            node,
            bucket,
            key,
            &upload.upload_id,
            index as u32 + 1,
            chunk,
        )
        .await
        {
            Ok(part) => parts.push(crate::r2::PublishedPart {
                part_number: part.part_number,
                etag: part.etag,
            }),
            Err(error) => {
                let _ =
                    crate::r2::abort_multipart_upload(node, bucket, key, &upload.upload_id).await;
                return Err(error);
            }
        }
    }
    crate::r2::complete_multipart_upload(node, bucket, key, &upload.upload_id, &parts).await?;
    Ok(())
}

fn batch_put_options(
    pipeline: &str,
    batch_id: &str,
    event_count: usize,
    uncompressed_bytes: usize,
) -> crate::r2::PutOptions {
    let mut custom_metadata = Map::new();
    custom_metadata.insert("pipeline".into(), json!(pipeline));
    custom_metadata.insert("batchId".into(), json!(batch_id));
    custom_metadata.insert("eventCount".into(), json!(event_count));
    custom_metadata.insert("uncompressedBytes".into(), json!(uncompressed_bytes));
    let mut http_metadata = Map::new();
    http_metadata.insert("contentEncoding".into(), json!("gzip"));
    crate::r2::PutOptions {
        content_type: Some("application/x-ndjson".into()),
        custom_metadata,
        http_metadata,
    }
}

fn render_key(pipeline: &str, template: &str, batch_id: &str, timestamp_ms: u64) -> Result<String> {
    let timestamp =
        time::OffsetDateTime::from_unix_timestamp_nanos(timestamp_ms as i128 * 1_000_000)
            .context("Pipeline 事件时间戳超出支持范围")?;
    // Stable across lease failover: a successor overwrites the same object if
    // the prior node died after upload but before committing the batch audit.
    let agent = &batch_id[..12];
    let key = template
        .replace("{pipeline}", pipeline)
        .replace("{yyyy}", &format!("{:04}", timestamp.year()))
        .replace("{mm}", &format!("{:02}", timestamp.month() as u8))
        .replace("{dd}", &format!("{:02}", timestamp.day()))
        .replace("{hh}", &format!("{:02}", timestamp.hour()))
        .replace("{agent}", agent)
        .replace("{batchId}", batch_id);
    if key.contains('{') || key.contains('}') {
        bail!("Pipeline 对象键模板包含未知占位符");
    }
    Ok(key)
}

fn batch_id(events: &[PendingEvent]) -> String {
    let mut hasher = Sha256::new();
    for event in events {
        hasher.update(event.id.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())[..32].into()
}

fn new_id() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

async fn delete_leased(node: &Node, pipeline: &str, batch_id: &str) -> Result<()> {
    exec(
        node,
        pipeline,
        "DELETE FROM pipeline_events WHERE state='leased' AND lease_token=?1",
        json!([batch_id]),
    )
    .await?;
    Ok(())
}

async fn batch_by_id(node: &Node, pipeline: &str, id: &str) -> Result<Option<PipelineBatch>> {
    rows(
        exec(
            node,
            pipeline,
            r#"SELECT id, object_key, event_count, uncompressed_bytes, compressed_bytes,
                      sha256, state, error, created_at_ms, completed_at_ms
               FROM pipeline_batches WHERE id=?1"#,
            json!([id]),
        )
        .await?,
    )
    .first()
    .map(row_to_batch)
    .transpose()
}

pub fn spawn_driver(node: Arc<Node>) {
    tokio::spawn(async move {
        loop {
            for (view, spec) in pipeline_records(&node) {
                if spec.suspended {
                    continue;
                }
                if let Err(error) = flush_once(&node, &view.resource.name, false).await {
                    tracing::warn!("刷新 Pipeline {} 失败：{error:#}", view.resource.name);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

async fn ensure_schema(node: &Node, pipeline: &str) -> Result<()> {
    let database = database_name(pipeline);
    d1::ensure_database(node, &database)?;
    if node.pipeline_schema_ready(&database) {
        return Ok(());
    }
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS pipeline_events (
             id TEXT PRIMARY KEY,
             payload TEXT NOT NULL,
             bytes INTEGER NOT NULL,
             received_at_ms INTEGER NOT NULL,
             state TEXT NOT NULL,
             lease_token TEXT,
             lease_until_ms INTEGER
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        "CREATE INDEX IF NOT EXISTS pipeline_events_ready ON pipeline_events(state, received_at_ms, id)",
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS pipeline_batches (
             id TEXT PRIMARY KEY,
             object_key TEXT,
             event_count INTEGER NOT NULL,
             uncompressed_bytes INTEGER NOT NULL,
             compressed_bytes INTEGER NOT NULL,
             sha256 TEXT,
             state TEXT NOT NULL,
             error TEXT,
             created_at_ms INTEGER NOT NULL,
             completed_at_ms INTEGER
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        "CREATE INDEX IF NOT EXISTS pipeline_batches_created ON pipeline_batches(created_at_ms DESC)",
        json!([]),
    )
    .await?;
    node.mark_pipeline_schema_ready(database);
    Ok(())
}

async fn exec(node: &Node, pipeline: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &database_name(pipeline), sql, params).await
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
        .with_context(|| format!("Pipeline 数据库行缺少 {field}"))
}

fn u64_field(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn optional_u64_field(row: &Value, field: &str) -> Option<u64> {
    row.get(field).and_then(Value::as_u64)
}

fn optional_string_field(row: &Value, field: &str) -> Option<String> {
    row.get(field).and_then(Value::as_str).map(str::to_string)
}

fn row_to_pending(row: &Value) -> Result<PendingEvent> {
    Ok(PendingEvent {
        id: string_field(row, "id")?.into(),
        payload: string_field(row, "payload")?.into(),
        bytes: u64_field(row, "bytes"),
        received_at_ms: u64_field(row, "received_at_ms"),
    })
}

fn row_to_batch(row: &Value) -> Result<PipelineBatch> {
    Ok(PipelineBatch {
        id: string_field(row, "id")?.into(),
        object_key: optional_string_field(row, "object_key"),
        event_count: u64_field(row, "event_count"),
        uncompressed_bytes: u64_field(row, "uncompressed_bytes"),
        compressed_bytes: u64_field(row, "compressed_bytes"),
        sha256: optional_string_field(row, "sha256"),
        state: string_field(row, "state")?.into(),
        error: optional_string_field(row, "error"),
        created_at_ms: u64_field(row, "created_at_ms"),
        completed_at_ms: optional_u64_field(row, "completed_at_ms"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> PipelineSpec {
        PipelineSpec {
            description: String::new(),
            output_bucket: "archive".into(),
            output_key_template: default_key_template(),
            batch_max_bytes: DEFAULT_BATCH_BYTES,
            batch_max_seconds: DEFAULT_BATCH_SECONDS,
            schema: None,
            transform_sql: None,
            suspended: false,
            suspend_reason: String::new(),
            hostnames: Vec::new(),
            tokens: Vec::new(),
        }
    }

    #[test]
    fn payload_formats_expand_consistently() {
        assert_eq!(
            parse_payload("application/json", br#"{"events":[{"x":1},{"x":2}]}"#)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            parse_payload("application/x-ndjson", b"{\"x\":1}\n{\"x\":2}\n")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            parse_payload("text/plain", b"hello\nworld\n").unwrap(),
            [json!("hello"), json!("world")]
        );
    }

    #[test]
    fn tokens_are_one_way_and_constant_time_checked() {
        let (token, plaintext) = mint_token("测试").unwrap();
        let mut spec = spec();
        spec.tokens.push(token);
        assert!(token_matches(&spec, &plaintext));
        assert!(!token_matches(&spec, "rfp_wrong"));
        let serialized = serde_json::to_string(&spec).unwrap();
        assert!(!serialized.contains(&plaintext));
    }

    #[test]
    fn schema_and_idempotent_key_are_validated() {
        let mut spec = spec();
        spec.schema = Some(json!({
            "type": "object",
            "required": ["message"],
            "properties": {"message": {"type": "string"}}
        }));
        spec.validate().unwrap();
        spec.output_key_template = "missing-id.jsonl.gz".into();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn sql_transform_filters_projects_and_computes() {
        let transformed = transform_events(
            vec![
                json!({"kind": "view", "amount": 5, "meta": {"region": "us"}}),
                json!({"kind": "purchase", "amount": 20, "meta": {"region": "eu"}}),
            ],
            Some(
                "INSERT INTO archive SELECT UPPER(kind) AS event_type, amount * 1.1 AS gross, json_extract(meta, '$.region') AS region FROM events WHERE amount >= 10",
            ),
        )
        .unwrap();
        assert_eq!(transformed.len(), 1);
        assert_eq!(transformed[0]["event_type"], "PURCHASE");
        assert_eq!(transformed[0]["gross"], 22.0);
        assert_eq!(transformed[0]["region"], "eu");
    }

    #[test]
    fn sql_transform_is_read_only_bounded_and_supports_raw_json() {
        let raw = transform_events(
            vec![json!({"odd\"field": 7})],
            Some("SELECT \"odd\"\"field\" AS value FROM events"),
        )
        .unwrap();
        assert_eq!(raw, [json!({"value": 7})]);
        assert!(transform_events(vec![json!({"x": 1})], Some("DELETE FROM events")).is_err());
        assert!(transform_events(
            vec![json!({"x": 1})],
            Some("SELECT x FROM events; DELETE FROM events")
        )
        .is_err());
        assert!(normalize_transform_sql(&"x".repeat(MAX_TRANSFORM_SQL_BYTES + 1)).is_err());
    }
}
