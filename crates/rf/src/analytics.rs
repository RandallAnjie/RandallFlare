//! Decentralized Analytics Engine datasets.
//!
//! Dataset definitions are operator-signed resources. Events are append-only
//! rows in a per-dataset D1 micro-quorum, preserving the familiar Analytics
//! Engine `blobs` / `doubles` / `indexes` shape without a central database.

use crate::d1;
use crate::node::{now_ms, Node};
use crate::peers::PeerClient;
use crate::resource::{self, ResourceRecord, ResourceView};
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const DATASET_KIND: &str = "analytics_dataset";
pub const MAX_BATCH: usize = 100;
pub const MAX_DIMENSIONS: usize = 20;
pub const MAX_STRING_BYTES: usize = 5 * 1024;
pub const MAX_WRITE_BYTES: usize = 1024 * 1024;
const MAX_TIMESTAMP_MS: u64 = 4_102_444_800_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetSpec {
    #[serde(default)]
    pub description: String,
    /// Optional automatic event expiry. Omitted means retain indefinitely.
    #[serde(default)]
    pub retention_days: Option<u32>,
}

impl DatasetSpec {
    pub fn validate(&self) -> Result<()> {
        if self.description.len() > 2_000 {
            bail!("Analytics 数据集描述不得超过 2000 个字符");
        }
        if self
            .retention_days
            .is_some_and(|days| days == 0 || days > 36_500)
        {
            bail!("Analytics 保留天数必须介于 1 和 36500 之间");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataPoint {
    #[serde(default)]
    pub blobs: Vec<String>,
    #[serde(default)]
    pub doubles: Vec<f64>,
    #[serde(default)]
    pub indexes: Vec<String>,
    #[serde(default, alias = "ts")]
    pub ts_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    pub id: String,
    pub blobs: Vec<String>,
    pub doubles: Vec<f64>,
    pub indexes: Vec<String>,
    pub ts_ms: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetStats {
    pub last_hour: u64,
    pub last_24_hours: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionGroup {
    pub key: Value,
    pub count: u64,
    pub sum: Option<f64>,
    pub average: Option<f64>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
}

pub fn dataset_record(node: &Node, name: &str) -> Option<(ResourceView, DatasetSpec)> {
    let view = resource::head(node, DATASET_KIND, name)?;
    if view.resource.deleted {
        return None;
    }
    let spec = dataset_spec(&view.resource).ok()?;
    Some((view, spec))
}

pub fn dataset_records(node: &Node) -> Vec<(ResourceView, DatasetSpec)> {
    resource::heads(node, Some(DATASET_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| dataset_spec(&view.resource).ok().map(|spec| (view, spec)))
        .collect()
}

pub fn dataset_spec(record: &ResourceRecord) -> Result<DatasetSpec> {
    if record.kind != DATASET_KIND {
        bail!("平台资源不是 Analytics 数据集");
    }
    let spec: DatasetSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

pub fn prepare_dataset_after(
    name: &str,
    spec: DatasetSpec,
    deleted: bool,
    head: Option<&ResourceView>,
) -> Result<ResourceRecord> {
    spec.validate()?;
    resource::prepare_after(
        DATASET_KIND,
        name,
        serde_json::to_value(spec)?,
        deleted,
        head,
    )
}

pub fn database_name(dataset: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("analytics/{dataset}").as_bytes()));
    format!("analytics-{}", &digest[..32])
}

pub async fn write(node: &Node, dataset: &str, points: Vec<DataPoint>) -> Result<usize> {
    let (_, spec) = dataset_record(node, dataset).context("Analytics 数据集不存在")?;
    if points.is_empty() || points.len() > MAX_BATCH {
        bail!("Analytics 每批必须包含 1 至 100 个数据点");
    }
    if serde_json::to_vec(&points)?.len() > MAX_WRITE_BYTES {
        bail!("Analytics 写入批次不得超过 1 MiB");
    }
    for point in &points {
        validate_point(point)?;
    }
    ensure_schema(node, dataset).await?;
    if let Some(days) = spec.retention_days {
        let threshold = now_ms().saturating_sub(days as u64 * 24 * 60 * 60 * 1_000);
        exec(
            node,
            dataset,
            "DELETE FROM analytics_events WHERE ts_ms < ?1",
            json!([threshold]),
        )
        .await?;
    }
    let created = now_ms();
    let mut sql = String::from(
        "INSERT INTO analytics_events (id, blobs_json, doubles_json, indexes_json, ts_ms, created_at_ms) VALUES ",
    );
    let mut params = Vec::with_capacity(points.len() * 6);
    for (index, point) in points.iter().enumerate() {
        if index > 0 {
            sql.push(',');
        }
        let offset = index * 6;
        sql.push_str(&format!(
            "(?{},?{},?{},?{},?{},?{})",
            offset + 1,
            offset + 2,
            offset + 3,
            offset + 4,
            offset + 5,
            offset + 6
        ));
        params.push(json!(new_event_id()));
        params.push(json!(serde_json::to_string(&point.blobs)?));
        params.push(json!(serde_json::to_string(&point.doubles)?));
        params.push(json!(serde_json::to_string(&point.indexes)?));
        params.push(json!(point.ts_ms.unwrap_or(created).min(MAX_TIMESTAMP_MS)));
        params.push(json!(created));
    }
    exec(node, dataset, &sql, Value::Array(params)).await?;
    Ok(points.len())
}

fn validate_point(point: &DataPoint) -> Result<()> {
    if point.blobs.len() > MAX_DIMENSIONS
        || point.doubles.len() > MAX_DIMENSIONS
        || point.indexes.len() > MAX_DIMENSIONS
    {
        bail!("Analytics blobs、doubles、indexes 各最多 20 项");
    }
    if point
        .blobs
        .iter()
        .chain(&point.indexes)
        .any(|value| value.len() > MAX_STRING_BYTES)
    {
        bail!("Analytics 字符串维度单项不得超过 5 KiB");
    }
    if point.doubles.iter().any(|value| !value.is_finite()) {
        bail!("Analytics doubles 只能包含有限数值");
    }
    Ok(())
}

fn new_event_id() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

pub async fn stats(node: &Node, dataset: &str) -> Result<DatasetStats> {
    ensure_schema(node, dataset).await?;
    let now = now_ms();
    let rows = rows(
        exec(
            node,
            dataset,
            r#"SELECT COUNT(*) AS total,
                      SUM(CASE WHEN ts_ms >= ?1 THEN 1 ELSE 0 END) AS last_hour,
                      SUM(CASE WHEN ts_ms >= ?2 THEN 1 ELSE 0 END) AS last_24_hours
               FROM analytics_events"#,
            json!([
                now.saturating_sub(60 * 60 * 1_000),
                now.saturating_sub(24 * 60 * 60 * 1_000)
            ]),
        )
        .await?,
    );
    let row = rows.first().context("Analytics 统计行缺失")?;
    Ok(DatasetStats {
        last_hour: u64_field(row, "last_hour"),
        last_24_hours: u64_field(row, "last_24_hours"),
        total: u64_field(row, "total"),
    })
}

pub async fn recent(
    node: &Node,
    dataset: &str,
    before_ts_ms: Option<u64>,
    limit: usize,
) -> Result<Vec<AnalyticsEvent>> {
    ensure_schema(node, dataset).await?;
    rows(
        exec(
            node,
            dataset,
            r#"SELECT id, blobs_json, doubles_json, indexes_json, ts_ms, created_at_ms
               FROM analytics_events WHERE ts_ms < ?1
               ORDER BY ts_ms DESC, id DESC LIMIT ?2"#,
            json!([
                before_ts_ms.unwrap_or(MAX_TIMESTAMP_MS.saturating_add(1)),
                limit.clamp(1, 1_000)
            ]),
        )
        .await?,
    )
    .iter()
    .map(row_to_event)
    .collect()
}

pub async fn group_by(
    node: &Node,
    dataset: &str,
    dimension: &str,
    dimension_index: usize,
    double_index: Option<usize>,
    since_ms: u64,
    limit: usize,
) -> Result<Vec<DimensionGroup>> {
    if dimension_index >= MAX_DIMENSIONS
        || double_index.is_some_and(|index| index >= MAX_DIMENSIONS)
    {
        bail!("Analytics 维度编号必须介于 0 和 19 之间");
    }
    let column = match dimension {
        "blob" | "blobs" => "blobs_json",
        "index" | "indexes" => "indexes_json",
        _ => bail!("Analytics 分组维度必须是 blob 或 index"),
    };
    ensure_schema(node, dataset).await?;
    let dimension_path = format!("$[{dimension_index}]");
    let value_path = format!("$[{}]", double_index.unwrap_or(0));
    let value_expr = if double_index.is_some() {
        "json_extract(doubles_json, ?2)"
    } else {
        "NULL"
    };
    let sql = format!(
        r#"SELECT json_extract({column}, ?1) AS dimension_key,
                  COUNT(*) AS event_count,
                  SUM({value_expr}) AS value_sum,
                  AVG({value_expr}) AS value_average,
                  MIN({value_expr}) AS value_minimum,
                  MAX({value_expr}) AS value_maximum
           FROM analytics_events WHERE ts_ms >= ?3
           GROUP BY dimension_key ORDER BY event_count DESC LIMIT ?4"#
    );
    rows(
        exec(
            node,
            dataset,
            &sql,
            json!([dimension_path, value_path, since_ms, limit.clamp(1, 100)]),
        )
        .await?,
    )
    .iter()
    .map(|row| {
        Ok(DimensionGroup {
            key: row.get("dimension_key").cloned().unwrap_or(Value::Null),
            count: u64_field(row, "event_count"),
            sum: f64_field(row, "value_sum"),
            average: f64_field(row, "value_average"),
            minimum: f64_field(row, "value_minimum"),
            maximum: f64_field(row, "value_maximum"),
        })
    })
    .collect()
}

async fn ensure_schema(node: &Node, dataset: &str) -> Result<()> {
    let database = database_name(dataset);
    d1::ensure_database(node, &database)?;
    if node.analytics_schema_ready(&database) {
        return Ok(());
    }
    exec_database(
        node,
        &database,
        r#"CREATE TABLE IF NOT EXISTS analytics_events (
             id TEXT PRIMARY KEY,
             blobs_json TEXT NOT NULL,
             doubles_json TEXT NOT NULL,
             indexes_json TEXT NOT NULL,
             ts_ms INTEGER NOT NULL,
             created_at_ms INTEGER NOT NULL
           )"#,
        json!([]),
    )
    .await?;
    exec_database(
        node,
        &database,
        "CREATE INDEX IF NOT EXISTS analytics_events_ts ON analytics_events(ts_ms DESC)",
        json!([]),
    )
    .await?;
    node.mark_analytics_schema_ready(database);
    Ok(())
}

async fn exec(node: &Node, dataset: &str, sql: &str, params: Value) -> Result<Value> {
    exec_database(node, &database_name(dataset), sql, params).await
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
        .with_context(|| format!("Analytics 数据库行缺少 {field}"))
}

fn u64_field(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn f64_field(row: &Value, field: &str) -> Option<f64> {
    row.get(field).and_then(Value::as_f64)
}

fn row_to_event(row: &Value) -> Result<AnalyticsEvent> {
    Ok(AnalyticsEvent {
        id: string_field(row, "id")?.to_string(),
        blobs: serde_json::from_str(string_field(row, "blobs_json")?)?,
        doubles: serde_json::from_str(string_field(row, "doubles_json")?)?,
        indexes: serde_json::from_str(string_field(row, "indexes_json")?)?,
        ts_ms: u64_field(row, "ts_ms"),
        created_at_ms: u64_field(row, "created_at_ms"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_points_enforce_cloudflare_shaped_limits() {
        let valid = DataPoint {
            blobs: vec!["api".into()],
            doubles: vec![42.5],
            indexes: vec!["user-1".into()],
            ts_ms: None,
        };
        validate_point(&valid).unwrap();
        let mut invalid = valid;
        invalid.blobs = vec!["x".into(); 21];
        assert!(validate_point(&invalid).is_err());
    }

    #[test]
    fn dataset_database_names_are_stable_and_private() {
        assert_eq!(database_name("events"), database_name("events"));
        assert_ne!(database_name("events"), database_name("metrics"));
        assert!(rf_core::manifest::valid_name(&database_name("events")));
    }
}
