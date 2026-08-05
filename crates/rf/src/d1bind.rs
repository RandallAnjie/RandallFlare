//! Loopback service behind Cloudflare-shaped D1 bindings.
//!
//! workerd does not expose an open-source native D1 service designator, so rf
//! injects a tiny standards-shaped JavaScript facade and binds its Fetcher to
//! this listener. SQL still travels through the ordinary encrypted peer API
//! and per-database Raft quorum; the facade does not bypass consistency.

use crate::node::Node;
use crate::peers::PeerClient;
use anyhow::{bail, Context, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

pub const DATABASE_HEADER: &str = "x-rf-d1-database";

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/", post(execute))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("d1 binding server died: {error}");
        }
    });
    Ok(port)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct D1Request {
    mode: String,
    #[serde(default)]
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
    #[serde(default)]
    statements: Vec<Statement>,
}

async fn execute(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<D1Request>,
) -> Response {
    match execute_inner(&node, &remote, &headers, request).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

async fn execute_inner(
    node: &Node,
    remote: &SocketAddr,
    headers: &HeaderMap,
    request: D1Request,
) -> Result<Value> {
    if !remote.ip().is_loopback() {
        bail!("D1 binding 仅允许本机 workerd 访问");
    }
    let database = headers
        .get(DATABASE_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("D1 binding 缺少数据库标头")?;
    if !rf_core::manifest::valid_name(database) {
        bail!("D1 数据库名称无效");
    }
    crate::d1::ensure_database(node, database)?;
    let client = PeerClient::new(node.cfg.cluster_secret_bytes()?);
    let listen = node.cfg.peer_api.listen;
    let base = if listen.is_ipv6() {
        format!("[::1]:{}", listen.port())
    } else {
        format!("127.0.0.1:{}", listen.port())
    };
    match request.mode.as_str() {
        "query" | "first" | "run" => {
            if request.sql.trim().is_empty() {
                bail!("D1 SQL 不能为空");
            }
            execute_statement(&client, &base, database, &request.sql, request.params).await
        }
        "exec" => {
            if request.sql.trim().is_empty() {
                bail!("D1 SQL 不能为空");
            }
            // D1Database.exec commonly carries a migration script. Split only
            // at statement boundaries recognized by SQLite's completeness
            // checker, so semicolons inside quoted strings remain intact.
            let statements = split_sql_script(&request.sql)?;
            let mut count = 0u64;
            let mut duration = 0.0;
            for sql in statements {
                let result = execute_statement(&client, &base, database, &sql, vec![]).await?;
                count += result["meta"]["changes"].as_u64().unwrap_or(0);
                duration += result["meta"]["duration"].as_f64().unwrap_or(0.0);
            }
            Ok(json!({ "count": count, "duration": duration }))
        }
        "batch" => {
            if request.statements.is_empty() || request.statements.len() > 100 {
                bail!("D1 batch 必须包含 1 至 100 条语句");
            }
            let started = Instant::now();
            let count = request.statements.len();
            let statements = request
                .statements
                .into_iter()
                .map(|statement| crate::d1::Statement {
                    sql: statement.sql,
                    params: statement.params,
                })
                .collect::<Vec<_>>();
            let output = client.d1_batch(&base, database, &statements).await?;
            let duration = started.elapsed().as_secs_f64() * 1000.0 / count as f64;
            let results = output["batch"]
                .as_array()
                .context("D1 batch response is missing results")?
                .iter()
                .map(|result| d1_result_value(result, duration))
                .collect::<Vec<_>>();
            Ok(Value::Array(results))
        }
        _ => bail!("D1 binding mode 无效"),
    }
}

async fn execute_statement(
    client: &PeerClient,
    base: &str,
    database: &str,
    sql: &str,
    params: Vec<Value>,
) -> Result<Value> {
    if sql.len() > 1024 * 1024 || params.len() > 1000 {
        bail!("D1 语句或参数过大");
    }
    let started = Instant::now();
    let result = client
        .d1_exec(base, database, sql, Value::Array(params))
        .await?;
    Ok(d1_result_value(
        &result,
        started.elapsed().as_secs_f64() * 1000.0,
    ))
}

fn d1_result_value(result: &Value, duration_ms: f64) -> Value {
    let rows = result["rows"].as_array().cloned().unwrap_or_default();
    let changes = result["rows_affected"].as_u64().unwrap_or(0);
    json!({
        "success": true,
        "results": rows,
        "meta": {
            "duration": duration_ms,
            "changes": changes,
            "rows_read": rows.len(),
            "rows_written": changes,
            "last_row_id": 0,
            "changed_db": changes > 0,
            "size_after": 0,
        }
    })
}

pub fn split_sql_script(script: &str) -> Result<Vec<String>> {
    let mut statements = Vec::new();
    let mut current = String::new();
    for character in script.chars() {
        current.push(character);
        if character == ';' && sqlite_statement_complete(&current)? && !current.trim().is_empty() {
            statements.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        statements.push(current);
    }
    if statements.is_empty() {
        bail!("D1 SQL 脚本为空");
    }
    Ok(statements)
}

pub fn import_statements(script: &str) -> Result<Vec<crate::d1::Statement>> {
    Ok(split_sql_script(script)?
        .into_iter()
        .filter(|sql| !transaction_control(sql))
        .map(|sql| crate::d1::Statement {
            sql,
            params: vec![],
        })
        .collect())
}

pub fn transaction_control(sql: &str) -> bool {
    let normalized = sql.trim().trim_end_matches(';').trim().to_ascii_uppercase();
    normalized == "BEGIN"
        || normalized == "BEGIN TRANSACTION"
        || normalized == "BEGIN DEFERRED"
        || normalized == "BEGIN IMMEDIATE"
        || normalized == "BEGIN EXCLUSIVE"
        || normalized == "COMMIT"
        || normalized == "END"
        || normalized == "END TRANSACTION"
        || normalized == "ROLLBACK"
}

fn sqlite_statement_complete(sql: &str) -> Result<bool> {
    let sql = std::ffi::CString::new(sql).context("D1 SQL 包含 NUL 字节")?;
    // SAFETY: CString guarantees a live, NUL-terminated pointer for the
    // duration of this call; sqlite3_complete neither retains nor mutates it.
    Ok(unsafe { rusqlite::ffi::sqlite3_complete(sql.as_ptr()) != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_script_split_preserves_quoted_semicolons() {
        assert_eq!(
            split_sql_script("INSERT INTO t VALUES ('a;b'); UPDATE t SET v='c';").unwrap(),
            vec!["INSERT INTO t VALUES ('a;b');", " UPDATE t SET v='c';"]
        );
        assert_eq!(split_sql_script("SELECT 1").unwrap(), vec!["SELECT 1"]);
        let imported = import_statements(
            "BEGIN TRANSACTION; CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (1); COMMIT;",
        )
        .unwrap();
        assert_eq!(imported.len(), 2);
        assert!(imported[0].sql.contains("CREATE TABLE"));
    }
}
