//! Loopback backend for workerd's native `R2Bucket` binding.
//!
//! Stock workerd turns R2 JavaScript calls into HTTP requests whose Cap'n
//! Proto JSON metadata is carried in `CF-R2-Request` (GET) or prepended to
//! the body (PUT). This adapter speaks that protocol and routes operations to
//! RandallFlare's signed bucket catalog, D1 metadata quorum and object store.

use crate::node::Node;
use crate::r2::{self, ObjectMeta, PublishedPart, PutOptions};
use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;

pub const BUCKET_HEADER: &str = "x-rf-r2-bucket";
const REQUEST_HEADER: &str = "cf-r2-request";
const METADATA_SIZE_HEADER: &str = "cf-r2-metadata-size";
const ERROR_HEADER: &str = "cf-r2-error";
const MAX_BINDING_METADATA: usize = 1024 * 1024;

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = router(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("r2 binding server died: {error}");
        }
    });
    Ok(port)
}

pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/", get(binding_get).put(binding_put))
        .layer(DefaultBodyLimit::max(
            r2::MAX_DIRECT_OBJECT_BYTES + MAX_BINDING_METADATA,
        ))
        .with_state(node)
}

fn bucket(headers: &HeaderMap, remote: &SocketAddr) -> Result<String> {
    if !remote.ip().is_loopback() {
        bail!("R2 binding 仅允许本机 workerd 访问");
    }
    let bucket = headers
        .get(BUCKET_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("R2 binding 缺少 bucket 标头")?
        .to_string();
    if !rf_core::manifest::valid_name(&bucket) {
        bail!("R2 binding bucket 名称无效");
    }
    Ok(bucket)
}

fn request_from_header(headers: &HeaderMap) -> Result<Value> {
    let raw = headers
        .get(REQUEST_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("R2 binding 缺少请求元数据")?;
    if raw.len() > MAX_BINDING_METADATA {
        bail!("R2 binding 请求元数据过大");
    }
    let value: Value = serde_json::from_str(raw).context("R2 binding 请求元数据不是 JSON")?;
    validate_request(&value)?;
    Ok(value)
}

fn request_from_body<'a>(headers: &HeaderMap, body: &'a [u8]) -> Result<(Value, &'a [u8])> {
    let size = headers
        .get(METADATA_SIZE_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("R2 binding 缺少元数据长度")?
        .parse::<usize>()
        .context("R2 binding 元数据长度无效")?;
    if size > MAX_BINDING_METADATA || body.len() < size {
        bail!("R2 binding 元数据长度越界");
    }
    let value: Value =
        serde_json::from_slice(&body[..size]).context("R2 binding 请求元数据不是 JSON")?;
    validate_request(&value)?;
    Ok((value, &body[size..]))
}

fn validate_request(request: &Value) -> Result<()> {
    if request.get("version").and_then(Value::as_u64) != Some(1)
        || request.get("method").and_then(Value::as_str).is_none()
    {
        bail!("不支持此版本的 R2 binding 请求");
    }
    Ok(())
}

async fn binding_get(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let bucket = match bucket(&headers, &remote) {
        Ok(bucket) => bucket,
        Err(error) => return r2_error(StatusCode::BAD_REQUEST, 10001, error),
    };
    let request = match request_from_header(&headers) {
        Ok(request) => request,
        Err(error) => return r2_error(StatusCode::BAD_REQUEST, 10001, error),
    };
    match request["method"].as_str().unwrap() {
        "head" => {
            let Some(key) = request.get("object").and_then(Value::as_str) else {
                return r2_error_message(StatusCode::BAD_REQUEST, 10001, "R2 head 缺少对象键");
            };
            match r2::head_object(&node, &bucket, key).await {
                Ok(Some(metadata)) => metadata_response(object_json(&metadata, None), &[]),
                Ok(None) => object_not_found(key),
                Err(error) => backend_error(error),
            }
        }
        "get" => {
            let Some(key) = request.get("object").and_then(Value::as_str) else {
                return r2_error_message(StatusCode::BAD_REQUEST, 10001, "R2 get 缺少对象键");
            };
            match r2::get_object(&node, &bucket, key).await {
                Ok(Some((metadata, bytes))) => {
                    if !condition_matches(request.get("onlyIf"), Some(&metadata)) {
                        return metadata_response_status(
                            StatusCode::NOT_MODIFIED,
                            object_json(&metadata, None),
                            &[],
                        );
                    }
                    match requested_range(&request, bytes.len()) {
                        Ok(Some((offset, length))) => metadata_response(
                            object_json(&metadata, Some((offset, length))),
                            &bytes[offset..offset + length],
                        ),
                        Ok(None) => metadata_response(object_json(&metadata, None), &bytes),
                        Err(error) => r2_error(StatusCode::RANGE_NOT_SATISFIABLE, 10039, error),
                    }
                }
                Ok(None) => object_not_found(key),
                Err(error) => backend_error(error),
            }
        }
        "list" => {
            let prefix = request.get("prefix").and_then(Value::as_str).unwrap_or("");
            let cursor = request
                .get("cursor")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty());
            let start_after = request
                .get("startAfter")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty());
            let delimiter = request
                .get("delimiter")
                .and_then(Value::as_str)
                .unwrap_or("");
            let limit = request
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(1000)
                .clamp(1, r2::MAX_LIST_LIMIT as u64) as usize;
            match r2::list_objects_delimited(
                &node,
                &bucket,
                prefix,
                cursor.or(start_after),
                limit,
                delimiter,
            )
            .await
            {
                Ok(list) => metadata_response(
                    json!({
                        "objects": list.objects.iter().map(|item| object_json(item, None)).collect::<Vec<_>>(),
                        "truncated": list.truncated,
                        "cursor": list.cursor.unwrap_or_default(),
                        "delimitedPrefixes": list.delimited_prefixes,
                    }),
                    &[],
                ),
                Err(error) => backend_error(error),
            }
        }
        method => r2_error_message(
            StatusCode::NOT_IMPLEMENTED,
            10002,
            &format!("尚未实现 R2 binding 方法 {method}"),
        ),
    }
}

async fn binding_put(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let bucket = match bucket(&headers, &remote) {
        Ok(bucket) => bucket,
        Err(error) => return r2_error(StatusCode::BAD_REQUEST, 10001, error),
    };
    let (request, bytes) = match request_from_body(&headers, &body) {
        Ok(request) => request,
        Err(error) => return r2_error(StatusCode::BAD_REQUEST, 10001, error),
    };
    match request["method"].as_str().unwrap() {
        "put" => {
            let Some(key) = request.get("object").and_then(Value::as_str) else {
                return r2_error_message(StatusCode::BAD_REQUEST, 10001, "R2 put 缺少对象键");
            };
            if let Some(expected) = request.get("sha256").and_then(Value::as_str) {
                if !expected.eq_ignore_ascii_case(&hex::encode(Sha256::digest(bytes))) {
                    return r2_error_message(
                        StatusCode::BAD_REQUEST,
                        10037,
                        "R2 put 的 SHA-256 校验失败",
                    );
                }
            }
            match r2::head_object(&node, &bucket, key).await {
                Ok(existing) if !condition_matches(request.get("onlyIf"), existing.as_ref()) => {
                    return r2_error_message(
                        StatusCode::PRECONDITION_FAILED,
                        10031,
                        "R2 put 前置条件未满足",
                    );
                }
                Ok(_) => {}
                Err(error) => return backend_error(error),
            }
            let options = put_options(&request);
            match options {
                Ok(options) => match r2::put_object(&node, &bucket, key, bytes, options).await {
                    Ok(metadata) => JsonBody(object_json(&metadata, None)).into_response(),
                    Err(error) => backend_error(error),
                },
                Err(error) => r2_error(StatusCode::BAD_REQUEST, 10001, error),
            }
        }
        "delete" => {
            let keys: Vec<&str> = if let Some(key) = request.get("object").and_then(Value::as_str) {
                vec![key]
            } else {
                request
                    .get("objects")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect()
            };
            if keys.is_empty() || keys.len() > 1000 {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 delete 必须包含 1 至 1000 个对象键",
                );
            }
            for key in keys {
                if let Err(error) = r2::delete_object(&node, &bucket, key).await {
                    return backend_error(error);
                }
            }
            JsonBody(json!({})).into_response()
        }
        "createMultipartUpload" => {
            let Some(key) = request.get("object").and_then(Value::as_str) else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 createMultipartUpload 缺少对象键",
                );
            };
            let options = match put_options(&request) {
                Ok(options) => options,
                Err(error) => return r2_error(StatusCode::BAD_REQUEST, 10001, error),
            };
            match r2::create_multipart_upload(&node, &bucket, key, options).await {
                Ok(upload) => JsonBody(json!({ "uploadId": upload.upload_id })).into_response(),
                Err(error) => backend_error(error),
            }
        }
        "uploadPart" => {
            let Some(key) = request.get("object").and_then(Value::as_str) else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 uploadPart 缺少对象键",
                );
            };
            let Some(upload_id) = request.get("uploadId").and_then(Value::as_str) else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 uploadPart 缺少 uploadId",
                );
            };
            let Some(part_number) = request
                .get("partNumber")
                .and_then(json_u64)
                .and_then(|number| u32::try_from(number).ok())
            else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 uploadPart 分片编号无效",
                );
            };
            match r2::upload_part(&node, &bucket, key, upload_id, part_number, bytes).await {
                Ok(part) => JsonBody(json!({ "etag": part.etag })).into_response(),
                Err(error) => backend_error(error),
            }
        }
        "completeMultipartUpload" => {
            let Some(key) = request.get("object").and_then(Value::as_str) else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 completeMultipartUpload 缺少对象键",
                );
            };
            let Some(upload_id) = request.get("uploadId").and_then(Value::as_str) else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 completeMultipartUpload 缺少 uploadId",
                );
            };
            let parts = match published_parts(&request) {
                Ok(parts) => parts,
                Err(error) => return r2_error(StatusCode::BAD_REQUEST, 10001, error),
            };
            match r2::complete_multipart_upload(&node, &bucket, key, upload_id, &parts).await {
                Ok(metadata) => JsonBody(object_json(&metadata, None)).into_response(),
                Err(error) => backend_error(error),
            }
        }
        "abortMultipartUpload" => {
            let Some(key) = request.get("object").and_then(Value::as_str) else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 abortMultipartUpload 缺少对象键",
                );
            };
            let Some(upload_id) = request.get("uploadId").and_then(Value::as_str) else {
                return r2_error_message(
                    StatusCode::BAD_REQUEST,
                    10001,
                    "R2 abortMultipartUpload 缺少 uploadId",
                );
            };
            match r2::abort_multipart_upload(&node, &bucket, key, upload_id).await {
                Ok(()) => JsonBody(json!({})).into_response(),
                Err(error) => backend_error(error),
            }
        }
        method => r2_error_message(
            StatusCode::NOT_IMPLEMENTED,
            10002,
            &format!("尚未实现 R2 binding 方法 {method}"),
        ),
    }
}

fn put_options(request: &Value) -> Result<PutOptions> {
    let mut custom_metadata = Map::new();
    for field in request
        .get("customFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let key = field
            .get("k")
            .and_then(Value::as_str)
            .context("R2 自定义元数据缺少 k")?;
        let value = field
            .get("v")
            .and_then(Value::as_str)
            .context("R2 自定义元数据缺少 v")?;
        custom_metadata.insert(key.to_string(), Value::String(value.to_string()));
    }
    let http_metadata = request
        .get("httpFields")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let content_type = http_metadata
        .get("contentType")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(PutOptions {
        content_type,
        custom_metadata,
        http_metadata,
    })
}

fn published_parts(request: &Value) -> Result<Vec<PublishedPart>> {
    request
        .get("parts")
        .and_then(Value::as_array)
        .context("R2 completeMultipartUpload 缺少分片列表")?
        .iter()
        .map(|part| {
            Ok(PublishedPart {
                part_number: part
                    .get("part")
                    .and_then(json_u64)
                    .and_then(|number| u32::try_from(number).ok())
                    .context("R2 已发布分片编号无效")?,
                etag: part
                    .get("etag")
                    .and_then(Value::as_str)
                    .context("R2 已发布分片缺少 ETag")?
                    .to_string(),
            })
        })
        .collect()
}

fn object_json(metadata: &ObjectMeta, range: Option<(usize, usize)>) -> Value {
    let mut http_fields = metadata.http_metadata.clone();
    if let Some(content_type) = &metadata.content_type {
        http_fields.insert("contentType".into(), Value::String(content_type.clone()));
    }
    let custom_fields: Vec<Value> = metadata
        .custom_metadata
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|value| json!({ "k": key, "v": value })))
        .collect();
    let mut value = json!({
        "name": metadata.key,
        "version": metadata.sha256,
        "size": metadata.size,
        "etag": metadata.etag,
        "uploaded": metadata.uploaded_at_ms,
        "httpFields": http_fields,
        "customFields": custom_fields,
        "checksums": { "2": metadata.sha256 },
        "storageClass": "Standard",
    });
    if let Some((offset, length)) = range {
        value["range"] = json!({ "offset": offset, "length": length });
    }
    value
}

fn condition_matches(condition: Option<&Value>, object: Option<&ObjectMeta>) -> bool {
    let Some(condition) = condition.and_then(Value::as_object) else {
        return true;
    };
    let etag_matches = condition
        .get("etagMatches")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if !etag_matches.is_empty()
        && !etag_matches
            .iter()
            .any(|condition| etag_matches_object(condition, object))
    {
        return false;
    }
    let etag_does_not_match = condition
        .get("etagDoesNotMatch")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if etag_does_not_match
        .iter()
        .any(|condition| etag_matches_object(condition, object))
    {
        return false;
    }
    let granularity = if condition
        .get("secondsGranularity")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        1000
    } else {
        1
    };
    if let Some(before) = condition.get("uploadedBefore").and_then(json_u64) {
        let Some(object) = object else { return false };
        if object.uploaded_at_ms / granularity >= before / granularity {
            return false;
        }
    }
    if let Some(after) = condition.get("uploadedAfter").and_then(json_u64) {
        let Some(object) = object else { return false };
        if object.uploaded_at_ms / granularity <= after / granularity {
            return false;
        }
    }
    true
}

fn etag_matches_object(condition: &Value, object: Option<&ObjectMeta>) -> bool {
    let Some(object) = object else { return false };
    condition.get("type").and_then(Value::as_str) == Some("wildcard")
        || condition.get("value").and_then(Value::as_str) == Some("*")
        || condition
            .get("value")
            .and_then(Value::as_str)
            .is_some_and(|etag| etag.trim_matches('"') == object.etag)
}

fn requested_range(request: &Value, size: usize) -> Result<Option<(usize, usize)>> {
    let range = request.get("range").and_then(Value::as_object);
    let header = request.get("rangeHeader").and_then(Value::as_str);
    if range.is_none() && header.is_none() {
        return Ok(None);
    }
    if size == 0 {
        bail!("空对象没有可读取的字节范围");
    }
    let (offset, length) = if let Some(range) = range {
        if let Some(suffix) = range.get("suffix").and_then(json_u64) {
            let length = (suffix as usize).min(size);
            (size - length, length)
        } else {
            let offset = range.get("offset").and_then(json_u64).unwrap_or(0) as usize;
            let length = range
                .get("length")
                .and_then(json_u64)
                .map(|length| length as usize)
                .unwrap_or_else(|| size.saturating_sub(offset));
            (offset, length)
        }
    } else {
        parse_range_header(header.unwrap(), size)?
    };
    if offset >= size || length == 0 || offset.saturating_add(length) > size {
        bail!("请求的 R2 字节范围超出对象边界");
    }
    Ok(Some((offset, length)))
}

// Cap'n Proto's JSON codec serializes 64-bit integers as decimal strings to
// preserve exact values in JavaScript. Accept ordinary JSON numbers as well so
// this adapter remains straightforward to exercise outside workerd.
fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn parse_range_header(header: &str, size: usize) -> Result<(usize, usize)> {
    let value = header.strip_prefix("bytes=").context("R2 Range 标头无效")?;
    if value.contains(',') {
        bail!("R2 仅支持单个字节范围");
    }
    let (start, end) = value.split_once('-').context("R2 Range 标头无效")?;
    if start.is_empty() {
        let suffix = end.parse::<usize>()?;
        let length = suffix.min(size);
        return Ok((size - length, length));
    }
    let start = start.parse::<usize>()?;
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<usize>()?.min(size - 1)
    };
    if end < start {
        bail!("R2 Range 结束位置小于开始位置");
    }
    Ok((start, end - start + 1))
}

fn metadata_response(metadata: Value, bytes: &[u8]) -> Response {
    metadata_response_status(StatusCode::OK, metadata, bytes)
}

fn metadata_response_status(status: StatusCode, metadata: Value, bytes: &[u8]) -> Response {
    let metadata = serde_json::to_vec(&metadata).expect("R2 metadata is serializable");
    let mut body = Vec::with_capacity(metadata.len() + bytes.len());
    body.extend_from_slice(&metadata);
    body.extend_from_slice(bytes);
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        METADATA_SIZE_HEADER,
        HeaderValue::from_str(&metadata.len().to_string()).unwrap(),
    );
    response
}

fn object_not_found(key: &str) -> Response {
    r2_error_message(
        StatusCode::NOT_FOUND,
        10007,
        &format!("R2 对象 {key} 不存在"),
    )
}

fn backend_error(error: anyhow::Error) -> Response {
    let message = format!("{error:#}");
    if message.contains("不存在") {
        r2_error_message(StatusCode::NOT_FOUND, 10007, &message)
    } else if message.contains("配额不足") {
        r2_error_message(StatusCode::INSUFFICIENT_STORAGE, 10027, &message)
    } else {
        r2_error_message(StatusCode::BAD_GATEWAY, 10001, &message)
    }
}

fn r2_error(status: StatusCode, code: u32, error: anyhow::Error) -> Response {
    r2_error_message(status, code, &format!("{error:#}"))
}

fn r2_error_message(status: StatusCode, code: u32, message: &str) -> Response {
    // HTTP field values are ASCII. Keep the useful localized diagnostic in the
    // response body and give workerd a stable, parseable protocol error header.
    let wire_message = if message.is_ascii() {
        message
    } else {
        "RandallFlare R2 operation failed"
    };
    let error = json!({ "version": 1, "v4code": code, "message": wire_message }).to_string();
    let mut response = (status, message.to_string()).into_response();
    response.headers_mut().insert(
        ERROR_HEADER,
        HeaderValue::from_str(&error).unwrap_or_else(|_| {
            HeaderValue::from_static("{\"version\":1,\"v4code\":10001,\"message\":\"R2 error\"}")
        }),
    );
    response
}

struct JsonBody(Value);

impl IntoResponse for JsonBody {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self.0).expect("R2 response is serializable");
        let mut response = body.into_response();
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_bounded_and_support_suffixes() {
        assert_eq!(parse_range_header("bytes=2-4", 10).unwrap(), (2, 3));
        assert_eq!(parse_range_header("bytes=-3", 10).unwrap(), (7, 3));
        assert_eq!(parse_range_header("bytes=8-", 10).unwrap(), (8, 2));
        assert!(parse_range_header("bytes=9-2", 10).is_err());
        assert_eq!(json_u64(&json!("18446744073709551615")), Some(u64::MAX));
        assert_eq!(json_u64(&json!(7)), Some(7));
        assert_eq!(
            requested_range(&json!({ "range": { "offset": "7", "length": "5" } }), 22).unwrap(),
            Some((7, 5))
        );
    }

    #[test]
    fn r2_conditions_cover_wildcards_etags_and_dates() {
        let metadata = ObjectMeta {
            key: "hello".into(),
            sha256: "ab".repeat(32),
            size: 1,
            etag: "tag-1".into(),
            content_type: None,
            custom_metadata: Default::default(),
            http_metadata: Default::default(),
            storage: crate::objectstore::StorageLocation::Local,
            uploaded_at_ms: 12_345,
        };
        assert!(condition_matches(
            Some(&json!({ "etagMatches": [{ "type": "strong", "value": "tag-1" }] })),
            Some(&metadata)
        ));
        assert!(!condition_matches(
            Some(&json!({ "etagMatches": [{ "type": "wildcard", "value": "" }] })),
            None
        ));
        assert!(condition_matches(
            Some(&json!({ "etagDoesNotMatch": [{ "type": "wildcard", "value": "" }] })),
            None
        ));
        assert!(!condition_matches(
            Some(&json!({ "uploadedBefore": "12000" })),
            Some(&metadata)
        ));
        assert!(condition_matches(
            Some(&json!({ "uploadedAfter": "12000" })),
            Some(&metadata)
        ));
    }
}
