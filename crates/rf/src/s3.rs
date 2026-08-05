//! R2 S3 credentials and a path-style AWS Signature Version 4 endpoint.

use crate::node::{now_ms, Node};
use crate::resource::{self, ResourceRecord};
use anyhow::{bail, Context, Result};
use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use zeroize::{Zeroize, Zeroizing};

pub const CREDENTIAL_KIND: &str = "r2_s3_credential";
pub const CREDENTIAL_SCHEMA: u8 = 1;
const SECRET_PURPOSE: &str = "r2-s3-signature-v4";
const MAX_S3_BODY: usize = crate::r2::MAX_DIRECT_OBJECT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketGrant {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3CredentialSpec {
    pub schema: u8,
    pub label: String,
    pub access_key_id: String,
    pub secret: crate::sealed::SealedValue,
    #[serde(default)]
    pub acl_enabled: bool,
    #[serde(default)]
    pub grants: BTreeMap<String, BucketGrant>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub revoked_at_ms: Option<u64>,
}

impl S3CredentialSpec {
    pub fn validate(&self) -> Result<()> {
        if self.schema != CREDENTIAL_SCHEMA {
            bail!("不支持此版本的 R2/S3 凭据");
        }
        if self.label.trim().is_empty()
            || self.label.len() > 120
            || self.label.contains(['\r', '\n'])
        {
            bail!("R2/S3 凭据名称必须为 1 至 120 个字符");
        }
        if self.access_key_id.len() < 16
            || self.access_key_id.len() > 64
            || !self
                .access_key_id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            bail!("R2/S3 Access Key ID 无效");
        }
        if self.secret.nonce_base64.len() > 128 || self.secret.ciphertext_base64.len() > 1024 {
            bail!("R2/S3 Secret Access Key 密文无效");
        }
        if self.created_at_ms == 0 || self.revoked_at_ms.is_some_and(|at| at < self.created_at_ms) {
            bail!("R2/S3 凭据时间无效");
        }
        if self.grants.len() > 1024 {
            bail!("单个 R2/S3 凭据最多授权 1024 个 bucket");
        }
        for (bucket, grant) in &self.grants {
            if !rf_core::manifest::valid_name(bucket) || (!grant.read && !grant.write) {
                bail!("R2/S3 bucket 授权无效：{bucket}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct S3CredentialView {
    pub id: String,
    pub version: u64,
    pub label: String,
    pub access_key_id: String,
    pub acl_enabled: bool,
    pub grants: BTreeMap<String, BucketGrant>,
    pub created_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
    pub last_used_at_ms: Option<u64>,
    pub active: bool,
}

pub fn mint(
    node: &Node,
    label: String,
    acl_enabled: bool,
    grants: BTreeMap<String, BucketGrant>,
) -> Result<(ResourceRecord, String, String)> {
    let access_key_id = format!("RFR2{}", hex::encode_upper(rand::random::<[u8; 11]>()));
    let raw_secret =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 30]>());
    let name = format!("s3-{}", access_key_id.to_ascii_lowercase());
    if resource::head(node, CREDENTIAL_KIND, &name).is_some() {
        bail!("R2/S3 凭据随机标识碰撞，请重试");
    }
    let cluster_secret = node.cfg.cluster_secret_bytes()?;
    let spec = S3CredentialSpec {
        schema: CREDENTIAL_SCHEMA,
        label: label.trim().to_string(),
        access_key_id: access_key_id.clone(),
        secret: crate::sealed::seal(
            &cluster_secret,
            SECRET_PURPOSE,
            &name,
            raw_secret.as_bytes(),
        )?,
        acl_enabled,
        grants,
        created_at_ms: now_ms(),
        revoked_at_ms: None,
    };
    validate_grant_buckets(node, &spec)?;
    spec.validate()?;
    let record = resource::prepare_after(
        CREDENTIAL_KIND,
        name,
        serde_json::to_value(spec)?,
        false,
        None,
    )?;
    Ok((record, access_key_id, raw_secret))
}

pub fn update(
    node: &Node,
    id: &str,
    label: Option<String>,
    acl_enabled: Option<bool>,
    grants: Option<BTreeMap<String, BucketGrant>>,
    revoke: bool,
) -> Result<ResourceRecord> {
    let head = resource::head(node, CREDENTIAL_KIND, id).context("R2/S3 凭据不存在")?;
    if head.resource.deleted {
        bail!("R2/S3 凭据不存在");
    }
    let mut spec = credential_spec(&head.resource)?;
    if let Some(label) = label {
        spec.label = label.trim().to_string();
    }
    if let Some(enabled) = acl_enabled {
        spec.acl_enabled = enabled;
    }
    if let Some(grants) = grants {
        spec.grants = grants;
    }
    if revoke {
        spec.revoked_at_ms = Some(now_ms());
    }
    validate_grant_buckets(node, &spec)?;
    spec.validate()?;
    resource::prepare_after(
        CREDENTIAL_KIND,
        id,
        serde_json::to_value(spec)?,
        false,
        Some(&head),
    )
}

pub fn credential_spec(record: &ResourceRecord) -> Result<S3CredentialSpec> {
    if record.kind != CREDENTIAL_KIND {
        bail!("平台资源不是 R2/S3 凭据");
    }
    let spec: S3CredentialSpec = serde_json::from_value(record.spec()?)?;
    spec.validate()?;
    Ok(spec)
}

fn validate_grant_buckets(node: &Node, spec: &S3CredentialSpec) -> Result<()> {
    for bucket in spec.grants.keys() {
        if crate::r2::bucket_record(node, bucket).is_none() {
            bail!("R2/S3 授权引用了不存在的 bucket：{bucket}");
        }
    }
    Ok(())
}

pub fn views(node: &Node) -> Vec<S3CredentialView> {
    resource::heads(node, Some(CREDENTIAL_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .filter_map(|view| {
            let spec = credential_spec(&view.resource).ok()?;
            let id = view.resource.name.clone();
            let active = spec.revoked_at_ms.is_none();
            Some(S3CredentialView {
                id: id.clone(),
                version: view.resource.version,
                label: spec.label,
                access_key_id: spec.access_key_id,
                acl_enabled: spec.acl_enabled,
                grants: spec.grants,
                created_at_ms: spec.created_at_ms,
                revoked_at_ms: spec.revoked_at_ms,
                last_used_at_ms: node.store.credential_last_used(&id).ok().flatten(),
                active,
            })
        })
        .collect()
}

struct Authenticated {
    id: String,
    spec: S3CredentialSpec,
}

impl Authenticated {
    fn may(&self, bucket: &str, write: bool) -> bool {
        if !self.spec.acl_enabled {
            return true;
        }
        self.spec.grants.get(bucket).is_some_and(
            |grant| {
                if write {
                    grant.write
                } else {
                    grant.read
                }
            },
        )
    }
}

impl Drop for Authenticated {
    fn drop(&mut self) {
        self.spec.secret.nonce_base64.zeroize();
        self.spec.secret.ciphertext_base64.zeroize();
    }
}

#[derive(Debug)]
struct ParsedAuthorization {
    access_key_id: String,
    date_stamp: String,
    region: String,
    signed_headers: Vec<String>,
    signature: String,
}

pub async fn handle(node: Arc<Node>, request: Request<Body>) -> Response {
    match handle_result(&node, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!("S3 request failed: {error:#}");
            classified_error(&error)
        }
    }
}

fn classified_error(error: &anyhow::Error) -> Response {
    let text = format!("{error:#}");
    if text.contains("bucket 不存在") {
        return s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "bucket 不存在", None);
    }
    if text.contains("分片上传不存在")
        || text.contains("分片上传已过期")
        || text.contains("分片缺少")
    {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "分片上传不存在或已过期",
            None,
        );
    }
    if text.contains("配额") {
        return s3_error(
            StatusCode::FORBIDDEN,
            "QuotaExceeded",
            "R2 存储配额不足",
            None,
        );
    }
    if text.contains("length limit")
        || text.contains("body length")
        || text.contains("不得超过")
        || text.contains("过大")
    {
        return s3_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "EntityTooLarge",
            "请求正文或对象过大",
            None,
        );
    }
    if text.contains("rclone")
        || text.contains("存储后端")
        || text.contains("没有可用")
        || text.contains("not on local disk")
    {
        return s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "对象存储后端暂时不可用",
            None,
        );
    }
    if text.contains("无效")
        || text.contains("不完整")
        || text.contains("必须")
        || text.contains("校验")
        || text.contains("摘要")
        || text.contains("ETag")
    {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "S3 请求参数或正文无效",
            None,
        );
    }
    s3_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        "RandallFlare 内部错误",
        None,
    )
}

async fn handle_result(node: &Node, request: Request<Body>) -> Result<Response> {
    let auth = match authenticate(node, request.method(), request.uri(), request.headers()) {
        Ok(auth) => auth,
        Err(response) => return Ok(*response),
    };
    let method = request.method().clone();
    let query = parse_query(request.uri().query().unwrap_or_default());
    let raw_path = request.uri().path().strip_prefix("/s3").unwrap_or_default();
    let decoded = percent_encoding::percent_decode_str(raw_path.trim_start_matches('/'))
        .decode_utf8()
        .map_err(|_| anyhow::anyhow!("S3 路径不是有效 UTF-8"))?
        .into_owned();
    let (bucket, key) = decoded
        .split_once('/')
        .map(|(bucket, key)| (bucket, Some(key)))
        .unwrap_or((decoded.as_str(), None));

    if bucket.is_empty() {
        if method != Method::GET {
            return Ok(s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "服务根目录仅支持 GET",
                None,
            ));
        }
        return Ok(list_buckets(node, &auth));
    }
    if crate::r2::bucket_record(node, bucket).is_none() {
        return Ok(s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "bucket 不存在",
            Some(bucket),
        ));
    }
    let write = matches!(method, Method::PUT | Method::POST | Method::DELETE);
    if !auth.may(bucket, write) {
        return Ok(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "此凭据没有所需的 bucket 权限",
            Some(bucket),
        ));
    }

    let response = match key {
        None if method == Method::HEAD => StatusCode::OK.into_response(),
        None if method == Method::GET && query.contains_key("uploads") => {
            list_multipart_uploads(node, bucket, &query).await?
        }
        None if method == Method::GET => list_objects(node, bucket, &query).await?,
        // rclone and several SDKs issue CreateBucket before the first upload.
        // Bucket definitions remain operator-signed resources, so acknowledge
        // the call only when that bucket already exists and the credential has
        // write access; never create unsigned control-plane state here.
        None if method == Method::PUT => StatusCode::OK.into_response(),
        None => s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "请在控制台创建或删除 bucket",
            Some(bucket),
        ),
        Some("") => s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidURI",
            "对象 key 不能为空",
            Some(bucket),
        ),
        Some(key) => object_request(node, request, bucket, key, &query).await?,
    };
    Ok(response)
}

fn authenticate(
    node: &Node,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> std::result::Result<Authenticated, Box<Response>> {
    let parsed = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_authorization)
        .ok_or_else(|| {
            boxed_s3_error(
                StatusCode::UNAUTHORIZED,
                "InvalidRequest",
                "缺少或无法解析 Signature V4 Authorization",
                None,
            )
        })?;
    let date = headers
        .get("x-amz-date")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let request_ms = parse_amz_date(date).ok_or_else(|| {
        boxed_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "x-amz-date 格式无效",
            None,
        )
    })?;
    if now_ms().abs_diff(request_ms) > 15 * 60 * 1000 || !date.starts_with(&parsed.date_stamp) {
        return Err(boxed_s3_error(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "请求时间与节点相差超过 15 分钟",
            None,
        ));
    }
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            boxed_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "缺少 x-amz-content-sha256",
                None,
            )
        })?;
    if payload_hash != "UNSIGNED-PAYLOAD"
        && (payload_hash.len() != 64 || !payload_hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(boxed_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "x-amz-content-sha256 无效",
            None,
        ));
    }
    let (id, spec) = resource::heads(node, Some(CREDENTIAL_KIND))
        .into_iter()
        .filter(|view| !view.resource.deleted)
        .find_map(|view| {
            let spec = credential_spec(&view.resource).ok()?;
            (spec.access_key_id == parsed.access_key_id && spec.revoked_at_ms.is_none())
                .then_some((view.resource.name, spec))
        })
        .ok_or_else(|| {
            boxed_s3_error(
                StatusCode::FORBIDDEN,
                "InvalidAccessKeyId",
                "Access Key ID 不存在",
                None,
            )
        })?;
    let cluster_secret = node.cfg.cluster_secret_bytes().map_err(|_| {
        boxed_s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "节点凭据配置不可用",
            None,
        )
    })?;
    let raw_secret = Zeroizing::new(
        crate::sealed::open(&cluster_secret, SECRET_PURPOSE, &id, &spec.secret).map_err(|_| {
            boxed_s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "节点无法解密凭据",
                None,
            )
        })?,
    );
    let expected = {
        let secret_text = std::str::from_utf8(&raw_secret).map_err(|_| {
            boxed_s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "节点凭据编码无效",
                None,
            )
        })?;
        expected_signature(
            &parsed,
            secret_text,
            method,
            uri,
            headers,
            payload_hash,
            date,
        )
        .map_err(|_| {
            boxed_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "签名规范化失败",
                None,
            )
        })?
    };
    if !constant_time_eq(expected.as_bytes(), parsed.signature.as_bytes()) {
        return Err(boxed_s3_error(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "请求签名不匹配",
            None,
        ));
    }
    let _ = node.store.touch_credential(&id, now_ms());
    Ok(Authenticated { id, spec })
}

fn boxed_s3_error(
    status: StatusCode,
    code: &str,
    message: &str,
    resource: Option<&str>,
) -> Box<Response> {
    Box::new(s3_error(status, code, message, resource))
}

fn parse_authorization(value: &str) -> Option<ParsedAuthorization> {
    let rest = value.strip_prefix("AWS4-HMAC-SHA256 ")?;
    let mut fields = BTreeMap::new();
    for component in rest.split(',') {
        let (key, value) = component.trim().split_once('=')?;
        fields.insert(key, value);
    }
    let credential = fields.get("Credential")?.split('/').collect::<Vec<_>>();
    if credential.len() != 5 || credential[3] != "s3" || credential[4] != "aws4_request" {
        return None;
    }
    let signed_headers = fields
        .get("SignedHeaders")?
        .split(';')
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if signed_headers.is_empty()
        || signed_headers.windows(2).any(|pair| pair[0] >= pair[1])
        || !signed_headers.iter().any(|name| name == "host")
    {
        return None;
    }
    let signature = fields.get("Signature")?.to_ascii_lowercase();
    if signature.len() != 64 || !signature.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(ParsedAuthorization {
        access_key_id: credential[0].to_string(),
        date_stamp: credential[1].to_string(),
        region: credential[2].to_string(),
        signed_headers,
        signature,
    })
}

fn expected_signature(
    parsed: &ParsedAuthorization,
    secret: &str,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    payload_hash: &str,
    amz_date: &str,
) -> Result<String> {
    let mut canonical_headers = String::new();
    for name in &parsed.signed_headers {
        let mut values = headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(",");
        // In HTTP/2 the signed `host` header is carried as the `:authority`
        // pseudo-header and Hyper exposes it on the URI, not HeaderMap.
        if values.is_empty() && name == "host" {
            values = uri
                .authority()
                .map(|authority| authority.as_str().to_string())
                .unwrap_or_default();
        }
        if values.is_empty() {
            bail!("签名声明的请求头不存在：{name}");
        }
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&collapse_whitespace(&values));
        canonical_headers.push('\n');
    }
    let signed = parsed.signed_headers.join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        uri.path(),
        canonical_query(uri.query().unwrap_or_default()),
        canonical_headers,
        signed,
        payload_hash,
    );
    let scope = format!("{}/{}/s3/aws4_request", parsed.date_stamp, parsed.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let date_key = hmac(
        format!("AWS4{secret}").as_bytes(),
        parsed.date_stamp.as_bytes(),
    );
    let region_key = hmac(&date_key, parsed.region.as_bytes());
    let service_key = hmac(&region_key, b"s3");
    let signing_key = hmac(&service_key, b"aws4_request");
    Ok(hex::encode(hmac(&signing_key, string_to_sign.as_bytes())))
}

fn hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts all key sizes");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

fn collapse_whitespace(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_query(raw: &str) -> BTreeMap<String, Vec<String>> {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for component in raw.split('&').filter(|value| !value.is_empty()) {
        let (key, value) = component.split_once('=').unwrap_or((component, ""));
        let key = percent_encoding::percent_decode_str(key)
            .decode_utf8_lossy()
            .into_owned();
        let value = percent_encoding::percent_decode_str(value)
            .decode_utf8_lossy()
            .into_owned();
        values.entry(key).or_default().push(value);
    }
    values
}

fn canonical_query(raw: &str) -> String {
    let mut values = Vec::new();
    for component in raw.split('&').filter(|value| !value.is_empty()) {
        let (key, value) = component.split_once('=').unwrap_or((component, ""));
        let key = aws_encode(&percent_encoding::percent_decode_str(key).collect::<Vec<_>>());
        let value = aws_encode(&percent_encoding::percent_decode_str(value).collect::<Vec<_>>());
        values.push((key, value));
    }
    values.sort();
    values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_encode(value: &[u8]) -> String {
    let mut encoded = String::new();
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn query_one<'a>(query: &'a BTreeMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    query
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn list_buckets(node: &Node, auth: &Authenticated) -> Response {
    let buckets = crate::r2::bucket_records(node)
        .into_iter()
        .filter(|(view, _)| {
            !auth.spec.acl_enabled || auth.spec.grants.contains_key(&view.resource.name)
        })
        .map(|(view, _)| {
            format!(
                "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
                escape_xml(&view.resource.name),
                timestamp(0)
            )
        })
        .collect::<String>();
    xml_response(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>{}</ID></Owner><Buckets>{buckets}</Buckets></ListAllMyBucketsResult>",
            escape_xml(&auth.id)
        ),
    )
}

async fn list_objects(
    node: &Node,
    bucket: &str,
    query: &BTreeMap<String, Vec<String>>,
) -> Result<Response> {
    let prefix = query_one(query, "prefix").unwrap_or_default();
    let cursor = query_one(query, "continuation-token")
        .and_then(|value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .ok()
        })
        .and_then(|value| String::from_utf8(value).ok());
    let limit = query_one(query, "max-keys")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);
    let delimiter = query_one(query, "delimiter").unwrap_or_default();
    let list = if delimiter.is_empty() {
        crate::r2::list_objects(node, bucket, prefix, cursor.as_deref(), limit).await?
    } else {
        crate::r2::list_objects_delimited(node, bucket, prefix, cursor.as_deref(), limit, delimiter)
            .await?
    };
    let contents = list
        .objects
        .iter()
        .map(|object| {
            format!(
                "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                escape_xml(&object.key),
                timestamp(object.uploaded_at_ms),
                escape_xml(&object.etag),
                object.size
            )
        })
        .collect::<String>();
    let prefixes = list
        .delimited_prefixes
        .iter()
        .map(|prefix| {
            format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                escape_xml(prefix)
            )
        })
        .collect::<String>();
    let next = list
        .cursor
        .map(|cursor| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cursor))
        .map(|cursor| {
            format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                escape_xml(&cursor)
            )
        })
        .unwrap_or_default();
    Ok(xml_response(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{limit}</MaxKeys><IsTruncated>{}</IsTruncated>{next}{contents}{prefixes}</ListBucketResult>",
            escape_xml(bucket),
            escape_xml(prefix),
            list.objects.len() + list.delimited_prefixes.len(),
            list.truncated
        ),
    ))
}

async fn list_multipart_uploads(
    node: &Node,
    bucket: &str,
    query: &BTreeMap<String, Vec<String>>,
) -> Result<Response> {
    let prefix = query_one(query, "prefix").unwrap_or_default();
    let cursor = query_one(query, "upload-id-marker").filter(|value| !value.is_empty());
    let limit = query_one(query, "max-uploads")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);
    let list = crate::r2::list_multipart_uploads(node, bucket, prefix, cursor, limit).await?;
    let uploads = list
        .uploads
        .iter()
        .map(|upload| {
            format!(
                "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiator><ID>RandallFlare</ID><DisplayName>RandallFlare</DisplayName></Initiator><Owner><ID>RandallFlare</ID><DisplayName>RandallFlare</DisplayName></Owner><StorageClass>STANDARD</StorageClass><Initiated>{}</Initiated></Upload>",
                escape_xml(&upload.key),
                escape_xml(&upload.upload_id),
                timestamp(upload.created_at_ms),
            )
        })
        .collect::<String>();
    let next_marker = list
        .cursor
        .as_deref()
        .map(|cursor| {
            format!(
                "<NextUploadIdMarker>{}</NextUploadIdMarker>",
                escape_xml(cursor)
            )
        })
        .unwrap_or_default();
    Ok(xml_response(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker>{next_marker}<Prefix>{}</Prefix><MaxUploads>{limit}</MaxUploads><IsTruncated>{}</IsTruncated>{uploads}</ListMultipartUploadsResult>",
            escape_xml(bucket),
            escape_xml(query_one(query, "key-marker").unwrap_or_default()),
            escape_xml(query_one(query, "upload-id-marker").unwrap_or_default()),
            escape_xml(prefix),
            list.truncated,
        ),
    ))
}

async fn object_request(
    node: &Node,
    request: Request<Body>,
    bucket: &str,
    key: &str,
    query: &BTreeMap<String, Vec<String>>,
) -> Result<Response> {
    let method = request.method().clone();
    if method == Method::POST && query.contains_key("uploads") {
        let upload =
            crate::r2::create_multipart_upload(node, bucket, key, put_options(request.headers()))
                .await?;
        return Ok(xml_response(
            StatusCode::OK,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
                escape_xml(bucket),
                escape_xml(key),
                upload.upload_id
            ),
        ));
    }
    if let Some(upload_id) = query_one(query, "uploadId") {
        if method == Method::GET {
            let detail = crate::r2::multipart_upload_detail(node, bucket, upload_id).await?;
            if detail.upload.key != key {
                bail!("R2 分片上传不存在");
            }
            let marker = query_one(query, "part-number-marker")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(0);
            let limit = query_one(query, "max-parts")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(1000)
                .clamp(1, 1000);
            let mut parts = detail
                .parts
                .into_iter()
                .filter(|part| part.part_number > marker)
                .take(limit + 1)
                .collect::<Vec<_>>();
            let truncated = parts.len() > limit;
            parts.truncate(limit);
            let next_marker = truncated
                .then(|| parts.last().map(|part| part.part_number))
                .flatten()
                .map(|part| format!("<NextPartNumberMarker>{part}</NextPartNumberMarker>"))
                .unwrap_or_default();
            let entries = parts
                .iter()
                .map(|part| {
                    format!(
                        "<Part><PartNumber>{}</PartNumber><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag><Size>{}</Size></Part>",
                        part.part_number,
                        timestamp(detail.upload.created_at_ms),
                        escape_xml(&part.etag),
                        part.size,
                    )
                })
                .collect::<String>();
            return Ok(xml_response(
                StatusCode::OK,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><PartNumberMarker>{marker}</PartNumberMarker>{next_marker}<MaxParts>{limit}</MaxParts><IsTruncated>{truncated}</IsTruncated>{entries}</ListPartsResult>",
                    escape_xml(bucket),
                    escape_xml(key),
                    escape_xml(upload_id),
                ),
            ));
        }
        if method == Method::DELETE {
            crate::r2::abort_multipart_upload(node, bucket, key, upload_id).await?;
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        if method == Method::PUT {
            let part_number = query_one(query, "partNumber")
                .and_then(|value| value.parse::<u32>().ok())
                .context("S3 partNumber 无效")?;
            let declared = declared_payload_hash(request.headers());
            let body = to_bytes(request.into_body(), crate::r2::MAX_MULTIPART_PART_BYTES).await?;
            verify_payload_hash(&body, declared.as_deref())?;
            let part =
                crate::r2::upload_part(node, bucket, key, upload_id, part_number, &body).await?;
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&format!("\"{}\"", part.etag))?,
            );
            return Ok(response);
        }
        if method == Method::POST {
            let declared = declared_payload_hash(request.headers());
            let body = to_bytes(request.into_body(), 1024 * 1024).await?;
            verify_payload_hash(&body, declared.as_deref())?;
            let parts = parse_completed_parts(
                std::str::from_utf8(&body).context("S3 CompleteMultipartUpload XML 不是 UTF-8")?,
            )?;
            let object =
                crate::r2::complete_multipart_upload(node, bucket, key, upload_id, &parts).await?;
            return Ok(xml_response(
                StatusCode::OK,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><ETag>&quot;{}&quot;</ETag></CompleteMultipartUploadResult>",
                    escape_xml(bucket),
                    escape_xml(key),
                    escape_xml(&object.etag)
                ),
            ));
        }
    }
    match method {
        Method::GET | Method::HEAD => {
            get_object_response(node, bucket, key, method == Method::HEAD, request.headers()).await
        }
        Method::PUT => {
            let options = put_options(request.headers());
            let declared = declared_payload_hash(request.headers());
            let body = to_bytes(request.into_body(), MAX_S3_BODY).await?;
            verify_payload_hash(&body, declared.as_deref())?;
            let object = crate::r2::put_object(node, bucket, key, &body, options).await?;
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&format!("\"{}\"", object.etag))?,
            );
            Ok(response)
        }
        Method::DELETE => {
            crate::r2::delete_object(node, bucket, key).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Ok(s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "对象操作方法不受支持",
            Some(key),
        )),
    }
}

fn declared_payload_hash(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn put_options(headers: &HeaderMap) -> crate::r2::PutOptions {
    let mut custom_metadata = serde_json::Map::new();
    for (name, value) in headers {
        if let Some(name) = name.as_str().strip_prefix("x-amz-meta-") {
            if let Ok(value) = value.to_str() {
                custom_metadata.insert(name.to_string(), Value::String(value.to_string()));
            }
        }
    }
    let mut http_metadata = serde_json::Map::new();
    for (header_name, field) in [
        (header::CACHE_CONTROL, "cacheControl"),
        (header::CONTENT_DISPOSITION, "contentDisposition"),
        (header::CONTENT_ENCODING, "contentEncoding"),
        (header::CONTENT_LANGUAGE, "contentLanguage"),
    ] {
        if let Some(value) = headers
            .get(header_name)
            .and_then(|value| value.to_str().ok())
        {
            http_metadata.insert(field.into(), Value::String(value.into()));
        }
    }
    crate::r2::PutOptions {
        content_type: headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        custom_metadata,
        http_metadata,
    }
}

async fn get_object_response(
    node: &Node,
    bucket: &str,
    key: &str,
    head_only: bool,
    request_headers: &HeaderMap,
) -> Result<Response> {
    let Some(metadata) = crate::r2::head_object(node, bucket, key).await? else {
        return Ok(s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "对象不存在",
            Some(key),
        ));
    };
    if request_headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !etag_header_matches(value, &metadata.etag))
    {
        return Ok(s3_error(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            "If-Match 条件不满足",
            Some(key),
        ));
    }
    if request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| etag_header_matches(value, &metadata.etag))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&format!("\"{}\"", metadata.etag))?,
        );
        return Ok(response);
    }

    let range = request_headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| byte_range(value, metadata.size));
    let (status, start, length, content_range) = match range {
        Some(Ok((start, end))) => (
            StatusCode::PARTIAL_CONTENT,
            start,
            end - start + 1,
            Some(format!("bytes {start}-{end}/{}", metadata.size)),
        ),
        Some(Err(())) => {
            let mut response = s3_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "请求的字节范围超出对象边界",
                Some(key),
            );
            response.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{}", metadata.size))?,
            );
            return Ok(response);
        }
        None => (StatusCode::OK, 0, metadata.size, None),
    };
    let mut response = if head_only {
        status.into_response()
    } else {
        let Some((current, file)) = crate::r2::materialize_object(node, bucket, key).await? else {
            return Ok(s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "对象不存在",
                Some(key),
            ));
        };
        if current.sha256 != metadata.sha256 {
            return Ok(s3_error(
                StatusCode::CONFLICT,
                "OperationAborted",
                "对象在读取期间发生变化，请重试",
                Some(key),
            ));
        }
        Response::builder()
            .status(status)
            .body(Body::from_stream(file.stream(start, length).await?))?
    };
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string())?,
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", metadata.etag))?,
    );
    response.headers_mut().insert(
        header::LAST_MODIFIED,
        HeaderValue::from_str(&httpdate::fmt_http_date(
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(metadata.uploaded_at_ms),
        ))?,
    );
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(content_range) = content_range {
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&content_range)?,
        );
    }
    if let Some(content_type) = metadata.content_type.as_deref() {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_str(content_type)?);
    }
    for (name, value) in metadata.custom_metadata {
        if let Some(value) = value.as_str() {
            if let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::from_bytes(format!("x-amz-meta-{name}").as_bytes()),
                HeaderValue::from_str(value),
            ) {
                response.headers_mut().insert(name, value);
            }
        }
    }
    Ok(response)
}

fn etag_header_matches(header: &str, etag: &str) -> bool {
    header.split(',').any(|candidate| {
        let candidate = candidate.trim().trim_start_matches("W/").trim_matches('"');
        candidate == "*" || candidate == etag
    })
}

fn byte_range(header: &str, size: u64) -> std::result::Result<(u64, u64), ()> {
    let value = header.strip_prefix("bytes=").ok_or(())?;
    if size == 0 || value.contains(',') {
        return Err(());
    }
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        return Ok((size.saturating_sub(suffix), size - 1));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if start >= size || start > end {
        return Err(());
    }
    Ok((start, end))
}

fn verify_payload_hash(body: &[u8], declared: Option<&str>) -> Result<()> {
    if let Some(declared) = declared.filter(|value| *value != "UNSIGNED-PAYLOAD") {
        if !constant_time_eq(
            hex::encode(Sha256::digest(body)).as_bytes(),
            declared.to_ascii_lowercase().as_bytes(),
        ) {
            bail!("S3 请求正文摘要与 x-amz-content-sha256 不匹配");
        }
    }
    Ok(())
}

fn parse_completed_parts(xml: &str) -> Result<Vec<crate::r2::PublishedPart>> {
    let mut parts = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Part>") {
        rest = &rest[start + 6..];
        let end = rest
            .find("</Part>")
            .context("CompleteMultipartUpload 缺少 </Part>")?;
        let part = &rest[..end];
        let number = xml_value(part, "PartNumber")
            .context("分片缺少 PartNumber")?
            .parse::<u32>()?;
        let etag = completed_etag(xml_value(part, "ETag").context("分片缺少 ETag")?)?;
        parts.push(crate::r2::PublishedPart {
            part_number: number,
            etag,
        });
        rest = &rest[end + 7..];
    }
    if parts.is_empty() {
        bail!("CompleteMultipartUpload 至少需要一个 Part");
    }
    Ok(parts)
}

fn completed_etag(value: &str) -> Result<String> {
    let value = value.trim();
    let value = [
        ("\"", "\""),
        ("&quot;", "&quot;"),
        ("&#34;", "&#34;"),
        ("&#x22;", "&#x22;"),
        ("&#X22;", "&#X22;"),
    ]
    .into_iter()
    .find_map(|(prefix, suffix)| {
        value
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
    })
    .unwrap_or(value);
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        bail!("分片 ETag 无效");
    }
    Ok(value.to_string())
}

fn xml_value<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let start_tag = format!("<{name}>");
    let end_tag = format!("</{name}>");
    let start = xml.find(&start_tag)? + start_tag.len();
    let end = xml[start..].find(&end_tag)? + start;
    Some(&xml[start..end])
}

fn parse_amz_date(value: &str) -> Option<u64> {
    if value.len() != 16 || value.as_bytes().get(8) != Some(&b'T') || !value.ends_with('Z') {
        return None;
    }
    let number = |range: std::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let year = number(0..4)?;
    let month = number(4..6)?;
    let day = number(6..8)?;
    let hour = number(9..11)?;
    let minute = number(11..13)?;
    let second = number(13..15)?;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)?
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)?;
    u64::try_from(seconds).ok()?.checked_mul(1000)
}

fn days_in_month(year: i64, month: i64) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if leap { 29 } else { 28 }),
        _ => None,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let shifted = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * shifted + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn timestamp(at_ms: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp((at_ms / 1000) as i64)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

fn xml_response(status: StatusCode, xml: String) -> Response {
    let mut response = (status, xml).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

fn s3_error(status: StatusCode, code: &str, message: &str, resource: Option<&str>) -> Response {
    xml_response(
        status,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code><Message>{}</Message>{}</Error>",
            escape_xml(code),
            escape_xml(message),
            resource
                .map(|value| format!("<Resource>{}</Resource>", escape_xml(value)))
                .unwrap_or_default()
        ),
    )
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_and_dates_are_strict() {
        let parsed = parse_authorization("AWS4-HMAC-SHA256 Credential=RFR2TEST/20260804/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(parsed.region, "auto");
        assert_eq!(parse_amz_date("20260804T120000Z"), Some(1_785_844_800_000));
        assert!(parse_amz_date("20261304T120000Z").is_none());
        assert!(parse_amz_date("20260229T120000Z").is_none());
        assert!(parse_amz_date("20240229T120000Z").is_some());
    }

    #[test]
    fn query_canonicalization_sorts_encoded_pairs() {
        assert_eq!(
            canonical_query("z=2&a=hello%20world&a=0"),
            "a=0&a=hello%20world&z=2"
        );
    }

    #[test]
    fn completion_xml_is_bounded_to_declared_parts() {
        let parts = parse_completed_parts("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"abc\"</ETag></Part></CompleteMultipartUpload>").unwrap();
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[0].etag, "abc");
        let parts = parse_completed_parts("<CompleteMultipartUpload><Part><ETag>&#34;def&#34;</ETag><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>").unwrap();
        assert_eq!(parts[0].part_number, 2);
        assert_eq!(parts[0].etag, "def");
    }

    #[test]
    fn ranges_and_etag_conditions_match_s3_get_semantics() {
        assert_eq!(byte_range("bytes=2-4", 10), Ok((2, 4)));
        assert_eq!(byte_range("bytes=-3", 10), Ok((7, 9)));
        assert_eq!(byte_range("bytes=8-", 10), Ok((8, 9)));
        assert!(byte_range("bytes=10-", 10).is_err());
        assert!(byte_range("bytes=1-2,4-5", 10).is_err());
        assert!(etag_header_matches("\"abc\", \"def\"", "def"));
        assert!(etag_header_matches("*", "anything"));
        assert!(!etag_header_matches("\"abc\"", "def"));
    }
}
