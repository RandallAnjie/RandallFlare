//! Loopback Binary Deliver execution service for `env.<BINDING>.exec()`.
//!
//! Every invocation re-authorizes the signed Worker binding and signed binary
//! policy. The executable is SHA-256 verified, then run inside a fresh
//! bubblewrap namespace with a private writable directory, cleared environment,
//! dropped capabilities and optional network namespace. No host data directory,
//! cluster credential or operator key is mounted into the sandbox.

use crate::binary::{self, BinarySpec};
use crate::node::Node;
use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::mpsc;

pub const WORKER_HEADER: &str = "x-rf-binary-worker";
pub const BINDING_HEADER: &str = "x-rf-binary-binding";
const MAX_EXEC_BODY: usize = binary::MAX_BINARY_BYTES * 4 / 3 + 1024 * 1024;
const HARD_TIMEOUT_MS: u64 = 30 * 60 * 1000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExecRequest {
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    stdin: String,
    #[serde(default)]
    stdin_base64: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    output_files: Vec<OutputFileSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OutputFileSpec {
    path: String,
    bucket: String,
    key: String,
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputFileResult {
    path: String,
    bucket: String,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecResponse {
    ok: bool,
    exit_code: i32,
    stdout: String,
    stderr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    stdout_base64: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    stderr_base64: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stdout_truncated: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stderr_truncated: bool,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    timed_out: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    uploads: Vec<OutputFileResult>,
}

pub async fn serve(node: Arc<Node>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/exec", post(exec))
        .layer(DefaultBodyLimit::max(MAX_EXEC_BODY))
        .with_state(node);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Binary Deliver binding server died: {error}");
        }
    });
    Ok(port)
}

async fn exec(
    State(node): State<Arc<Node>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match exec_inner(&node, remote, &headers, &body).await {
        Ok(output) => Json(output).into_response(),
        Err(error) => (
            classify_error(&error),
            Json(ExecResponse {
                error: Some(format!("{error:#}")),
                ..Default::default()
            }),
        )
            .into_response(),
    }
}

async fn exec_inner(
    node: &Arc<Node>,
    remote: SocketAddr,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<ExecResponse> {
    if !remote.ip().is_loopback() {
        bail!("Binary Deliver binding 仅允许本机 workerd 访问");
    }
    let worker = header(headers, WORKER_HEADER, "Binary binding 缺少来源 Worker")?;
    let binding = header(headers, BINDING_HEADER, "Binary binding 缺少绑定名")?;
    if !rf_core::manifest::valid_name(worker) || !valid_identifier(binding) {
        bail!("Binary binding 身份无效");
    }
    let manifest = node.manifest(worker).context("来源 Worker 不存在")?;
    let binary_name = crate::deploy::binary_bindings(&manifest)
        .get(binding)
        .cloned()
        .context("当前签名 Worker 清单未授权此 Binary binding")?;
    let (_, spec) = binary::record(node, &binary_name).context("Binary 定义不存在")?;
    authorize(node, &spec)?;

    let request: ExecRequest =
        serde_json::from_slice(body).context("Binary exec 请求不是有效 JSON")?;
    validate_request(&request, &spec)?;
    let stdin = decode_stdin(&request, &spec)?;
    let executable = binary::materialize(node, &binary_name, &spec).await?;
    let timeout_ms = request
        .timeout_ms
        .unwrap_or(spec.default_timeout_ms)
        .clamp(1, HARD_TIMEOUT_MS);
    run_once(
        node,
        worker,
        &binary_name,
        &spec,
        request,
        stdin,
        executable,
        timeout_ms,
    )
    .await
}

fn authorize(node: &Node, spec: &BinarySpec) -> Result<()> {
    if spec.suspended {
        bail!("Binary 已暂停");
    }
    if spec.os_arch != binary::current_os_arch() {
        bail!(
            "Binary 目标为 {}，当前节点为 {}",
            spec.os_arch,
            binary::current_os_arch()
        );
    }
    let tags = crate::placement::effective_tags(node, &node.id_hex());
    if let Some(missing) = spec.required_tags.iter().find(|tag| !tags.contains(*tag)) {
        bail!("Binary 要求当前节点具备标签 {missing}");
    }
    crate::build::configured_binary(node.cfg.build.sandbox.as_deref(), "bwrap")
        .context("当前节点未安装 Binary Deliver 必需的 bubblewrap")?;
    Ok(())
}

fn validate_request(request: &ExecRequest, spec: &BinarySpec) -> Result<()> {
    if !request.stdin.is_empty() && !request.stdin_base64.is_empty() {
        bail!("stdin 与 stdinBase64 不能同时使用");
    }
    if request.args.len() > 256
        || request
            .args
            .iter()
            .any(|value| value.len() > 16 * 1024 || value.as_bytes().contains(&0))
    {
        bail!("Binary 参数过多、过长或含有 NUL");
    }
    if request.env.len() > 128
        || request
            .env
            .iter()
            .any(|(name, value)| !valid_env(name) || name.starts_with("BD_") || value.len() > 8192)
    {
        bail!("Binary 环境变量无效，BD_ 前缀为平台保留");
    }
    if request.output_files.len() > 64 {
        bail!("Binary 每次执行最多可发布 64 个输出文件");
    }
    if !request.output_files.is_empty() && !spec.allow_r2 {
        bail!("此 Binary 策略未授权 R2 输出文件");
    }
    Ok(())
}

fn decode_stdin(request: &ExecRequest, spec: &BinarySpec) -> Result<Vec<u8>> {
    let bytes = if request.stdin_base64.is_empty() {
        request.stdin.as_bytes().to_vec()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(&request.stdin_base64)
            .context("stdinBase64 无效")?
    };
    if bytes.len() as u64 > spec.max_stdin_bytes {
        bail!(
            "Binary 标准输入 {} 字节超过上限 {} 字节",
            bytes.len(),
            spec.max_stdin_bytes
        );
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
async fn run_once(
    node: &Node,
    worker: &str,
    binary_name: &str,
    spec: &BinarySpec,
    request: ExecRequest,
    stdin: Vec<u8>,
    executable: PathBuf,
    timeout_ms: u64,
) -> Result<ExecResponse> {
    let started = Instant::now();
    let temp = create_temp_dir(node)?;
    let result = run_in_temp(
        node,
        worker,
        binary_name,
        spec,
        &request,
        &stdin,
        &executable,
        timeout_ms,
        &temp,
    )
    .await;
    let _ = std::fs::remove_dir_all(&temp);
    result.map(|mut response| {
        response.duration_ms = started.elapsed().as_millis() as u64;
        response
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_in_temp(
    node: &Node,
    worker: &str,
    binary_name: &str,
    spec: &BinarySpec,
    request: &ExecRequest,
    stdin: &[u8],
    executable: &Path,
    timeout_ms: u64,
    temp: &Path,
) -> Result<ExecResponse> {
    let bwrap = crate::build::configured_binary(node.cfg.build.sandbox.as_deref(), "bwrap")
        .context("bubblewrap 不可用")?;
    let mut command = sandbox_command(
        &bwrap,
        executable,
        temp,
        worker,
        binary_name,
        spec,
        request,
        spec.allow_network && crate::quota::policy(node)?.worker_outbound_allowed,
    )?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().context("启动 Binary 沙箱")?;
    if let Some(mut input) = child.stdin.take() {
        let stdin = stdin.to_vec();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = input.write_all(&stdin).await;
        });
    }
    let (limit_tx, mut limit_rx) = mpsc::channel(2);
    // Keep the channel open until the process exits so a normal EOF cannot be
    // mistaken for an output-limit signal in the select below.
    let _limit_guard = limit_tx.clone();
    let stdout_task = tokio::spawn(read_capped(
        child.stdout.take().context("Binary stdout 管道缺失")?,
        spec.max_output_bytes as usize,
        limit_tx.clone(),
    ));
    let stderr_task = tokio::spawn(read_capped(
        child.stderr.take().context("Binary stderr 管道缺失")?,
        spec.max_output_bytes as usize,
        limit_tx,
    ));

    enum Outcome {
        Exited(std::io::Result<std::process::ExitStatus>),
        TimedOut,
        OutputLimit,
    }
    let outcome = {
        let wait = child.wait();
        tokio::pin!(wait);
        tokio::select! {
            status = &mut wait => Outcome::Exited(status),
            _ = tokio::time::sleep(Duration::from_millis(timeout_ms)) => Outcome::TimedOut,
            _ = limit_rx.recv() => Outcome::OutputLimit,
        }
    };
    if !matches!(outcome, Outcome::Exited(_)) {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    let stdout = stdout_task.await.context("Binary stdout 收集任务中断")??;
    let stderr = stderr_task.await.context("Binary stderr 收集任务中断")??;
    let mut response = ExecResponse::default();
    encode_output(stdout.bytes, true, &mut response);
    encode_output(stderr.bytes, false, &mut response);
    response.stdout_truncated = stdout.truncated;
    response.stderr_truncated = stderr.truncated;
    match outcome {
        Outcome::Exited(status) => {
            let status = status?;
            response.ok = status.success();
            response.exit_code = status.code().unwrap_or(-1);
            if !status.success() {
                response.error = Some(format!("Binary 异常退出：{status}"));
            }
        }
        Outcome::TimedOut => {
            response.exit_code = -1;
            response.timed_out = true;
            response.error = Some("Binary 执行超时".into());
        }
        Outcome::OutputLimit => {
            response.exit_code = -1;
            response.stdout_truncated = stdout.truncated;
            response.stderr_truncated = stderr.truncated;
            response.error = Some("Binary 输出超过签名策略上限，进程已终止".into());
        }
    }
    if response.ok {
        for output in &request.output_files {
            response
                .uploads
                .push(upload_file(node, worker, temp, output).await);
        }
    }
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
fn sandbox_command(
    bwrap: &Path,
    executable: &Path,
    temp: &Path,
    worker: &str,
    binary_name: &str,
    spec: &BinarySpec,
    request: &ExecRequest,
    network_allowed: bool,
) -> Result<Command> {
    let mut command = Command::new(bwrap);
    command
        .arg("--die-with-parent")
        .arg("--new-session")
        .arg("--unshare-all");
    if network_allowed {
        command.arg("--share-net");
    }
    command
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--bind")
        .arg(temp)
        .arg("/work")
        .arg("--ro-bind")
        .arg(executable)
        .arg("/rf-binary")
        .arg("--chdir")
        .arg("/work")
        .arg("--setenv")
        .arg("HOME")
        .arg("/work")
        .arg("--setenv")
        .arg("TMPDIR")
        .arg("/work")
        .arg("--setenv")
        .arg("BD_TMPDIR")
        .arg("/work")
        .arg("--setenv")
        .arg("BD_BINARY_NAME")
        .arg(binary_name)
        .arg("--setenv")
        .arg("BD_BINARY_SHA256")
        .arg(&spec.sha256)
        .arg("--setenv")
        .arg("BD_WORKER_ID")
        .arg(worker)
        .arg("--setenv")
        .arg("PATH")
        .arg("/usr/local/bin:/usr/bin:/bin");
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            command.arg("--ro-bind").arg(path).arg(path);
        }
    }
    for path in ["/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs"] {
        if network_allowed && Path::new(path).exists() {
            command.arg("--ro-bind").arg(path).arg(path);
        }
    }
    for (name, value) in &request.env {
        command.arg("--setenv").arg(name).arg(value);
    }
    command.arg("/rf-binary").args(&request.args).env_clear();
    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(crate::build::clear_child_capabilities);
    }
    Ok(command)
}

struct CappedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

async fn read_capped<R: AsyncRead + Unpin>(
    mut reader: R,
    cap: usize,
    signal: mpsc::Sender<()>,
) -> Result<CappedOutput> {
    let mut output = Vec::with_capacity(cap.min(64 * 1024));
    let mut buffer = [0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = cap.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..read.min(remaining)]);
        if read > remaining && !truncated {
            truncated = true;
            let _ = signal.try_send(());
        }
    }
    Ok(CappedOutput {
        bytes: output,
        truncated,
    })
}

fn encode_output(bytes: Vec<u8>, stdout: bool, response: &mut ExecResponse) {
    if let Ok(text) = String::from_utf8(bytes.clone()) {
        if stdout {
            response.stdout = text;
        } else {
            response.stderr = text;
        }
    } else {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        if stdout {
            response.stdout_base64 = encoded;
        } else {
            response.stderr_base64 = encoded;
        }
    }
}

async fn upload_file(
    node: &Node,
    worker: &str,
    temp: &Path,
    output: &OutputFileSpec,
) -> OutputFileResult {
    let mut result = OutputFileResult {
        path: output.path.clone(),
        bucket: output.bucket.clone(),
        key: output.key.clone(),
        sha256: None,
        size_bytes: None,
        content_type: output.content_type.clone(),
        error: None,
    };
    let operation = async {
        if !safe_relative(&output.path) {
            bail!("输出文件路径必须位于 BD_TMPDIR 内");
        }
        crate::r2::validate_key(&output.key)?;
        let manifest = node.manifest(worker).context("来源 Worker 不存在")?;
        let bucket = crate::deploy::r2_bindings(&manifest)
            .get(&output.bucket)
            .cloned()
            .context("输出文件指定的 R2 binding 不存在")?;
        let root = std::fs::canonicalize(temp)?;
        let path = std::fs::canonicalize(temp.join(&output.path))?;
        if !path.starts_with(&root) || !path.is_file() {
            bail!("输出文件路径越过沙箱边界或不是普通文件");
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() > crate::r2::MAX_DIRECT_OBJECT_BYTES {
            bail!("Binary R2 输出文件超过 63 MiB，请使用 stdout 分片或 Pipeline");
        }
        let metadata = crate::r2::put_object(
            node,
            &bucket,
            &output.key,
            &bytes,
            crate::r2::PutOptions {
                content_type: output.content_type.clone(),
                ..Default::default()
            },
        )
        .await?;
        Result::<_>::Ok(metadata)
    }
    .await;
    match operation {
        Ok(metadata) => {
            result.sha256 = Some(metadata.sha256);
            result.size_bytes = Some(metadata.size);
        }
        Err(error) => result.error = Some(format!("{error:#}")),
    }
    result
}

fn create_temp_dir(node: &Node) -> Result<PathBuf> {
    let root = node.cfg.data_dir.join("binary-tmp");
    std::fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    }
    for _ in 0..8 {
        let path = root.join(hex::encode(rand::random::<[u8; 16]>()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("无法创建唯一 Binary 执行目录")
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn valid_env(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

fn header<'a>(headers: &'a HeaderMap, name: &str, message: &str) -> Result<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .with_context(|| message.to_string())
}

fn classify_error(error: &anyhow::Error) -> StatusCode {
    let message = format!("{error:#}");
    if message.contains("不存在") {
        StatusCode::NOT_FOUND
    } else if message.contains("暂停")
        || message.contains("未授权")
        || message.contains("要求当前节点")
    {
        StatusCode::FORBIDDEN
    } else if message.contains("未安装") || message.contains("不具备") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_path_guards_are_strict() {
        assert!(valid_identifier("FFMPEG_BIN"));
        assert!(!valid_identifier("bad-name"));
        assert!(valid_env("LOG_LEVEL"));
        assert!(!valid_env("2BAD"));
        assert!(safe_relative("out/video.mp4"));
        assert!(!safe_relative("../secret"));
        assert!(!safe_relative("/etc/passwd"));
    }

    #[tokio::test]
    async fn capped_reader_reports_overflow_without_allocating_past_cap() {
        let (tx, mut rx) = mpsc::channel(1);
        let output = read_capped(&b"abcdef"[..], 3, tx).await.unwrap();
        assert_eq!(output.bytes, b"abc");
        assert!(output.truncated);
        assert_eq!(rx.recv().await, Some(()));
    }

    #[tokio::test]
    async fn bubblewrap_exec_has_private_workdir_and_no_host_etc() -> Result<()> {
        let Some(bwrap) = crate::build::configured_binary(None, "bwrap") else {
            return Ok(());
        };
        let temp = std::env::temp_dir().join(format!(
            "rf-binarybind-test-{}",
            hex::encode(rand::random::<[u8; 12]>())
        ));
        std::fs::create_dir(&temp).unwrap();
        let spec = BinarySpec {
            schema: binary::BINARY_SCHEMA,
            description: String::new(),
            sha256: "ab".repeat(32),
            size_bytes: 1,
            storage: crate::objectstore::StorageLocation::Local,
            os_arch: binary::current_os_arch().into(),
            default_timeout_ms: 1_000,
            max_stdin_bytes: 1024,
            max_output_bytes: 1024,
            allow_network: false,
            allow_r2: false,
            required_tags: Vec::new(),
            suspended: false,
        };
        let request = ExecRequest {
            args: vec![
                "-c".into(),
                "test ! -e /etc/passwd && test \"$BD_WORKER_ID\" = worker && printf private > result.txt && printf sandbox-ok".into(),
            ],
            stdin: String::new(),
            stdin_base64: String::new(),
            timeout_ms: None,
            env: BTreeMap::new(),
            output_files: Vec::new(),
        };
        let mut command = sandbox_command(
            &bwrap,
            Path::new("/bin/sh"),
            &temp,
            "worker",
            "shell",
            &spec,
            &request,
            false,
        )?;
        let output = command.output().await?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"sandbox-ok");
        assert_eq!(std::fs::read(temp.join("result.txt"))?, b"private");
        std::fs::remove_dir_all(&temp)?;
        Ok(())
    }
}
