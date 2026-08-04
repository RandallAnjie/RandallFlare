//! Decentralized Git-backed Worker builds.
//!
//! Repository definitions are operator-signed and replicated through the
//! existing internal KV anti-entropy path. A build executes only on the node
//! where it was requested, inside bubblewrap when a custom command is used.
//! The resulting content-addressed Worker manifest requires a second operator
//! signature before the normal manifest/blob gossip path deploys it cluster
//! wide. GitHub is therefore a source host, never a control plane.

use crate::deploy::{self, Bundle};
use crate::management::{ApprovalState, CreatedApproval};
use crate::node::{now_ms, Node};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rf_core::envelope::Envelope;
use rf_core::manifest::{valid_name, WorkerManifest};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};

pub const SOURCE_NAMESPACE: &str = "__rf_worker_sources_v1";
pub const BUILD_NAMESPACE: &str = "__rf_worker_builds_v1";
const SOURCE_SCHEMA: u8 = 1;
const MAX_LOG_LINES: usize = 500;
const MAX_LOG_LINE_BYTES: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSource {
    pub schema: u8,
    pub worker: String,
    pub version: u64,
    pub prev: Option<[u8; 32]>,
    #[serde(default)]
    pub deleted: bool,
    pub repository: String,
    pub branch: String,
    pub root: String,
    #[serde(default)]
    pub build_command: String,
    pub output_dir: String,
    #[serde(default)]
    pub use_github_token: bool,
    #[serde(default)]
    pub webhook: bool,
}

impl WorkerSource {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SOURCE_SCHEMA {
            bail!("不支持此版本的 Worker 源码配置格式");
        }
        if !valid_name(&self.worker) {
            bail!("Worker 名称须由 1 至 63 个小写字母、数字或连字符组成");
        }
        if self.version == 0 || (self.version == 1) != self.prev.is_none() {
            bail!("Worker 源码配置的版本链无效");
        }
        if self.deleted {
            return Ok(());
        }
        normalize_github_repository(&self.repository)?;
        validate_branch(&self.branch)?;
        validate_relative(&self.root, true, "仓库根目录")?;
        validate_relative(&self.output_dir, true, "输出目录")?;
        if self.build_command.len() > 8 * 1024 || self.build_command.as_bytes().contains(&0) {
            bail!("构建命令过长或含有 NUL 字符");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRecord {
    #[serde(flatten)]
    pub source: WorkerSource,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildState {
    Queued,
    Cloning,
    Building,
    Packaging,
    AwaitingApproval,
    Deployed,
    Failed,
}

impl BuildState {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Deployed | Self::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJob {
    pub id: String,
    pub worker: String,
    pub repository: String,
    pub branch: String,
    pub node_id: String,
    #[serde(default)]
    pub approve_node: String,
    pub trigger: String,
    pub state: BuildState,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub requested_commit: Option<String>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub approval: Option<CreatedApproval>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub log: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInput {
    pub worker: String,
    pub repository: String,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default = "default_dot")]
    pub root: String,
    #[serde(default)]
    pub build_command: String,
    #[serde(default = "default_dot")]
    pub output_dir: String,
    #[serde(default)]
    pub use_github_token: bool,
    #[serde(default)]
    pub webhook: bool,
}

fn default_branch() -> String {
    "main".into()
}

fn default_dot() -> String {
    ".".into()
}

pub fn prepare_source(node: &Node, input: SourceInput) -> Result<WorkerSource> {
    let repository = normalize_github_repository(&input.repository)?;
    let head = source_head(node, &input.worker);
    let source = WorkerSource {
        schema: SOURCE_SCHEMA,
        worker: input.worker,
        version: head
            .as_ref()
            .map(|record| record.source.version + 1)
            .unwrap_or(1),
        prev: head
            .map(|record| decode_digest(&record.digest))
            .transpose()?,
        deleted: false,
        repository,
        branch: input.branch,
        root: input.root,
        build_command: input.build_command,
        output_dir: input.output_dir,
        use_github_token: input.use_github_token,
        webhook: input.webhook,
    };
    source.validate()?;
    Ok(source)
}

pub fn prepare_source_delete(node: &Node, worker: &str) -> Result<WorkerSource> {
    let head = source_head(node, worker).ok_or_else(|| anyhow::anyhow!("未找到源码配置"))?;
    Ok(WorkerSource {
        schema: SOURCE_SCHEMA,
        worker: worker.to_string(),
        version: head.source.version + 1,
        prev: Some(decode_digest(&head.digest)?),
        deleted: true,
        repository: head.source.repository,
        branch: head.source.branch,
        root: head.source.root,
        build_command: String::new(),
        output_dir: head.source.output_dir,
        use_github_token: false,
        webhook: false,
    })
}

/// Persist one verified immutable source envelope. Replication is provided by
/// the normal internal-KV gossip loop.
pub fn ingest_source(node: &Node, envelope: &Envelope) -> Result<WorkerSource> {
    let source: WorkerSource = envelope
        .open(Some(&node.cfg.operator))
        .map_err(|error| anyhow::anyhow!("Worker 源码配置签名无效：{error}"))?;
    source.validate()?;
    let digest = hex::encode(envelope.digest());
    let key = format!("{}/{:020}/{}", source.worker, source.version, digest);
    if node.kv_get(SOURCE_NAMESPACE, &key).is_none() {
        node.kv_put(SOURCE_NAMESPACE, &key, Some(envelope.to_bytes()), None)?;
    }
    // Only accept a non-genesis record when its exact predecessor is already
    // known. An out-of-order gossip replica still stores the immutable record;
    // it becomes the head as soon as the predecessor arrives.
    if source_head(node, &source.worker)
        .as_ref()
        .map(|record| record.digest.as_str())
        != Some(digest.as_str())
    {
        tracing::debug!(worker = %source.worker, version = source.version, "已保存非最新的 Worker 源码配置记录");
    }
    Ok(source)
}

pub fn source_head(node: &Node, worker: &str) -> Option<SourceRecord> {
    source_records(node, Some(worker))
        .into_iter()
        .filter(|record| record.source.worker == worker)
        .max_by(|a, b| (a.source.version, &a.digest).cmp(&(b.source.version, &b.digest)))
}

pub fn source_records(node: &Node, worker: Option<&str>) -> Vec<SourceRecord> {
    let prefix = worker.map(|name| format!("{name}/")).unwrap_or_default();
    let mut candidates: BTreeMap<String, Vec<(WorkerSource, String)>> = BTreeMap::new();
    for (key, entry) in node.kv_dump(SOURCE_NAMESPACE) {
        if !key.starts_with(&prefix) {
            continue;
        }
        let Some(bytes) = entry.visible(now_ms()) else {
            continue;
        };
        let Ok(envelope) = Envelope::from_bytes(bytes) else {
            continue;
        };
        let Ok(source) = envelope.open::<WorkerSource>(Some(&node.cfg.operator)) else {
            continue;
        };
        if source.validate().is_err() || !key.starts_with(&format!("{}/", source.worker)) {
            continue;
        }
        candidates
            .entry(source.worker.clone())
            .or_default()
            .push((source, hex::encode(envelope.digest())));
    }

    let mut out = Vec::new();
    for (_, mut records) in candidates {
        records.sort_by(|a, b| (a.0.version, &a.1).cmp(&(b.0.version, &b.1)));
        let mut accepted: HashMap<String, WorkerSource> = HashMap::new();
        for (source, digest) in records {
            let linked = if source.version == 1 {
                source.prev.is_none()
            } else {
                source
                    .prev
                    .map(hex::encode)
                    .map(|prev| {
                        accepted
                            .get(&prev)
                            .map(|prior| prior.version + 1 == source.version)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            };
            if linked {
                accepted.insert(digest.clone(), source.clone());
                out.push(SourceRecord { source, digest });
            }
        }
    }
    out.sort_by(|a, b| {
        (&a.source.worker, a.source.version, &a.digest).cmp(&(
            &b.source.worker,
            b.source.version,
            &b.digest,
        ))
    });
    out
}

pub fn live_sources(node: &Node) -> Vec<SourceRecord> {
    let mut heads: BTreeMap<String, SourceRecord> = BTreeMap::new();
    for record in source_records(node, None) {
        let replace = heads
            .get(&record.source.worker)
            .map(|old| (record.source.version, &record.digest) > (old.source.version, &old.digest))
            .unwrap_or(true);
        if replace {
            heads.insert(record.source.worker.clone(), record);
        }
    }
    heads
        .into_values()
        .filter(|record| !record.source.deleted)
        .collect()
}

pub fn build_jobs(node: &Node, worker: Option<&str>) -> Vec<BuildJob> {
    let mut jobs = Vec::new();
    for (_, entry) in node.kv_dump(BUILD_NAMESPACE) {
        let Some(value) = entry.visible(now_ms()) else {
            continue;
        };
        let Ok(job) = serde_json::from_slice::<BuildJob>(value) else {
            continue;
        };
        if worker.map(|name| name == job.worker).unwrap_or(true) {
            jobs.push(job);
        }
    }
    jobs.sort_by_key(|job| std::cmp::Reverse(job.created_at_ms));
    jobs
}

pub fn build_job(node: &Node, id: &str) -> Option<BuildJob> {
    let value = node.kv_get(BUILD_NAMESPACE, id)?;
    serde_json::from_slice(&value).ok()
}

pub fn start_build(
    node: Arc<Node>,
    worker: &str,
    trigger: impl Into<String>,
    session_id: Option<[u8; 32]>,
    requested_commit: Option<String>,
) -> Result<BuildJob> {
    if !node.cfg.build.enabled {
        bail!("此节点尚未启用 Git 构建");
    }
    let source = source_head(&node, worker)
        .filter(|record| !record.source.deleted)
        .ok_or_else(|| anyhow::anyhow!("Worker 尚未连接代码仓库"))?;
    if let Some(commit) = requested_commit.as_deref() {
        if commit.len() != 40 || !commit.chars().all(|value| value.is_ascii_hexdigit()) {
            bail!("指定的 Git 提交必须是 40 位 SHA-1");
        }
    }
    let id = random_id();
    let now = now_ms();
    let job = BuildJob {
        id: id.clone(),
        worker: worker.to_string(),
        repository: source.source.repository.clone(),
        branch: source.source.branch.clone(),
        node_id: node.id_hex(),
        approve_node: node.cfg.peer_api_advertise().to_string(),
        trigger: trigger.into(),
        state: BuildState::Queued,
        created_at_ms: now,
        updated_at_ms: now,
        commit: None,
        requested_commit,
        version: None,
        approval: None,
        error: None,
        log: vec!["构建任务已进入此节点的队列".into()],
    };
    persist_job(&node, &job)?;
    let shared = Arc::new(Mutex::new(job.clone()));
    tokio::spawn(async move {
        let result = run_build(node.clone(), source.source, shared.clone(), session_id).await;
        let builds_root = node.cfg.data_dir.join("builds");
        cleanup_workspace(&builds_root, &builds_root.join(&id));
        if let Err(error) = result {
            fail_job(&node, &shared, error.to_string()).await;
        }
    });
    Ok(job)
}

/// On restart, in-flight child processes are gone. Mark their records failed
/// rather than pretending they are still running; queued jobs are safe to
/// retry from the console/webhook.
pub fn recover_interrupted(node: &Node) {
    let builds_root = node.cfg.data_dir.join("builds");
    for mut job in build_jobs(node, None) {
        if job.node_id == node.id_hex() && !job.state.terminal() {
            job.state = BuildState::Failed;
            job.error = Some("构建期间节点发生重启，请重新发起构建".into());
            job.updated_at_ms = now_ms();
            append_log(&mut job, "构建因节点重启而中断");
            let _ = persist_job(node, &job);
        }
        if job.node_id == node.id_hex()
            && job.id.len() == 32
            && job.id.chars().all(|value| value.is_ascii_hexdigit())
        {
            cleanup_workspace(&builds_root, &builds_root.join(&job.id));
        }
    }
}

async fn run_build(
    node: Arc<Node>,
    source: WorkerSource,
    job: Arc<Mutex<BuildJob>>,
    session_id: Option<[u8; 32]>,
) -> Result<()> {
    let git =
        configured_binary(node.cfg.build.git.as_deref(), "git").context("此节点无法使用 Git")?;
    let builds_root = node.cfg.data_dir.join("builds");
    std::fs::create_dir_all(&builds_root)?;
    let job_id = job.lock().await.id.clone();
    let workspace = builds_root.join(&job_id);
    if workspace.exists() {
        bail!("构建工作区已存在；为确保隔离安全，不会重复使用");
    }
    std::fs::create_dir(&workspace)?;
    let checkout = workspace.join("repo");

    set_state(&node, &job, BuildState::Cloning, "正在克隆 GitHub 仓库").await?;
    let mut clone = Command::new(&git);
    clone
        .arg("clone")
        .arg("--depth=1")
        .arg("--single-branch")
        .arg("--branch")
        .arg(&source.branch)
        .arg("--")
        .arg(&source.repository)
        .arg(&checkout);
    sanitized_env(&mut clone, &workspace);
    apply_git_auth(&mut clone, &node, &source)?;
    run_logged(
        &node,
        &job,
        clone,
        Duration::from_secs(node.cfg.build.timeout_seconds.min(300)),
    )
    .await
    .context("Git 克隆失败")?;

    let mut commit = git_revision(&git, &checkout, &workspace).await?;
    let requested = job.lock().await.requested_commit.clone();
    if let Some(requested) = requested.filter(|requested| *requested != commit) {
        {
            let mut current = job.lock().await;
            append_log(
                &mut current,
                &format!("正在获取 Webhook 指定的提交 {}", short_commit(&requested)),
            );
            current.updated_at_ms = now_ms();
            persist_job(&node, &current)?;
        }
        let mut fetch = Command::new(&git);
        fetch
            .arg("-C")
            .arg(&checkout)
            .arg("fetch")
            .arg("--depth=1")
            .arg("origin")
            .arg(&requested);
        sanitized_env(&mut fetch, &workspace);
        apply_git_auth(&mut fetch, &node, &source)?;
        run_logged(
            &node,
            &job,
            fetch,
            Duration::from_secs(node.cfg.build.timeout_seconds.min(300)),
        )
        .await
        .context("获取 Webhook 指定的提交失败")?;

        let mut checkout_commit = Command::new(&git);
        checkout_commit
            .arg("-C")
            .arg(&checkout)
            .arg("checkout")
            .arg("--detach")
            .arg(&requested);
        sanitized_env(&mut checkout_commit, &workspace);
        run_logged(&node, &job, checkout_commit, Duration::from_secs(60))
            .await
            .context("检出 Webhook 指定的提交失败")?;
        commit = git_revision(&git, &checkout, &workspace).await?;
        if commit != requested {
            bail!("Git 检出的结果与 Webhook 指定的提交不一致");
        }
    }
    {
        let mut current = job.lock().await;
        current.commit = Some(commit.clone());
        append_log(
            &mut current,
            &format!("已检出提交 {}", short_commit(&commit)),
        );
        current.updated_at_ms = now_ms();
        persist_job(&node, &current)?;
    }

    let project_root = join_relative(&checkout, &source.root)?;
    if !project_root.is_dir() {
        bail!("仓库根目录不存在：{}", source.root);
    }
    if !source.build_command.trim().is_empty() {
        set_state(&node, &job, BuildState::Building, "正在沙箱中执行构建命令").await?;
        let sandbox = configured_binary(node.cfg.build.sandbox.as_deref(), "bwrap")
            .context("自定义构建命令要求此节点安装 bubblewrap（bwrap）")?;
        let command = sandbox_command(&sandbox, &checkout, &source.root, &source.build_command)?;
        run_logged(
            &node,
            &job,
            command,
            Duration::from_secs(node.cfg.build.timeout_seconds),
        )
        .await
        .context("沙箱构建失败")?;
    } else {
        set_state(
            &node,
            &job,
            BuildState::Building,
            "零配置构建：直接使用仓库文件",
        )
        .await?;
    }

    set_state(
        &node,
        &job,
        BuildState::Packaging,
        "正在验证 rf.json 并封装不可变内容块",
    )
    .await?;
    let output_root = join_relative(&project_root, &source.output_dir)?;
    if !output_root.is_dir() {
        bail!("构建输出目录不存在：{}", source.output_dir);
    }
    let bundle: Bundle = deploy::read_bundle(&output_root)?;
    let file_count = bundle.modules.len().saturating_add(bundle.assets.len());
    let bundle_bytes: usize = bundle
        .modules
        .iter()
        .map(|(_, bytes, _)| bytes.len())
        .chain(bundle.assets.iter().map(|(_, bytes)| bytes.len()))
        .sum();
    if file_count > 2_048 || bundle_bytes > 64 * 1024 * 1024 {
        bail!("构建产物超过 2,048 个文件或 64 MiB");
    }
    if bundle.spec.name != source.worker {
        bail!(
            "rf.json 中的 Worker 名称为 {:?}，但该仓库连接的是 {:?}",
            bundle.spec.name,
            source.worker
        );
    }
    let manifest = deploy::prepare_manifest_local(&bundle, &node)?;
    let approval = node.management.create_manifest_scoped(
        session_id,
        &manifest,
        format!(
            "部署 Git 构建 {} v{}（来源：{}@{}）",
            manifest.name,
            manifest.version,
            github_slug(&source.repository),
            short_commit(&commit)
        ),
    )?;
    {
        let mut current = job.lock().await;
        current.state = BuildState::AwaitingApproval;
        current.version = Some(manifest.version);
        current.approval = Some(approval.clone());
        current.updated_at_ms = now_ms();
        append_log(
            &mut current,
            &format!("构建产物已就绪；管理员审批码为 {}", approval.code),
        );
        persist_job(&node, &current)?;
    }

    loop {
        tokio::time::sleep(Duration::from_millis(900)).await;
        match node.management.poll_internal(&approval.id)? {
            poll if poll.state == ApprovalState::Completed => {
                set_state(
                    &node,
                    &job,
                    BuildState::Deployed,
                    "已提交签名部署清单；集群分发已经开始",
                )
                .await?;
                break;
            }
            poll if poll.state == ApprovalState::Failed => {
                bail!("部署清单审批失败：{}", poll.error.unwrap_or_default());
            }
            _ if now_ms() >= approval.expires_at_ms => bail!("部署清单审批已过期"),
            _ => {}
        }
    }
    Ok(())
}

async fn git_revision(git: &Path, checkout: &Path, workspace: &Path) -> Result<String> {
    let mut revision = Command::new(git);
    revision
        .arg("-C")
        .arg(checkout)
        .arg("rev-parse")
        .arg("HEAD");
    sanitized_env(&mut revision, workspace);
    let output = revision.output().await.context("读取 Git 提交")?;
    if !output.status.success() {
        bail!("无法解析当前检出的 Git 提交");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn apply_git_auth(command: &mut Command, node: &Node, source: &WorkerSource) -> Result<()> {
    if !source.use_github_token {
        return Ok(());
    }
    let token = std::env::var(&node.cfg.build.github_token_env).with_context(|| {
        format!(
            "此源码配置需要 GitHub 令牌，但节点尚未设置环境变量 {}",
            node.cfg.build.github_token_env
        )
    })?;
    if token.is_empty() || token.as_bytes().contains(&b'\n') {
        bail!("节点本地的 GitHub 令牌为空或格式有误");
    }
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    command
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader")
        .env(
            "GIT_CONFIG_VALUE_0",
            format!("AUTHORIZATION: basic {basic}"),
        );
    Ok(())
}

async fn set_state(
    node: &Node,
    job: &Arc<Mutex<BuildJob>>,
    state: BuildState,
    message: &str,
) -> Result<()> {
    let mut current = job.lock().await;
    current.state = state;
    current.updated_at_ms = now_ms();
    append_log(&mut current, message);
    persist_job(node, &current)
}

async fn fail_job(node: &Node, job: &Arc<Mutex<BuildJob>>, error: String) {
    let mut current = job.lock().await;
    current.state = BuildState::Failed;
    current.error = Some(error.clone());
    current.updated_at_ms = now_ms();
    append_log(&mut current, &format!("错误：{error}"));
    if let Err(persist_error) = persist_job(node, &current) {
        tracing::error!(job = %current.id, "无法保存失败构建的状态：{persist_error}");
    }
}

fn persist_job(node: &Node, job: &BuildJob) -> Result<()> {
    node.kv_put(
        BUILD_NAMESPACE,
        &job.id,
        Some(serde_json::to_vec(job)?),
        None,
    )
}

fn append_log(job: &mut BuildJob, message: &str) {
    let mut line = message.replace(['\r', '\0'], "");
    if line.len() > MAX_LOG_LINE_BYTES {
        line.truncate(MAX_LOG_LINE_BYTES);
        line.push('…');
    }
    job.log
        .push(format!("{}  {}", timestamp_label(now_ms()), line));
    if job.log.len() > MAX_LOG_LINES {
        job.log.drain(..job.log.len() - MAX_LOG_LINES);
    }
}

async fn run_logged(
    node: &Node,
    job: &Arc<Mutex<BuildJob>>,
    mut command: Command,
    timeout: Duration,
) -> Result<()> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().context("启动构建进程")?;
    let stdout = child.stdout.take().context("读取标准输出")?;
    let stderr = child.stderr.take().context("读取标准错误")?;
    let (tx, mut rx) = mpsc::channel::<String>(64);
    spawn_log_reader("out", stdout, tx.clone());
    spawn_log_reader("err", stderr, tx.clone());
    drop(tx);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let status = loop {
        tokio::select! {
            line = rx.recv() => {
                if let Some(line) = line {
                    let mut current = job.lock().await;
                    append_log(&mut current, &line);
                    current.updated_at_ms = now_ms();
                    persist_job(node, &current)?;
                }
            }
            status = child.wait() => break status.context("等待构建进程结束")?,
            _ = &mut deadline => {
                let _ = child.kill().await;
                bail!("构建进程超过 {} 秒时限", timeout.as_secs());
            }
        }
    };
    while let Ok(line) = rx.try_recv() {
        let mut current = job.lock().await;
        append_log(&mut current, &line);
        current.updated_at_ms = now_ms();
        persist_job(node, &current)?;
    }
    if !status.success() {
        bail!("构建进程异常退出：{status}");
    }
    Ok(())
}

fn spawn_log_reader<R>(prefix: &'static str, stream: R, tx: mpsc::Sender<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(format!("[{prefix}] {line}")).await.is_err() {
                break;
            }
        }
    });
}

fn sandbox_command(
    bwrap: &Path,
    checkout: &Path,
    root: &str,
    build_command: &str,
) -> Result<Command> {
    let mut command = Command::new(bwrap);
    command
        .arg("--die-with-parent")
        .arg("--new-session")
        .arg("--unshare-all")
        .arg("--share-net")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--bind")
        .arg(checkout)
        .arg("/repo")
        .arg("--chdir")
        .arg(if root == "." {
            "/repo".into()
        } else {
            format!("/repo/{root}")
        })
        .arg("--setenv")
        .arg("HOME")
        .arg("/tmp")
        .arg("--setenv")
        .arg("PATH")
        .arg("/usr/local/bin:/usr/bin:/bin")
        .arg("--setenv")
        .arg("CI")
        .arg("true");
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            command.arg("--ro-bind").arg(path).arg(path);
        }
    }
    for path in ["/etc/resolv.conf", "/etc/ssl/certs"] {
        if Path::new(path).exists() {
            command.arg("--ro-bind").arg(path).arg(path);
        }
    }
    command.arg("/bin/sh").arg("-lc").arg(build_command);
    command.env_clear();
    // The hardened service carries CAP_NET_BIND_SERVICE so the daemon can own
    // :80/:443 without running as root. bubblewrap deliberately refuses to
    // start when an ordinary (non-setuid) invocation arrives with unexpected
    // capabilities. Strip the inherited capability set in the forked build
    // child immediately before exec; the daemon and workerd lifecycle keep
    // their existing service policy.
    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(clear_child_capabilities);
    }
    Ok(command)
}

#[cfg(target_os = "linux")]
fn clear_child_capabilities() -> std::io::Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // Clear ambient first; otherwise the next exec would restore that
    // capability into the permitted/effective sets.
    let ambient = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if ambient != 0 {
        return Err(std::io::Error::last_os_error());
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let cleared = unsafe { libc::syscall(libc::SYS_capset, &header, &data) };
    if cleared != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn sanitized_env(command: &mut Command, home: &Path) {
    command
        .env_clear()
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        )
        .env("HOME", home)
        .env("LANG", "C.UTF-8")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1");
}

pub fn configured_binary(configured: Option<&Path>, name: &str) -> Option<PathBuf> {
    if let Some(path) = configured {
        return path.is_file().then(|| path.to_path_buf());
    }
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|path| path.join(name))
        .find(|path| path.is_file())
}

fn validate_relative(value: &str, allow_dot: bool, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 1024 || value.contains('\\') {
        bail!("{label}必须是安全的相对路径");
    }
    if value == "." && allow_dot {
        return Ok(());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("{label}必须是安全的相对路径");
    }
    Ok(())
}

fn join_relative(base: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative(relative, true, "路径")?;
    Ok(if relative == "." {
        base.to_path_buf()
    } else {
        base.join(relative)
    })
}

fn validate_branch(branch: &str) -> Result<()> {
    if branch.is_empty()
        || branch.len() > 255
        || branch.starts_with('-')
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.contains("..")
        || branch.contains("//")
        || !branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        bail!("Git 分支名称无效");
    }
    Ok(())
}

pub fn normalize_github_repository(repository: &str) -> Result<String> {
    let value = repository.trim().trim_end_matches('/');
    let path = value
        .strip_prefix("https://github.com/")
        .ok_or_else(|| anyhow::anyhow!("仓库地址必须是 https://github.com URL"))?
        .trim_end_matches(".git");
    let mut parts = path.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if owner.is_empty()
        || repo.is_empty()
        || parts.next().is_some()
        || !owner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || !repo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("仓库地址必须明确指定一个 GitHub 所有者与仓库名");
    }
    Ok(format!("https://github.com/{owner}/{repo}.git"))
}

fn github_slug(repository: &str) -> &str {
    repository
        .strip_prefix("https://github.com/")
        .unwrap_or(repository)
        .trim_end_matches(".git")
}

fn decode_digest(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("源码摘要无效"))
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn timestamp_label(ms: u64) -> String {
    let total = ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        (total / 3600) % 24,
        (total / 60) % 60,
        total % 60
    )
}

fn short_commit(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

fn cleanup_workspace(root: &Path, workspace: &Path) {
    if workspace.parent() == Some(root) && workspace.file_name().is_some() && workspace.exists() {
        if let Err(error) = std::fs::remove_dir_all(workspace) {
            tracing::warn!(path = %workspace.display(), "无法清理构建工作区：{error}");
        }
    }
}

pub fn webhook_secret(node: &Node, worker: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&node.cfg.cluster_secret_bytes()?)
        .map_err(|_| anyhow::anyhow!("集群密钥无效"))?;
    mac.update(b"randallflare-github-webhook-v1\0");
    mac.update(worker.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn verify_webhook(secret_hex: &str, signature: &str, body: &[u8]) -> bool {
    let Some(signature) = signature.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(signature) else {
        return false;
    };
    // GitHub treats the configured secret as UTF-8 text. The console exposes
    // the derived key in hex, so the ASCII hex string itself is the HMAC key.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret_hex.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

pub fn rollback_manifest(node: &Node, historical: &WorkerManifest) -> Result<WorkerManifest> {
    let (version, prev) = node
        .manifest_head(&historical.name)
        .ok_or_else(|| anyhow::anyhow!("Worker 不存在"))?;
    let mut rollback = historical.clone();
    rollback.version = version + 1;
    rollback.prev = Some(prev);
    rollback.deleted = false;
    rollback
        .validate()
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(rollback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_core::identity::{AnyKeypair, Keypair};

    fn node() -> (Node, AnyKeypair, PathBuf) {
        let operator = AnyKeypair::Ed(Keypair::from_seed([41; 32]));
        let data_dir = std::env::temp_dir().join(format!(
            "rf-build-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let config: crate::config::NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {data_dir:?}
            operator = "{operator}"
            cluster_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            [gossip]
            listen = "127.0.0.1:17381"
            [peer_api]
            listen = "127.0.0.1:17382"
            "#,
            operator = operator.signer_id(),
        ))
        .unwrap();
        let node = Node::open(config, Keypair::from_seed([42; 32])).unwrap();
        (node, operator, data_dir)
    }

    #[test]
    fn github_urls_are_canonical_and_other_hosts_are_rejected() {
        assert_eq!(
            normalize_github_repository("https://github.com/RandallAnjie/RandallFlare/").unwrap(),
            "https://github.com/RandallAnjie/RandallFlare.git"
        );
        assert!(normalize_github_repository("git@github.com:a/b.git").is_err());
        assert!(normalize_github_repository("https://example.com/a/b").is_err());
        assert!(normalize_github_repository("https://github.com/a/b/extra").is_err());
    }

    #[test]
    fn unsafe_paths_and_branches_are_rejected() {
        assert!(validate_relative("packages/worker", true, "root").is_ok());
        assert!(validate_relative("../secret", true, "root").is_err());
        assert!(validate_relative("/etc", true, "root").is_err());
        assert!(validate_branch("feature/workers-v2").is_ok());
        assert!(validate_branch("--upload-pack=bad").is_err());
        assert!(validate_branch("refs//bad").is_err());
    }

    #[test]
    fn webhook_signatures_are_verified() {
        let key = hex::encode([7u8; 32]);
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(b"payload");
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_webhook(&key, &signature, b"payload"));
        assert!(!verify_webhook(&key, &signature, b"tampered"));
    }

    #[test]
    fn signed_source_chain_is_resolved_and_unsigned_data_is_ignored() {
        let (node, operator, data_dir) = node();
        let first = prepare_source(
            &node,
            SourceInput {
                worker: "demo".into(),
                repository: "https://github.com/example/demo".into(),
                branch: "main".into(),
                root: ".".into(),
                build_command: String::new(),
                output_dir: ".".into(),
                use_github_token: false,
                webhook: true,
            },
        )
        .unwrap();
        ingest_source(&node, &Envelope::seal_any(&first, &operator)).unwrap();
        assert_eq!(source_head(&node, "demo").unwrap().source.version, 1);

        let second = prepare_source(
            &node,
            SourceInput {
                worker: "demo".into(),
                repository: "https://github.com/example/demo".into(),
                branch: "stable".into(),
                root: "worker".into(),
                build_command: "npm run build".into(),
                output_dir: "dist".into(),
                use_github_token: true,
                webhook: false,
            },
        )
        .unwrap();
        ingest_source(&node, &Envelope::seal_any(&second, &operator)).unwrap();
        let head = source_head(&node, "demo").unwrap();
        assert_eq!(head.source.version, 2);
        assert_eq!(head.source.branch, "stable");

        let attacker = AnyKeypair::Ed(Keypair::from_seed([43; 32]));
        assert!(ingest_source(&node, &Envelope::seal_any(&second, &attacker)).is_err());
        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bubblewrap_command_can_write_only_the_checkout() {
        let Some(bwrap) = configured_binary(None, "bwrap") else {
            return;
        };
        let root = std::env::temp_dir().join(format!(
            "rf-bwrap-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let checkout = root.join("repo");
        std::fs::create_dir_all(&checkout).unwrap();
        std::fs::write(checkout.join("rf.json"), b"{}").unwrap();
        let mut command = sandbox_command(
            &bwrap,
            &checkout,
            ".",
            "test -f rf.json && printf sandbox-ok > artifact.txt",
        )
        .unwrap();
        let output = command.output().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(checkout.join("artifact.txt")).unwrap(),
            "sandbox-ok"
        );
        std::fs::remove_dir_all(root).ok();
    }
}
