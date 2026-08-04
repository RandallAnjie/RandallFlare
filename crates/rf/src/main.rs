//! rf — RandallFlare node daemon + operator CLI in one binary.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rf::config::NodeConfig;
use rf::node::Node;
use rf::peers::PeerClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "rf",
    version,
    about = "RandallFlare — an edge platform with no control plane"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an operator keypair (+ a suggested cluster secret).
    Keygen {
        /// Directory for operator.key (default ~/.rf)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Generate an Ethereum-style secp256k1 key — the operator
        /// identity becomes a 0x wallet address.
        #[arg(long)]
        eth: bool,
    },
    /// Run the node daemon.
    Run {
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Validate a node config and inspect runtime prerequisites.
    Doctor {
        #[arg(long, short)]
        config: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check the public identity/health endpoint of a node.
    Health {
        #[arg(long, env = "RF_NODE")]
        node: String,
    },
    /// Run the local, credential-isolating management console.
    Console {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        /// Loopback address for the browser UI.
        #[arg(long, default_value = "127.0.0.1:7390")]
        listen: SocketAddr,
    },
    /// Approve a browser login or Worker change with the operator key.
    Authorize {
        /// One-time code displayed by the management interface.
        code: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Deploy a worker directory (rf.json + modules + assets).
    Deploy {
        dir: PathBuf,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Cluster status as seen by one node.
    Status {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Delete (tombstone) a worker.
    WorkerDelete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// KV operations against any node.
    Kv {
        #[command(subcommand)]
        cmd: KvCmd,
    },
    /// Replicated SQLite (D1) operations.
    D1 {
        #[command(subcommand)]
        cmd: D1Cmd,
    },
    /// R2-compatible bucket and object operations.
    R2 {
        #[command(subcommand)]
        cmd: R2Cmd,
    },
    /// Decentralized Queue operations.
    Queue {
        #[command(subcommand)]
        cmd: QueueCmd,
    },
    /// Decentralized Analytics Engine operations.
    Analytics {
        #[command(subcommand)]
        cmd: AnalyticsCmd,
    },
    /// Durable Pipeline ingest and R2 batch operations.
    Pipeline {
        #[command(subcommand)]
        cmd: PipelineCmd,
    },
    /// Durable Worker Workflow definitions and instances.
    Workflow {
        #[command(subcommand)]
        cmd: WorkflowCmd,
    },
    /// 可视化、持久化的去中心化 Flow 编排。
    Flow {
        #[command(subcommand)]
        cmd: FlowCmd,
    },
    /// Fetch and verify a worker's transparency log (hash chain).
    Log {
        worker: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
        /// Operator identity to verify against (default: derived from
        /// your operator key file).
        #[arg(long)]
        operator: Option<String>,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum D1Cmd {
    /// Create a database (replica group picked by rendezvous hash).
    Create {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Execute SQL (writes replicate through the quorum; SELECTs run
    /// on the leader).
    Exec {
        name: String,
        sql: String,
        /// JSON params, e.g. --params '[1, "two"]'
        #[arg(long, default_value = "[]")]
        params: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum KvCmd {
    List {
        ns: String,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    Get {
        ns: String,
        key: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    Put {
        ns: String,
        key: String,
        value: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    Delete {
        ns: String,
        key: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum R2Cmd {
    /// List signed bucket definitions.
    BucketList {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Create or update a bucket. Omitting --rclone-remote uses local storage.
    BucketCreate {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        public: bool,
        #[arg(long)]
        rclone_remote: Option<String>,
        #[arg(long, default_value = "")]
        rclone_prefix: String,
        #[arg(long)]
        max_bytes: Option<u64>,
        #[arg(long)]
        max_objects: Option<u64>,
        #[arg(long)]
        expire_after_days: Option<u32>,
        #[arg(long = "cors-origin")]
        cors_origins: Vec<String>,
        /// Additional public hostname (repeatable). The default r2-<bucket>
        /// hostname is derived from ingress.default_domain automatically.
        #[arg(long = "hostname")]
        hostnames: Vec<String>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Tombstone a bucket definition (stored object bytes are retained for GC).
    BucketDelete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// List objects by key prefix.
    List {
        bucket: String,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Read object metadata.
    Head {
        bucket: String,
        object: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Upload one object (up to 63 MiB; multipart support is separate).
    Put {
        bucket: String,
        object: String,
        file: PathBuf,
        #[arg(long)]
        content_type: Option<String>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Download one object. Without --output, writes bytes to stdout.
    Get {
        bucket: String,
        object: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Delete one object's metadata index.
    Delete {
        bucket: String,
        object: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum QueueCmd {
    /// List signed queue definitions and current depths.
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Create or update a signed queue definition.
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        consumer: Option<String>,
        #[arg(long, default_value_t = 10)]
        batch_size: u16,
        #[arg(long, default_value_t = 5_000)]
        max_wait_ms: u64,
        #[arg(long, default_value_t = 3)]
        max_retries: u16,
        #[arg(long, default_value_t = 120_000)]
        visibility_timeout_ms: u64,
        #[arg(long, default_value_t = 604_800)]
        retention_seconds: u64,
        #[arg(long)]
        dead_letter_queue: Option<String>,
        #[arg(long)]
        suspended: bool,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Tombstone a queue definition.
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Send one JSON message.
    Send {
        name: String,
        body: String,
        #[arg(long, default_value_t = 0)]
        delay_seconds: u64,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Show ready, inflight, dead-letter and lifetime counters.
    Stats {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// List dead letters.
    Dead {
        name: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Move one dead letter back to the ready queue.
    Redrive {
        name: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum AnalyticsCmd {
    /// List signed datasets and their current counters.
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Create or update a signed dataset.
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        retention_days: Option<u32>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Tombstone a dataset definition.
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Write one JSON data point.
    Write {
        name: String,
        point: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Show one dataset's hour, day and lifetime counters.
    Stats {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Read the newest events.
    Events {
        name: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        before: Option<u64>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Group events by a blob/index dimension and optionally aggregate a double.
    Group {
        name: String,
        #[arg(long, default_value = "blob")]
        dimension: String,
        #[arg(long, default_value_t = 0)]
        dimension_index: usize,
        #[arg(long)]
        double_index: Option<usize>,
        #[arg(long, default_value_t = 0)]
        since: u64,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum PipelineCmd {
    /// List signed Pipelines and their current queue depth.
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Create or update a signed Pipeline.
    Create {
        name: String,
        #[arg(long)]
        bucket: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(
            long,
            default_value = "{pipeline}/year={yyyy}/month={mm}/day={dd}/hour={hh}/{agent}-{batchId}.jsonl.gz"
        )]
        key_template: String,
        #[arg(long, default_value_t = rf::pipeline::DEFAULT_BATCH_BYTES)]
        batch_max_bytes: u64,
        #[arg(long, default_value_t = rf::pipeline::DEFAULT_BATCH_SECONDS)]
        batch_max_seconds: u64,
        /// Inline JSON Schema.
        #[arg(long)]
        schema: Option<String>,
        #[arg(long)]
        hostname: Vec<String>,
        #[arg(long)]
        suspended: bool,
        #[arg(long, default_value = "")]
        suspend_reason: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Tombstone a Pipeline definition.
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Mint a bearer token. The plaintext is printed once.
    TokenCreate {
        name: String,
        #[arg(long, default_value = "")]
        label: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Revoke a bearer token by its public token id.
    TokenRevoke {
        name: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Submit one JSON event or JSON event array over the encrypted node API.
    Send {
        name: String,
        events: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Show queue and batch counters.
    Status {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// List recent output batches.
    Batches {
        name: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Force one pending batch to R2.
    Flush {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum WorkflowCmd {
    /// List signed Workflows with instance counters.
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Create or update a signed Workflow definition.
    Create {
        name: String,
        #[arg(long)]
        worker: String,
        #[arg(long, default_value = "MyWorkflow")]
        entrypoint: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long, default_value_t = 30)]
        retention_days: u16,
        #[arg(long, default_value_t = 3)]
        instance_retries: u16,
        #[arg(long, default_value_t = 1500)]
        instance_timeout_seconds: u64,
        #[arg(long)]
        suspended: bool,
        #[arg(long, default_value = "")]
        suspend_reason: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Tombstone a Workflow definition.
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Create an instance. Reusing --idempotency-key returns the existing instance.
    Trigger {
        name: String,
        #[arg(long, default_value = "{}")]
        input: String,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// List recent instances.
    Instances {
        name: String,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Show one instance, steps, signals and audit events.
    Instance {
        name: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Deliver an external signal to a waiting instance.
    Signal {
        name: String,
        id: String,
        signal: String,
        #[arg(long, default_value = "null")]
        payload: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Pause an active instance.
    Pause(WorkflowActionArgs),
    /// Resume a paused instance.
    Resume(WorkflowActionArgs),
    /// Terminate an active instance.
    Terminate(WorkflowActionArgs),
    /// Restart a terminal instance from its durable step boundary.
    Restart(WorkflowActionArgs),
    /// Show per-status instance counters.
    Stats {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(clap::Args)]
struct WorkflowActionArgs {
    name: String,
    id: String,
    #[arg(long, env = "RF_NODE")]
    node: String,
    #[arg(long, env = "RF_CLUSTER_SECRET")]
    secret: String,
}

#[derive(Subcommand)]
enum FlowCmd {
    /// 列出已签名 Flow 及运行统计。
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 从 FlowGraph JSON 文件创建或更新 Flow。
    Create {
        name: String,
        #[arg(long)]
        graph: PathBuf,
        #[arg(long, default_value = "manual")]
        trigger: String,
        #[arg(long)]
        cron: Option<String>,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        hostname: Vec<String>,
        #[arg(long, default_value_t = 30)]
        retention_days: u16,
        #[arg(long, default_value_t = 32)]
        max_concurrent_runs: u16,
        #[arg(long)]
        suspended: bool,
        #[arg(long, default_value = "")]
        suspend_reason: String,
        /// 节点本地的失败告警 URL 环境变量名，不保存 URL 本身。
        #[arg(long)]
        alert_webhook_env: Option<String>,
        /// 同时签发一个 Webhook 令牌；明文只打印一次。
        #[arg(long)]
        webhook_token_label: Option<String>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 删除（写入墓碑）Flow 定义。
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 为 Webhook Flow 签发令牌，明文只打印一次。
    TokenCreate {
        name: String,
        #[arg(long, default_value = "Webhook")]
        label: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 按公开 ID 撤销 Webhook 令牌。
    TokenRevoke {
        name: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 手动创建一次 Flow 运行。
    Trigger {
        name: String,
        #[arg(long, default_value = "{}")]
        input: String,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 列出最近的 Flow 运行。
    Runs {
        name: String,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 查看运行、节点步骤和审计事件。
    Run {
        name: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 取消尚未结束的运行。
    Cancel(FlowActionArgs),
    /// 从原输入重试终态运行。
    Retry(FlowActionArgs),
    /// 查看每种状态的运行计数。
    Stats {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(clap::Args)]
struct FlowActionArgs {
    name: String,
    id: String,
    #[arg(long, env = "RF_NODE")]
    node: String,
    #[arg(long, env = "RF_CLUSTER_SECRET")]
    secret: String,
}

fn secret_bytes(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim()).context("cluster secret must be hex")?;
    b.try_into()
        .map_err(|_| anyhow::anyhow!("cluster secret must be 32 bytes"))
}

fn operator_key(path: Option<PathBuf>) -> Result<rf_core::identity::AnyKeypair> {
    let path = path.unwrap_or_else(default_operator_key_path);
    rf::keys::load_any(&path)
}

fn default_operator_key_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".rf").join("operator.key")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Two worker threads: the coordination layer must stay tiny; the
    // real work happens in workerd children.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen { dir, eth } => keygen(dir, eth),
        Cmd::Run { config } => run(config).await,
        Cmd::Doctor { config, json } => doctor(config, json),
        Cmd::Health { node } => health(&node).await,
        Cmd::Console {
            node,
            secret,
            key,
            listen,
        } => {
            let operator = match key {
                Some(path) => Some(operator_key(Some(path))?),
                None => {
                    let path = default_operator_key_path();
                    if path.is_file() {
                        Some(operator_key(Some(path))?)
                    } else {
                        None
                    }
                }
            };
            rf::console::serve(listen, node, secret_bytes(&secret)?, operator).await
        }
        Cmd::Authorize {
            code,
            node,
            key,
            secret,
        } => {
            use base64::Engine as _;

            let client = PeerClient::new(secret_bytes(&secret)?);
            let approval = client.authorization(&node, &code).await?;
            let status = client.status(&node).await?;
            let cluster_id = status
                .get("cluster_id")
                .and_then(serde_json::Value::as_str)
                .context("节点状态中缺少 cluster_id")?;
            let configured_operator: rf_core::identity::SignerId = status
                .get("operator")
                .and_then(serde_json::Value::as_str)
                .context("节点状态中缺少 operator")?
                .parse()
                .map_err(|error| anyhow::anyhow!("节点返回的管理员身份无效：{error}"))?;
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&approval.payload_base64)
                .context("节点返回的审批载荷无效")?;
            let operator = operator_key(key)?;
            if operator.signer_id() != configured_operator {
                anyhow::bail!("管理员密钥与节点 {node} 配置的管理员身份不匹配");
            }
            let description = describe_approval(approval.kind, &payload, cluster_id, &node)?;
            println!("{description}");
            let request = rf::management::ApprovalSignature {
                signer: operator.signer_id(),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(operator.sign(&payload)),
            };
            client.approve_authorization(&node, &code, &request).await?;
            println!("已批准 {}", approval.code);
            Ok(())
        }
        Cmd::Deploy {
            dir,
            node,
            key,
            secret,
        } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let op = operator_key(key)?;
            let bundle = rf::deploy::read_bundle(&dir)?;
            let version = rf::deploy::deploy(&bundle, &client, &node, &op).await?;
            println!("deployed {} v{version}", bundle.spec.name);
            Ok(())
        }
        Cmd::Status { node, secret } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let status = client.status(&node).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Cmd::WorkerDelete {
            name,
            node,
            key,
            secret,
        } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let op = operator_key(key)?;
            let v = rf::deploy::delete_worker(&name, &client, &node, &op).await?;
            println!("tombstoned {name} at v{v}");
            Ok(())
        }
        Cmd::Kv { cmd } => match cmd {
            KvCmd::List {
                ns,
                prefix,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                for key in client.kv_list(&node, &ns, &prefix).await? {
                    println!("{key}");
                }
                Ok(())
            }
            KvCmd::Get {
                ns,
                key,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                match client.kv_get(&node, &ns, &key).await? {
                    Some(v) => {
                        use std::io::Write;
                        std::io::stdout().write_all(&v)?;
                        Ok(())
                    }
                    None => {
                        eprintln!("(not found)");
                        std::process::exit(1);
                    }
                }
            }
            KvCmd::Put {
                ns,
                key,
                value,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                client.kv_put(&node, &ns, &key, value.into_bytes()).await?;
                Ok(())
            }
            KvCmd::Delete {
                ns,
                key,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                client.kv_delete(&node, &ns, &key).await?;
                Ok(())
            }
        },
        Cmd::D1 { cmd } => match cmd {
            D1Cmd::Create { name, node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let resp = client
                    .post(
                        &node,
                        "/v1/d1/create",
                        serde_json::json!({ "name": name }).to_string().into_bytes(),
                    )
                    .await?;
                println!("{}", String::from_utf8_lossy(&resp));
                Ok(())
            }
            D1Cmd::Exec {
                name,
                sql,
                params,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let params: serde_json::Value = serde_json::from_str(&params)?;
                let out = client.d1_exec(&node, &name, &sql, params).await?;
                println!("{}", serde_json::to_string_pretty(&out)?);
                Ok(())
            }
        },
        Cmd::R2 { cmd } => match cmd {
            R2Cmd::BucketList { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let buckets = client
                    .resource_heads(&node, Some(rf::r2::BUCKET_KIND))
                    .await?
                    .into_iter()
                    .filter(|view| !view.resource.deleted)
                    .map(|view| {
                        let spec = rf::r2::bucket_spec(&view.resource)?;
                        Ok(serde_json::json!({
                            "name": view.resource.name,
                            "version": view.resource.version,
                            "digest": view.digest,
                            "spec": spec,
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                println!("{}", serde_json::to_string_pretty(&buckets)?);
                Ok(())
            }
            R2Cmd::BucketCreate {
                name,
                description,
                public,
                rclone_remote,
                rclone_prefix,
                max_bytes,
                max_objects,
                expire_after_days,
                cors_origins,
                hostnames,
                node,
                key,
                secret,
            } => {
                let storage = match rclone_remote {
                    Some(remote) => rf::objectstore::StorageLocation::Rclone {
                        remote,
                        prefix: rclone_prefix,
                    },
                    None if rclone_prefix.is_empty() => rf::objectstore::StorageLocation::Local,
                    None => anyhow::bail!("--rclone-prefix 必须与 --rclone-remote 一起使用"),
                };
                let spec = rf::r2::BucketSpec {
                    description,
                    public_access: public,
                    storage,
                    max_bytes,
                    max_objects,
                    expire_objects_after_days: expire_after_days,
                    cors_origins,
                    hostnames,
                };
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::r2::BUCKET_KIND, &name)
                    .await?;
                let record = rf::r2::prepare_bucket_after(&name, spec, false, head.as_ref())?;
                let operator = operator_key(key)?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator);
                client.post_resource(&node, &envelope).await?;
                println!("R2 bucket {} 已更新至 v{}", record.name, record.version);
                Ok(())
            }
            R2Cmd::BucketDelete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::r2::BUCKET_KIND, &name)
                    .await?
                    .with_context(|| format!("R2 bucket {name} 不存在"))?;
                if head.resource.deleted {
                    anyhow::bail!("R2 bucket {name} 已删除");
                }
                let spec = rf::r2::bucket_spec(&head.resource)?;
                let record = rf::r2::prepare_bucket_after(&name, spec, true, Some(&head))?;
                let operator = operator_key(key)?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator);
                client.post_resource(&node, &envelope).await?;
                println!("R2 bucket {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
            R2Cmd::List {
                bucket,
                prefix,
                cursor,
                limit,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let objects = client
                    .r2_list(&node, &bucket, &prefix, cursor.as_deref(), limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&objects)?);
                Ok(())
            }
            R2Cmd::Head {
                bucket,
                object,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let metadata = client
                    .r2_head(&node, &bucket, &object)
                    .await?
                    .with_context(|| format!("R2 对象 {bucket}/{object} 不存在"))?;
                println!("{}", serde_json::to_string_pretty(&metadata)?);
                Ok(())
            }
            R2Cmd::Put {
                bucket,
                object,
                file,
                content_type,
                node,
                secret,
            } => {
                let bytes = std::fs::read(&file)
                    .with_context(|| format!("读取上传文件 {}", file.display()))?;
                let client = PeerClient::new(secret_bytes(&secret)?);
                let metadata = client
                    .r2_put(
                        &node,
                        &bucket,
                        &object,
                        &bytes,
                        &rf::r2::PutOptions {
                            content_type,
                            ..Default::default()
                        },
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&metadata)?);
                Ok(())
            }
            R2Cmd::Get {
                bucket,
                object,
                output,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let (_, bytes) = client
                    .r2_get(&node, &bucket, &object)
                    .await?
                    .with_context(|| format!("R2 对象 {bucket}/{object} 不存在"))?;
                if let Some(path) = output {
                    if path.exists() {
                        anyhow::bail!("拒绝覆盖已有文件：{}", path.display());
                    }
                    std::fs::write(&path, bytes)
                        .with_context(|| format!("写入下载文件 {}", path.display()))?;
                } else {
                    use std::io::Write;
                    std::io::stdout().write_all(&bytes)?;
                }
                Ok(())
            }
            R2Cmd::Delete {
                bucket,
                object,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                if !client.r2_delete(&node, &bucket, &object).await? {
                    anyhow::bail!("R2 对象 {bucket}/{object} 不存在");
                }
                println!("R2 对象 {bucket}/{object} 已删除");
                Ok(())
            }
        },
        Cmd::Queue { cmd } => match cmd {
            QueueCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let records = client
                    .resource_heads(&node, Some(rf::queue::QUEUE_KIND))
                    .await?;
                let mut queues = Vec::new();
                for view in records.into_iter().filter(|view| !view.resource.deleted) {
                    let spec = rf::queue::queue_spec(&view.resource)?;
                    let stats = client.queue_stats(&node, &view.resource.name).await.ok();
                    queues.push(serde_json::json!({
                        "name": view.resource.name,
                        "version": view.resource.version,
                        "digest": view.digest,
                        "spec": spec,
                        "stats": stats,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&queues)?);
                Ok(())
            }
            QueueCmd::Create {
                name,
                description,
                consumer,
                batch_size,
                max_wait_ms,
                max_retries,
                visibility_timeout_ms,
                retention_seconds,
                dead_letter_queue,
                suspended,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::queue::QUEUE_KIND, &name)
                    .await?;
                let spec = rf::queue::QueueSpec {
                    description,
                    consumer_worker: consumer,
                    batch_size,
                    max_wait_ms,
                    max_retries,
                    visibility_timeout_ms,
                    retention_seconds,
                    dead_letter_queue,
                    suspended,
                };
                let record = rf::queue::prepare_queue_after(&name, spec, false, head.as_ref())?;
                let operator = operator_key(key)?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator);
                client.post_resource(&node, &envelope).await?;
                println!("队列 {} 已更新至 v{}", record.name, record.version);
                Ok(())
            }
            QueueCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::queue::QUEUE_KIND, &name)
                    .await?
                    .with_context(|| format!("队列 {name} 不存在"))?;
                if head.resource.deleted {
                    anyhow::bail!("队列 {name} 已删除");
                }
                let spec = rf::queue::queue_spec(&head.resource)?;
                let record = rf::queue::prepare_queue_after(&name, spec, true, Some(&head))?;
                let operator = operator_key(key)?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator);
                client.post_resource(&node, &envelope).await?;
                println!("队列 {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
            QueueCmd::Send {
                name,
                body,
                delay_seconds,
                node,
                secret,
            } => {
                let body = serde_json::from_str(&body).context("队列消息体必须是 JSON")?;
                let client = PeerClient::new(secret_bytes(&secret)?);
                let ids = client
                    .queue_send(
                        &node,
                        &name,
                        &[rf::queue::SendMessage {
                            body,
                            delay_seconds,
                        }],
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&ids)?);
                Ok(())
            }
            QueueCmd::Stats { name, node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let stats = client.queue_stats(&node, &name).await?;
                println!("{}", serde_json::to_string_pretty(&stats)?);
                Ok(())
            }
            QueueCmd::Dead {
                name,
                limit,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let messages = client.queue_dead_letters(&node, &name, limit).await?;
                println!("{}", serde_json::to_string_pretty(&messages)?);
                Ok(())
            }
            QueueCmd::Redrive {
                name,
                id,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                if !client.queue_redrive(&node, &name, &id).await? {
                    anyhow::bail!("死信 {id} 不存在");
                }
                println!("死信 {id} 已重新入队");
                Ok(())
            }
        },
        Cmd::Analytics { cmd } => match cmd {
            AnalyticsCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let records = client
                    .resource_heads(&node, Some(rf::analytics::DATASET_KIND))
                    .await?;
                let mut datasets = Vec::new();
                for view in records.into_iter().filter(|view| !view.resource.deleted) {
                    let spec = rf::analytics::dataset_spec(&view.resource)?;
                    let stats = client
                        .analytics_stats(&node, &view.resource.name)
                        .await
                        .ok();
                    datasets.push(serde_json::json!({
                        "name": view.resource.name,
                        "version": view.resource.version,
                        "digest": view.digest,
                        "spec": spec,
                        "stats": stats,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&datasets)?);
                Ok(())
            }
            AnalyticsCmd::Create {
                name,
                description,
                retention_days,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::analytics::DATASET_KIND, &name)
                    .await?;
                let record = rf::analytics::prepare_dataset_after(
                    &name,
                    rf::analytics::DatasetSpec {
                        description,
                        retention_days,
                    },
                    false,
                    head.as_ref(),
                )?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!(
                    "Analytics 数据集 {} 已更新至 v{}",
                    record.name, record.version
                );
                Ok(())
            }
            AnalyticsCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::analytics::DATASET_KIND, &name)
                    .await?
                    .with_context(|| format!("Analytics 数据集 {name} 不存在"))?;
                if head.resource.deleted {
                    anyhow::bail!("Analytics 数据集 {name} 已删除");
                }
                let spec = rf::analytics::dataset_spec(&head.resource)?;
                let record = rf::analytics::prepare_dataset_after(&name, spec, true, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!(
                    "Analytics 数据集 {} 已删除（v{}）",
                    record.name, record.version
                );
                Ok(())
            }
            AnalyticsCmd::Write {
                name,
                point,
                node,
                secret,
            } => {
                let point: rf::analytics::DataPoint =
                    serde_json::from_str(&point).context("数据点必须是 Analytics JSON 对象")?;
                let written = PeerClient::new(secret_bytes(&secret)?)
                    .analytics_write(&node, &name, &[point])
                    .await?;
                println!("已写入 {written} 个 Analytics 数据点");
                Ok(())
            }
            AnalyticsCmd::Stats { name, node, secret } => {
                let stats = PeerClient::new(secret_bytes(&secret)?)
                    .analytics_stats(&node, &name)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&stats)?);
                Ok(())
            }
            AnalyticsCmd::Events {
                name,
                limit,
                before,
                node,
                secret,
            } => {
                let events = PeerClient::new(secret_bytes(&secret)?)
                    .analytics_recent(&node, &name, before, limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&events)?);
                Ok(())
            }
            AnalyticsCmd::Group {
                name,
                dimension,
                dimension_index,
                double_index,
                since,
                limit,
                node,
                secret,
            } => {
                let groups = PeerClient::new(secret_bytes(&secret)?)
                    .analytics_group(
                        &node,
                        &name,
                        &dimension,
                        dimension_index,
                        double_index,
                        since,
                        limit,
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&groups)?);
                Ok(())
            }
        },
        Cmd::Pipeline { cmd } => match cmd {
            PipelineCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let records = client
                    .resource_heads(&node, Some(rf::pipeline::PIPELINE_KIND))
                    .await?;
                let mut pipelines = Vec::new();
                for view in records.into_iter().filter(|view| !view.resource.deleted) {
                    let spec = rf::pipeline::pipeline_spec(&view.resource)?;
                    let status = client
                        .pipeline_status(&node, &view.resource.name)
                        .await
                        .ok();
                    pipelines.push(serde_json::json!({
                        "name": view.resource.name,
                        "version": view.resource.version,
                        "digest": view.digest,
                        "spec": spec,
                        "status": status,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&pipelines)?);
                Ok(())
            }
            PipelineCmd::Create {
                name,
                bucket,
                description,
                key_template,
                batch_max_bytes,
                batch_max_seconds,
                schema,
                hostname,
                suspended,
                suspend_reason,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::pipeline::PIPELINE_KIND, &name)
                    .await?;
                let tokens = head
                    .as_ref()
                    .filter(|view| !view.resource.deleted)
                    .map(|view| rf::pipeline::pipeline_spec(&view.resource))
                    .transpose()?
                    .map(|spec| spec.tokens)
                    .unwrap_or_default();
                let schema = schema
                    .map(|raw| serde_json::from_str(&raw).context("--schema 必须是 JSON Schema"))
                    .transpose()?;
                let spec = rf::pipeline::PipelineSpec {
                    description,
                    output_bucket: bucket,
                    output_key_template: key_template,
                    batch_max_bytes,
                    batch_max_seconds,
                    schema,
                    suspended,
                    suspend_reason,
                    hostnames: hostname
                        .into_iter()
                        .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
                        .collect(),
                    tokens,
                };
                let record =
                    rf::pipeline::prepare_pipeline_after(&name, spec, false, head.as_ref())?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Pipeline {} 已更新至 v{}", record.name, record.version);
                Ok(())
            }
            PipelineCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::pipeline::PIPELINE_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Pipeline {name} 不存在"))?;
                let spec = rf::pipeline::pipeline_spec(&head.resource)?;
                let record = rf::pipeline::prepare_pipeline_after(&name, spec, true, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Pipeline {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
            PipelineCmd::TokenCreate {
                name,
                label,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::pipeline::PIPELINE_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Pipeline {name} 不存在"))?;
                let mut spec = rf::pipeline::pipeline_spec(&head.resource)?;
                let (token, plaintext) = rf::pipeline::mint_token(label)?;
                spec.tokens.push(token);
                let record = rf::pipeline::prepare_pipeline_after(&name, spec, false, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("{plaintext}");
                Ok(())
            }
            PipelineCmd::TokenRevoke {
                name,
                id,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::pipeline::PIPELINE_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Pipeline {name} 不存在"))?;
                let mut spec = rf::pipeline::pipeline_spec(&head.resource)?;
                let before = spec.tokens.len();
                spec.tokens.retain(|token| token.id != id);
                if before == spec.tokens.len() {
                    anyhow::bail!("Pipeline 令牌 {id} 不存在");
                }
                let record = rf::pipeline::prepare_pipeline_after(&name, spec, false, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Pipeline 令牌 {id} 已撤销");
                Ok(())
            }
            PipelineCmd::Send {
                name,
                events,
                node,
                secret,
            } => {
                let value: serde_json::Value =
                    serde_json::from_str(&events).context("Pipeline 事件必须是 JSON")?;
                let events = match value {
                    serde_json::Value::Array(events) => events,
                    event => vec![event],
                };
                let accepted = PeerClient::new(secret_bytes(&secret)?)
                    .pipeline_ingest(&node, &name, &events)
                    .await?;
                println!("Pipeline 已接收 {accepted} 个事件");
                Ok(())
            }
            PipelineCmd::Status { name, node, secret } => {
                let status = PeerClient::new(secret_bytes(&secret)?)
                    .pipeline_status(&node, &name)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            PipelineCmd::Batches {
                name,
                limit,
                node,
                secret,
            } => {
                let batches = PeerClient::new(secret_bytes(&secret)?)
                    .pipeline_batches(&node, &name, limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&batches)?);
                Ok(())
            }
            PipelineCmd::Flush { name, node, secret } => {
                let batch = PeerClient::new(secret_bytes(&secret)?)
                    .pipeline_flush(&node, &name)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&batch)?);
                Ok(())
            }
        },
        Cmd::Workflow { cmd } => match cmd {
            WorkflowCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let records = client
                    .resource_heads(&node, Some(rf::workflow::WORKFLOW_KIND))
                    .await?;
                let mut workflows = Vec::new();
                for view in records.into_iter().filter(|view| !view.resource.deleted) {
                    let spec = rf::workflow::workflow_spec(&view.resource)?;
                    let stats = client.workflow_stats(&node, &view.resource.name).await.ok();
                    workflows.push(serde_json::json!({
                        "name": view.resource.name,
                        "version": view.resource.version,
                        "digest": view.digest,
                        "spec": spec,
                        "stats": stats,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&workflows)?);
                Ok(())
            }
            WorkflowCmd::Create {
                name,
                worker,
                entrypoint,
                description,
                retention_days,
                instance_retries,
                instance_timeout_seconds,
                suspended,
                suspend_reason,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::workflow::WORKFLOW_KIND, &name)
                    .await?;
                let spec = rf::workflow::WorkflowSpec {
                    description,
                    worker,
                    entrypoint,
                    suspended,
                    suspend_reason,
                    retention_days,
                    instance_retries,
                    instance_timeout_seconds,
                };
                let record =
                    rf::workflow::prepare_workflow_after(&name, spec, false, head.as_ref())?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Workflow {} 已更新至 v{}", record.name, record.version);
                Ok(())
            }
            WorkflowCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::workflow::WORKFLOW_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Workflow {name} 不存在"))?;
                let spec = rf::workflow::workflow_spec(&head.resource)?;
                let record = rf::workflow::prepare_workflow_after(&name, spec, true, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Workflow {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
            WorkflowCmd::Trigger {
                name,
                input,
                idempotency_key,
                node,
                secret,
            } => {
                let input = serde_json::from_str(&input).context("Workflow 输入必须是有效 JSON")?;
                let instance = PeerClient::new(secret_bytes(&secret)?)
                    .workflow_create(&node, &name, idempotency_key.as_deref(), input)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&instance)?);
                Ok(())
            }
            WorkflowCmd::Instances {
                name,
                status,
                limit,
                node,
                secret,
            } => {
                let instances = PeerClient::new(secret_bytes(&secret)?)
                    .workflow_instances(&node, &name, status.as_deref(), limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&instances)?);
                Ok(())
            }
            WorkflowCmd::Instance {
                name,
                id,
                node,
                secret,
            } => {
                let instance = PeerClient::new(secret_bytes(&secret)?)
                    .workflow_instance(&node, &name, &id)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&instance)?);
                Ok(())
            }
            WorkflowCmd::Signal {
                name,
                id,
                signal,
                payload,
                node,
                secret,
            } => {
                let payload =
                    serde_json::from_str(&payload).context("Workflow 信号负载必须是有效 JSON")?;
                let signal_id = PeerClient::new(secret_bytes(&secret)?)
                    .workflow_signal(&node, &name, &id, &signal, payload)
                    .await?;
                println!("Workflow 信号已写入：{signal_id}");
                Ok(())
            }
            WorkflowCmd::Pause(args) => {
                PeerClient::new(secret_bytes(&args.secret)?)
                    .workflow_action(&args.node, &args.name, &args.id, "pause")
                    .await?;
                println!("Workflow 实例 {} 已暂停", args.id);
                Ok(())
            }
            WorkflowCmd::Resume(args) => {
                PeerClient::new(secret_bytes(&args.secret)?)
                    .workflow_action(&args.node, &args.name, &args.id, "resume")
                    .await?;
                println!("Workflow 实例 {} 已恢复", args.id);
                Ok(())
            }
            WorkflowCmd::Terminate(args) => {
                PeerClient::new(secret_bytes(&args.secret)?)
                    .workflow_action(&args.node, &args.name, &args.id, "terminate")
                    .await?;
                println!("Workflow 实例 {} 已终止", args.id);
                Ok(())
            }
            WorkflowCmd::Restart(args) => {
                PeerClient::new(secret_bytes(&args.secret)?)
                    .workflow_action(&args.node, &args.name, &args.id, "restart")
                    .await?;
                println!("Workflow 实例 {} 已重启", args.id);
                Ok(())
            }
            WorkflowCmd::Stats { name, node, secret } => {
                let stats = PeerClient::new(secret_bytes(&secret)?)
                    .workflow_stats(&node, &name)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&stats)?);
                Ok(())
            }
        },
        Cmd::Flow { cmd } => match cmd {
            FlowCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let records = client
                    .resource_heads(&node, Some(rf::flow::FLOW_KIND))
                    .await?;
                let mut flows = Vec::new();
                for view in records.into_iter().filter(|view| !view.resource.deleted) {
                    let spec = rf::flow::flow_spec(&view.resource)?;
                    let stats = client.flow_stats(&node, &view.resource.name).await.ok();
                    flows.push(serde_json::json!({
                        "name": view.resource.name,
                        "version": view.resource.version,
                        "digest": view.digest,
                        "spec": spec,
                        "stats": stats,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&flows)?);
                Ok(())
            }
            FlowCmd::Create {
                name,
                graph,
                trigger,
                cron,
                description,
                hostname,
                retention_days,
                max_concurrent_runs,
                suspended,
                suspend_reason,
                alert_webhook_env,
                webhook_token_label,
                node,
                key,
                secret,
            } => {
                let graph: rf::flow::FlowGraph = serde_json::from_str(
                    &std::fs::read_to_string(&graph)
                        .with_context(|| format!("无法读取 Flow 图 {}", graph.display()))?,
                )
                .context("Flow 图文件必须是有效 FlowGraph JSON")?;
                let trigger = match trigger.as_str() {
                    "manual" => rf::flow::FlowTrigger::Manual,
                    "webhook" => rf::flow::FlowTrigger::Webhook,
                    "cron" => rf::flow::FlowTrigger::Cron,
                    _ => anyhow::bail!("Flow trigger 只允许 manual、webhook 或 cron"),
                };
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::flow::FLOW_KIND, &name)
                    .await?;
                let mut tokens = head
                    .as_ref()
                    .and_then(|head| rf::flow::flow_spec(&head.resource).ok())
                    .map(|spec| spec.tokens)
                    .unwrap_or_default();
                let plaintext = if let Some(label) = webhook_token_label {
                    let (token, plaintext) = rf::flow::mint_token(label)?;
                    tokens.push(token);
                    Some(plaintext)
                } else {
                    None
                };
                let spec = rf::flow::FlowSpec {
                    description,
                    graph,
                    trigger,
                    cron,
                    hostnames: hostname,
                    tokens,
                    suspended,
                    suspend_reason,
                    retention_days,
                    max_concurrent_runs,
                    alert_webhook_env,
                };
                let record = rf::flow::prepare_flow_after(&name, spec, false, head.as_ref())?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Flow {} 已更新至 v{}", record.name, record.version);
                if let Some(plaintext) = plaintext {
                    println!("Webhook 令牌（仅显示一次）：{plaintext}");
                }
                Ok(())
            }
            FlowCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::flow::FLOW_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Flow {name} 不存在"))?;
                let spec = rf::flow::flow_spec(&head.resource)?;
                let record = rf::flow::prepare_flow_after(&name, spec, true, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Flow {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
            FlowCmd::TokenCreate {
                name,
                label,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::flow::FLOW_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Flow {name} 不存在"))?;
                let mut spec = rf::flow::flow_spec(&head.resource)?;
                let (token, plaintext) = rf::flow::mint_token(label)?;
                spec.tokens.push(token);
                let record = rf::flow::prepare_flow_after(&name, spec, false, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("{plaintext}");
                Ok(())
            }
            FlowCmd::TokenRevoke {
                name,
                id,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::flow::FLOW_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Flow {name} 不存在"))?;
                let mut spec = rf::flow::flow_spec(&head.resource)?;
                let before = spec.tokens.len();
                spec.tokens.retain(|token| token.id != id);
                if before == spec.tokens.len() {
                    anyhow::bail!("Flow Webhook 令牌 {id} 不存在");
                }
                let record = rf::flow::prepare_flow_after(&name, spec, false, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Flow Webhook 令牌 {id} 已撤销");
                Ok(())
            }
            FlowCmd::Trigger {
                name,
                input,
                idempotency_key,
                node,
                secret,
            } => {
                let input = serde_json::from_str(&input).context("Flow 输入必须是有效 JSON")?;
                let run = PeerClient::new(secret_bytes(&secret)?)
                    .flow_create(&node, &name, idempotency_key.as_deref(), input)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&run)?);
                Ok(())
            }
            FlowCmd::Runs {
                name,
                status,
                limit,
                node,
                secret,
            } => {
                let runs = PeerClient::new(secret_bytes(&secret)?)
                    .flow_runs(&node, &name, status.as_deref(), limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&runs)?);
                Ok(())
            }
            FlowCmd::Run {
                name,
                id,
                node,
                secret,
            } => {
                let run = PeerClient::new(secret_bytes(&secret)?)
                    .flow_run(&node, &name, &id)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&run)?);
                Ok(())
            }
            FlowCmd::Cancel(args) => {
                PeerClient::new(secret_bytes(&args.secret)?)
                    .flow_action(&args.node, &args.name, &args.id, "cancel")
                    .await?;
                println!("Flow 运行 {} 已取消", args.id);
                Ok(())
            }
            FlowCmd::Retry(args) => {
                let run = PeerClient::new(secret_bytes(&args.secret)?)
                    .flow_action(&args.node, &args.name, &args.id, "retry")
                    .await?;
                println!("{}", serde_json::to_string_pretty(&run)?);
                Ok(())
            }
            FlowCmd::Stats { name, node, secret } => {
                let stats = PeerClient::new(secret_bytes(&secret)?)
                    .flow_stats(&node, &name)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&stats)?);
                Ok(())
            }
        },
        Cmd::Log {
            worker,
            node,
            secret,
            operator,
            key,
        } => {
            let client = PeerClient::new(secret_bytes(&secret)?);
            let operator_id: rf_core::identity::SignerId = match operator {
                Some(s) => s.parse().map_err(|e| anyhow::anyhow!("--operator: {e}"))?,
                None => operator_key(key)?.signer_id(),
            };
            let envs = client.worker_log(&node, &worker).await?;
            let chain = rf_core::manifest::verify_chain(&envs, &operator_id)
                .map_err(|e| anyhow::anyhow!("chain verification FAILED: {e}"))?;
            println!(
                "transparency log for {worker} — {} entries, chain OK",
                chain.len()
            );
            for (m, env) in chain.iter().zip(&envs) {
                println!(
                    "  v{:<4} {}  {}{}",
                    m.version,
                    hex::encode(&env.digest()[..8]),
                    if m.deleted { "[tombstone] " } else { "" },
                    m.hostnames.join(",")
                );
            }
            Ok(())
        }
    }
}

fn describe_approval(
    kind: rf::management::ApprovalKind,
    payload: &[u8],
    expected_cluster_id: &str,
    node: &str,
) -> Result<String> {
    match kind {
        rf::management::ApprovalKind::Login => {
            let grant: rf::management::ConsoleGrant =
                postcard::from_bytes(payload).context("节点返回的控制台授权凭证无效")?;
            grant
                .validate(expected_cluster_id, rf::node::now_ms())
                .context("已拒绝无效的控制台授权凭证")?;
            Ok(format!(
                "通过节点 {node} 登录 RandallFlare 集群 {}",
                grant.cluster_id
            ))
        }
        rf::management::ApprovalKind::Manifest => {
            let manifest: rf_core::manifest::WorkerManifest =
                postcard::from_bytes(payload).context("节点返回的 Worker 部署清单无效")?;
            manifest
                .validate()
                .map_err(|error| anyhow::anyhow!("已拒绝无效的部署清单：{error}"))?;
            if manifest.deleted {
                return Ok(format!(
                    "删除 Worker {}（生成版本 v{}）",
                    manifest.name, manifest.version
                ));
            }
            let routes = if manifest.hostnames.is_empty() {
                "无".to_string()
            } else {
                manifest.hostnames.join(", ")
            };
            let env_keys = if manifest.env.is_empty() {
                "无".to_string()
            } else {
                manifest.env.keys().cloned().collect::<Vec<_>>().join(", ")
            };
            Ok(format!(
                "部署 Worker {} v{}（{} 个模块，{} 项静态资源）\n  路由：{}\n  环境变量键：{}\n  KV 绑定：{}\n  定时触发器：{}",
                manifest.name,
                manifest.version,
                manifest.modules.len(),
                manifest.assets.len(),
                routes,
                env_keys,
                manifest.kv_bindings.len(),
                manifest.crons.len(),
            ))
        }
        rf::management::ApprovalKind::Source => {
            let source: rf::build::WorkerSource =
                postcard::from_bytes(payload).context("节点返回的 Worker 源码配置无效")?;
            source.validate().context("已拒绝无效的 Worker 源码配置")?;
            if source.deleted {
                Ok(format!(
                    "断开 Worker {} 与 GitHub 仓库的连接（源码配置 v{}）",
                    source.worker, source.version
                ))
            } else {
                Ok(format!(
                    "将 Worker {} 连接至 {} 的 {} 分支（源码配置 v{}）\n  项目目录：{}\n  构建命令：{}\n  产物目录：{}\n  使用私有令牌：{}\n  Webhook：{}",
                    source.worker,
                    source.repository,
                    source.branch,
                    source.version,
                    source.root,
                    if source.build_command.is_empty() { "零配置构建" } else { &source.build_command },
                    source.output_dir,
                    if source.use_github_token { "是" } else { "否" },
                    if source.webhook { "已启用" } else { "未启用" },
                ))
            }
        }
        rf::management::ApprovalKind::Resource => {
            let resource: rf::resource::ResourceRecord =
                postcard::from_bytes(payload).context("节点返回的平台资源配置无效")?;
            resource.validate().context("已拒绝无效的平台资源配置")?;
            if resource.deleted {
                Ok(format!(
                    "删除平台资源 {}/{}（生成版本 v{}）",
                    resource.kind, resource.name, resource.version
                ))
            } else {
                Ok(format!(
                    "更新平台资源 {}/{} v{}\n  配置摘要：{}",
                    resource.kind,
                    resource.name,
                    resource.version,
                    &rf::blob::sha256_hex(resource.spec_json.as_bytes())[..16],
                ))
            }
        }
    }
}

fn doctor(config: PathBuf, json: bool) -> Result<()> {
    let cfg = NodeConfig::load(&config)?;
    let configured_workerd = cfg.runtime.workerd.clone();
    let workerd = configured_workerd
        .clone()
        .or_else(rf::runtime::find_workerd);
    if let Some(path) = configured_workerd.as_ref() {
        if !path.is_file() {
            anyhow::bail!("configured workerd does not exist: {}", path.display());
        }
    }
    let workerd_version = workerd.as_ref().and_then(|path| {
        std::process::Command::new(path)
            .arg("--version")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
    });
    let git = rf::build::configured_binary(cfg.build.git.as_deref(), "git");
    let sandbox = rf::build::configured_binary(cfg.build.sandbox.as_deref(), "bwrap");
    let rclone_version = cfg.storage.rclone_binary.as_ref().and_then(|path| {
        std::process::Command::new(path)
            .arg("version")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .map(str::to_string)
            })
    });
    if let (Some(path), None) = (&configured_workerd, &workerd_version) {
        anyhow::bail!(
            "configured workerd could not be executed successfully: {}",
            path.display()
        );
    }
    let mut warnings = Vec::new();
    if workerd_version.is_none() {
        warnings.push("workerd not found; module workers and Durable Objects will be unavailable");
    }
    if cfg.build.enabled && git.is_none() {
        warnings.push("Git builds are enabled but git was not found");
    }
    if cfg.build.enabled && sandbox.is_none() {
        warnings.push(
            "bubblewrap was not found; zero-config builds work, custom build commands do not",
        );
    }
    if let Some(path) = &cfg.storage.rclone_binary {
        if rclone_version.is_none() {
            anyhow::bail!(
                "configured rclone could not be executed: {}",
                path.display()
            );
        }
    }
    if let Some(path) = &cfg.storage.rclone_config {
        if !path.is_file() {
            anyhow::bail!(
                "configured rclone config does not exist: {}",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                warnings.push("rclone config is readable by group or others; use mode 0600");
            }
        }
    }
    if cfg.public && cfg.ingress.http.is_none() && cfg.ingress.https.is_none() {
        warnings.push("public node has no HTTP or HTTPS ingress listener");
    }
    if !cfg.public && (cfg.ingress.http.is_some() || cfg.ingress.https.is_some()) {
        warnings.push("ingress is configured but public=false disables it");
    }
    if let Some(dns) = &cfg.dns {
        if std::env::var_os(&dns.api_token_env).is_none() {
            warnings.push("DNS is configured but its API token environment variable is absent");
        }
    }
    if let Some(acme) = &cfg.acme {
        let token_env = acme
            .api_token_env
            .as_deref()
            .or_else(|| cfg.dns.as_ref().map(|dns| dns.api_token_env.as_str()))
            .unwrap_or("CF_API_TOKEN");
        if std::env::var_os(token_env).is_none() {
            warnings.push("ACME is configured but its API token environment variable is absent");
        }
        if acme.zone.is_none() && cfg.dns.is_none() {
            warnings.push("ACME is configured but neither acme.zone nor dns.zone is set");
        }
    }
    if cfg.update.enabled {
        warnings.push(
            "self-update is enabled; the hardened systemd service intentionally cannot replace /usr/local/bin/rf",
        );
    }
    let report = serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "config": config,
        "data_dir": cfg.data_dir,
        "label": cfg.label,
        "operator": cfg.operator.to_string(),
        "public": cfg.public,
        "gossip_listen": cfg.gossip.listen,
        "gossip_advertise": cfg.gossip_advertise(),
        "peer_api_listen": cfg.peer_api.listen,
        "peer_api_advertise": cfg.peer_api_advertise(),
        "ingress_http": cfg.ingress.http,
        "ingress_https": cfg.ingress.https,
        "workerd": workerd,
        "workerd_version": workerd_version,
        "build_enabled": cfg.build.enabled,
        "git": git,
        "build_sandbox": sandbox,
        "github_token_configured": std::env::var_os(&cfg.build.github_token_env).is_some(),
        "object_storage": {
            "local_dir": cfg.storage.local_dir,
            "rclone": rclone_version,
            "rclone_configured": cfg.storage.rclone_config.is_some(),
        },
        "warnings": warnings,
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("configuration OK: {}", config.display());
        println!(
            "node: {} ({})",
            report["label"].as_str().unwrap_or(""),
            report["operator"].as_str().unwrap_or("unknown")
        );
        println!(
            "gossip: {} -> {}",
            report["gossip_listen"], report["gossip_advertise"]
        );
        println!(
            "peer API: {} -> {}",
            report["peer_api_listen"], report["peer_api_advertise"]
        );
        match report["workerd_version"].as_str() {
            Some(version) => println!("runtime: {version}"),
            None => println!("runtime: unavailable (assets-only mode)"),
        }
        if cfg.build.enabled {
            println!(
                "builds: git={} sandbox={}",
                report["git"].as_str().unwrap_or("unavailable"),
                report["build_sandbox"].as_str().unwrap_or("unavailable")
            );
        } else {
            println!("builds: disabled");
        }
        match report["object_storage"]["rclone"].as_str() {
            Some(version) => println!("storage: local + {version}"),
            None => println!("storage: local"),
        }
        for warning in report["warnings"].as_array().into_iter().flatten() {
            println!("warning: {}", warning.as_str().unwrap_or("unknown warning"));
        }
    }
    Ok(())
}

async fn health(node: &str) -> Result<()> {
    let response = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(5))
        .build()?
        .get(format!("http://{node}/v1/ping"))
        .send()
        .await?
        .error_for_status()?;
    let body = response.text().await?;
    let id = parse_ping(&body)?;
    println!("healthy {node} node={id}");
    Ok(())
}

fn parse_ping(body: &str) -> Result<rf_core::identity::PublicId> {
    let mut parts = body.split_whitespace();
    if parts.next() != Some("rf") {
        anyhow::bail!("invalid health response");
    }
    parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("health response omitted node identity"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid node identity in health response: {e}"))
}

async fn detect_public_ipv4() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    for url in ["https://api.ipify.org", "https://ipv4.icanhazip.com"] {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(text) = resp.text().await {
                let ip = text.trim().to_string();
                if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Ok(ip);
                }
            }
        }
    }
    anyhow::bail!("no detector reachable")
}

fn keygen(dir: Option<PathBuf>, eth: bool) -> Result<()> {
    let dir = dir.unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        home.join(".rf")
    });
    let path = dir.join("operator.key");
    if path.exists() {
        anyhow::bail!("{} already exists — refusing to overwrite", path.display());
    }
    let kp = if eth {
        rf_core::identity::AnyKeypair::Eth(rf::keys::generate_eth())
    } else {
        rf_core::identity::AnyKeypair::Ed(rf::keys::generate())
    };
    rf::keys::save_any(&path, &kp)?;
    let mut secret = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut secret);
    println!("operator key   : {}", path.display());
    println!("operator id    : {}", kp.signer_id());
    println!();
    println!("suggested cluster_secret (same on every node):");
    println!("  {}", hex::encode(secret));
    println!();
    println!("node config gets:  operator = \"{}\"", kp.signer_id());
    Ok(())
}

async fn run(config_path: PathBuf) -> Result<()> {
    // Both ring and aws-lc-rs sit in the dep tree (reqwest vs our
    // rustls) — pick ring explicitly or rustls panics at first use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("rustls crypto provider already installed"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,chitchat=warn".into()),
        )
        .init();

    let mut cfg = NodeConfig::load(&config_path)?;
    // Public nodes need their IPv4 for DNS self-registration; detect
    // it when the config doesn't pin one.
    if let Some(dns) = cfg.dns.as_mut() {
        if dns.my_ipv4.is_none() && cfg.public {
            match detect_public_ipv4().await {
                Ok(ip) => {
                    tracing::info!("detected public ipv4: {ip}");
                    dns.my_ipv4 = Some(ip);
                }
                Err(e) => tracing::warn!("public ipv4 detection failed: {e} — set dns.my_ipv4"),
            }
        }
    }
    let cfg = cfg;
    let keypair = rf::keys::load_or_create(&cfg.data_dir.join("node.key"))?;
    tracing::info!("node {} ({})", keypair.public().short(), cfg.label);

    let node = Arc::new(Node::open(cfg, keypair)?);
    rf::build::recover_interrupted(&node);

    let d1_registry: rf::d1::Registry = Default::default();
    let d1_leadership: rf::d1::Leadership = Default::default();
    let durable =
        rf::durable::Coordinator::new(node.clone(), d1_registry.clone(), d1_leadership.clone());
    let api_addr = rf::peerapi::serve(node.clone(), d1_registry.clone(), durable.clone()).await?;
    tracing::info!("peer api on {api_addr}");
    let _d1_manager = rf::d1::spawn_manager(node.clone(), d1_registry, d1_leadership);

    // KV binding backend for workerd — must be up before the runtime
    // writes any workerd config.
    let kvbind_port = rf::kvbind::serve(node.clone()).await?;
    node.set_kvbind_port(kvbind_port);
    tracing::info!("kvbind on 127.0.0.1:{kvbind_port}");
    let r2bind_port = rf::r2bind::serve(node.clone()).await?;
    node.set_r2bind_port(r2bind_port);
    tracing::info!("r2bind on 127.0.0.1:{r2bind_port}");
    let d1bind_port = rf::d1bind::serve(node.clone()).await?;
    node.set_d1bind_port(d1bind_port);
    tracing::info!("d1bind on 127.0.0.1:{d1bind_port}");
    let qbind_port = rf::qbind::serve(node.clone()).await?;
    node.set_qbind_port(qbind_port);
    tracing::info!("queue binding on 127.0.0.1:{qbind_port}");
    let analyticsbind_port = rf::analyticsbind::serve(node.clone()).await?;
    node.set_analyticsbind_port(analyticsbind_port);
    tracing::info!("Analytics binding on 127.0.0.1:{analyticsbind_port}");
    let pbind_port = rf::pbind::serve(node.clone()).await?;
    node.set_pbind_port(pbind_port);
    tracing::info!("Pipeline binding on 127.0.0.1:{pbind_port}");
    let workflowbind_port = rf::workflowbind::serve(node.clone()).await?;
    node.set_workflowbind_port(workflowbind_port);
    tracing::info!("Workflow binding on 127.0.0.1:{workflowbind_port}");

    let _gossip = rf::gossip::start(node.clone()).await?;
    durable.spawn_ensurer();
    durable.spawn_checkpointer();
    rf::gossip::spawn_blob_fetcher(node.clone());
    rf::pipeline::spawn_driver(node.clone());
    rf::workflow::spawn_driver(node.clone());
    rf::flow::spawn_driver(node.clone());
    tracing::info!("gossip on {}", node.cfg.gossip.listen);

    tokio::spawn(rf::runtime::Runtime::new(node.clone(), durable.clone()).run());

    if node.cfg.public {
        if let Some(http) = node.cfg.ingress.http {
            let addr = rf::ingress::serve(node.clone(), durable.clone(), http).await?;
            tracing::info!("ingress on {addr}");
        }
        if let Some(https) = node.cfg.ingress.https {
            rf::ingress::serve_tls(node.clone(), durable.clone(), https).await?;
            tracing::info!("tls ingress on {https}");
        }
    } else if node.cfg.ingress.http.is_some() || node.cfg.ingress.https.is_some() {
        tracing::warn!("ingress is configured but disabled because public = false");
    }

    rf::cron_driver::spawn(node.clone());
    rf::queue::spawn_dispatcher(node.clone());

    if let Some(dns_cfg) = node.cfg.dns.clone() {
        match std::env::var(&dns_cfg.api_token_env) {
            Ok(token) if !token.is_empty() => {
                let api = rf::dns::DnsApi::cloudflare(token, dns_cfg.zone.clone());
                rf::dns::spawn(node.clone(), api, dns_cfg);
                tracing::info!("dns reconciler armed");
            }
            _ => tracing::warn!(
                "dns configured but {} is empty — dns disabled",
                dns_cfg.api_token_env
            ),
        }
    }

    // Certs issued anywhere in the cluster materialize on every node.
    rf::acme::spawn_materializer(node.clone());
    if let Some(mut acme_cfg) = node.cfg.acme.clone() {
        let zone = acme_cfg
            .zone
            .clone()
            .or_else(|| node.cfg.dns.as_ref().map(|d| d.zone.clone()));
        let token_env = acme_cfg
            .api_token_env
            .clone()
            .or_else(|| node.cfg.dns.as_ref().map(|d| d.api_token_env.clone()))
            .unwrap_or_else(|| "CF_API_TOKEN".into());
        match (
            zone,
            std::env::var(&token_env).ok().filter(|t| !t.is_empty()),
        ) {
            (Some(zone), Some(token)) => {
                acme_cfg.zone = Some(zone.clone());
                let dns_api = match &acme_cfg.dns_api_base {
                    Some(base) => rf::dns::DnsApi::new(base.clone(), token, zone),
                    None => rf::dns::DnsApi::cloudflare(token, zone),
                };
                rf::acme::spawn_renewer(node.clone(), acme_cfg, dns_api);
                tracing::info!("acme renewer armed");
            }
            _ => {
                tracing::warn!("acme configured but zone or {token_env} missing — renewer disabled")
            }
        }
    }

    rf::anchor::spawn(node.clone(), node.cfg.anchor.clone());

    rf::selfupdate::spawn(node.cfg.update.clone());

    // R2 lifecycle rules, expired multipart sessions and delayed orphan
    // collection are idempotent. Every node may attempt the sweep; D1 quorum
    // serialization and conditional deletes make concurrent reconcilers safe.
    {
        let node = node.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
                match rf::r2::sweep_lifecycle(&node).await {
                    Ok(result)
                        if result.expired_objects > 0
                            || result.expired_uploads > 0
                            || result.collected_blobs > 0 =>
                    {
                        tracing::info!(
                            expired_objects = result.expired_objects,
                            expired_uploads = result.expired_uploads,
                            collected_blobs = result.collected_blobs,
                            retained_blobs = result.retained_blobs,
                            "R2 lifecycle sweep complete"
                        );
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!("R2 lifecycle sweep failed closed: {error:#}"),
                }
            }
        });
    }

    // Periodic GC.
    {
        let node = node.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                node.gc();
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::{describe_approval, parse_ping};
    use rf::management::{ApprovalKind, ConsoleGrant, CONSOLE_GRANT_VERSION};

    #[test]
    fn parses_health_identity() {
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(parse_ping(&format!("rf {id}\n")).unwrap().to_string(), id);
    }

    #[test]
    fn rejects_invalid_health_response() {
        assert!(parse_ping("ok").is_err());
        assert!(parse_ping("rf not-an-id").is_err());
    }

    #[test]
    fn login_approval_is_bound_to_reported_cluster() {
        let now = rf::node::now_ms();
        let grant = ConsoleGrant {
            version: CONSOLE_GRANT_VERSION,
            cluster_id: "cluster-a".into(),
            session_id: [1; 32],
            csrf: [2; 32],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
        };
        let payload = postcard::to_stdvec(&grant).unwrap();
        assert!(describe_approval(ApprovalKind::Login, &payload, "cluster-b", "node-a").is_err());
        assert_eq!(
            describe_approval(ApprovalKind::Login, &payload, "cluster-a", "node-a").unwrap(),
            "通过节点 node-a 登录 RandallFlare 集群 cluster-a"
        );
    }
}
