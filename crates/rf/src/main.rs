//! rf — RandallFlare node daemon + operator CLI in one binary.

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use rf::config::NodeConfig;
use rf::node::Node;
use rf::peers::PeerClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

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
    /// 写入后不可回读的加密 Worker Secret。
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
    /// Worker Cron 执行历史、手动触发与死信重放。
    Cron {
        #[command(subcommand)]
        cmd: CronCmd,
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
    /// 全局签名存储默认值、rclone 分片和物理分布。
    Storage {
        #[command(subcommand)]
        cmd: StorageCmd,
    },
    /// 自定义域名 DNS 所有权声明与验证。
    Hostname {
        #[command(subcommand)]
        cmd: HostnameCmd,
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
    /// 去中心化邮件域、路由、DNS 验证和投递记录。
    Email {
        #[command(subcommand)]
        cmd: EmailCmd,
    },
    /// 签名 Binary Deliver 程序、沙箱策略与存储。
    Binary {
        #[command(subcommand)]
        cmd: BinaryCmd,
    },
    /// 去中心化 Surge / Clash 分流规则与 TLS 出口目录。
    Exit {
        #[command(subcommand)]
        cmd: ExitCmd,
    },
    /// 注册、撤销客户端设备，或运行本地 SOCKS / HTTP 分流代理。
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// 聚合所有存活节点上的 Worker 请求日志。
    Requests {
        worker: String,
        #[arg(long)]
        hostname: Option<String>,
        /// 状态码类别：2、3、4 或 5。
        #[arg(long)]
        status_class: Option<u16>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        json: bool,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
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
enum SecretCmd {
    /// 仅列出 Secret 变量名，绝不返回值或密文。
    List {
        worker: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 从文件安全读取值并加密写入；使用 - 可从标准输入读取。
    Put {
        worker: String,
        binding: String,
        #[arg(long = "from-file")]
        from_file: PathBuf,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 删除一个 Secret 绑定并发布新的签名版本。
    Delete {
        worker: String,
        binding: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum CronCmd {
    /// 列出最近 7 天的执行记录；--dlq 只列死信。
    List {
        worker: String,
        #[arg(long)]
        dlq: bool,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 立即调用一次 scheduled()；默认表达式为 manual。
    Fire {
        worker: String,
        #[arg(long)]
        expression: Option<String>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 重放一条 DLQ 记录；重放本身只执行一次。
    Replay {
        worker: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 永久删除一条 DLQ 记录。
    Delete {
        worker: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
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
    /// Execute 1..100 statements from a JSON array as one replicated
    /// SQLite transaction.
    Batch {
        name: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Import a SQLite SQL script in validated 100-statement atomic batches.
    Import {
        name: String,
        file: PathBuf,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Download a portable online SQLite snapshot from the current leader.
    Export {
        name: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Create an online SQLite snapshot directly in an R2/rclone bucket.
    Backup {
        name: String,
        #[arg(long)]
        bucket: String,
        #[arg(long, default_value = "d1-backups")]
        prefix: String,
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
        /// 新对象使用全局签名 rclone 分片策略。
        #[arg(long, conflicts_with = "rclone_remote")]
        storage_policy: bool,
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
    /// List active multipart uploads and their staged byte totals.
    MultipartList {
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
    /// Inspect all uploaded parts of one multipart session.
    MultipartInspect {
        bucket: String,
        upload_id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// Abort one multipart session and schedule its staged parts for GC.
    MultipartAbort {
        bucket: String,
        upload_id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum BinaryCmd {
    /// 列出所有可用 Binary Deliver 定义。
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 上传或替换二进制，并发布新的签名定义。
    Upload(Box<BinaryUploadArgs>),
    /// 保留当前不可变内容，只更新执行策略。
    Configure(Box<BinaryConfigureArgs>),
    /// 删除（写入墓碑）Binary Deliver 定义。
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum StorageCmd {
    /// 显示签名策略和按实际位置固定的对象分布。
    Show {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 更新默认后端和有序 rclone 分片 remote。
    Configure {
        #[arg(long, value_parser = ["local", "rclone-sharded"])]
        new_bucket_backend: String,
        #[arg(long = "remote")]
        shard_remotes: Vec<String>,
        #[arg(long, default_value = "")]
        shard_prefix: String,
        /// JSON array of signed D1 automatic-backup policies. Omit to preserve.
        #[arg(long)]
        d1_backups_file: Option<PathBuf>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 从所连接节点探测策略中的每个 rclone remote。
    Probe {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum HostnameCmd {
    /// 列出全局域名声明和验证状态。
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 创建 DNS TXT 所有权声明；域名在验证前不会参与路由。
    Claim {
        hostname: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 查询 DNS，并在 TXT 完全匹配后签署验证结果。
    Verify {
        hostname: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 撤销一个域名的所有权；路由和自动证书会立即停用。
    Delete {
        hostname: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum ExitCmd {
    /// 列出签名出口规则和节点自行声明的出口端点。
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 从 ExitRuleSpec JSON 文件创建或更新规则。
    Apply {
        name: String,
        file: PathBuf,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 删除未被任何设备引用的出口规则。
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// 列出设备的脱敏状态；绝不返回令牌摘要或明文。
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 注册设备并显示一次令牌。
    Create {
        name: String,
        #[arg(long)]
        label: String,
        #[arg(long = "rule", required = true)]
        rules: Vec<String>,
        /// 令牌从现在起有效的天数；省略表示永不过期。
        #[arg(long)]
        expires_in_days: Option<u32>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 替换设备标签、规则与生命周期策略。
    Configure {
        name: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long = "rule")]
        rules: Vec<String>,
        #[arg(long)]
        expires_in_days: Option<u32>,
        #[arg(long)]
        clear_expiry: bool,
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        suspended: Option<bool>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 永久撤销设备令牌。
    Revoke {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 删除设备签名定义。
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 从文件读取一次性令牌，运行本机 SOCKS5 / HTTP 代理。
    Proxy {
        #[arg(long)]
        control: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7388")]
        listen: SocketAddr,
    },
}

#[derive(clap::Args)]
struct BinaryUploadArgs {
    name: String,
    file: PathBuf,
    #[arg(long, default_value = "")]
    description: String,
    #[arg(long)]
    rclone_remote: Option<String>,
    #[arg(long, default_value = "")]
    rclone_prefix: String,
    #[arg(long)]
    os_arch: Option<String>,
    #[arg(long, default_value_t = 30_000)]
    default_timeout_ms: u64,
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    max_stdin_bytes: u64,
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    max_output_bytes: u64,
    #[arg(long)]
    allow_network: bool,
    #[arg(long)]
    allow_r2: bool,
    #[arg(long = "required-tag")]
    required_tags: Vec<String>,
    #[arg(long)]
    suspended: bool,
    #[arg(long, env = "RF_NODE")]
    node: String,
    #[arg(long, env = "RF_OPERATOR_KEY")]
    key: Option<PathBuf>,
    #[arg(long, env = "RF_CLUSTER_SECRET")]
    secret: String,
}

#[derive(clap::Args)]
struct BinaryConfigureArgs {
    name: String,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    default_timeout_ms: Option<u64>,
    #[arg(long)]
    max_stdin_bytes: Option<u64>,
    #[arg(long)]
    max_output_bytes: Option<u64>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    allow_network: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    allow_r2: Option<bool>,
    #[arg(long = "required-tag")]
    required_tags: Vec<String>,
    #[arg(long, conflicts_with = "required_tags")]
    clear_required_tags: bool,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    suspended: Option<bool>,
    #[arg(long, env = "RF_NODE")]
    node: String,
    #[arg(long, env = "RF_OPERATOR_KEY")]
    key: Option<PathBuf>,
    #[arg(long, env = "RF_CLUSTER_SECRET")]
    secret: String,
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
    /// Send one JSON, text, bytes or JSON-compatible V8 message.
    Send {
        name: String,
        #[arg(required_unless_present = "file", conflicts_with = "file")]
        body: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, default_value = "json")]
        content_type: String,
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
    /// Run a bounded read-only SQL query against the flattened `events` view.
    Query {
        name: String,
        #[arg(required_unless_present = "file", conflicts_with = "file")]
        sql: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        /// Positional parameter encoded as JSON; repeat for multiple values.
        #[arg(long = "param")]
        params: Vec<String>,
        #[arg(long, default_value_t = 1_000)]
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
        /// Stateless SQL transform (`SELECT ... FROM events`).
        #[arg(long, conflicts_with = "transform_sql_file")]
        transform_sql: Option<String>,
        /// Read the stateless SQL transform from a UTF-8 file.
        #[arg(long, conflicts_with = "transform_sql")]
        transform_sql_file: Option<PathBuf>,
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
        cron: Option<String>,
        #[arg(long)]
        webhook: bool,
        #[arg(long = "hostname")]
        hostnames: Vec<String>,
        #[arg(long, default_value_t = 32)]
        max_concurrent_instances: u16,
        /// Maximum running instances sharing one --concurrency-group; 0 disables.
        #[arg(long, default_value_t = 1)]
        max_concurrent_instances_per_group: u16,
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
    /// Mint a Workflow webhook token. Its plaintext is printed once.
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
    /// Revoke a Workflow webhook token by public id.
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
        #[arg(long)]
        concurrency_group: Option<String>,
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

#[derive(Subcommand)]
enum EmailCmd {
    /// 列出已签名邮件域及最近一次 DNS 验证状态。
    List {
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 创建或更新邮件域；路由文件是 EmailRoute JSON 数组。
    Create(Box<EmailCreateArgs>),
    /// 删除（写入墓碑）邮件域定义。
    Delete {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_OPERATOR_KEY")]
        key: Option<PathBuf>,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 立即查询 TXT、MX、DKIM 和 SPF，并持久化验证结果。
    Verify {
        name: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 列出最近的入站与出站投递。
    Messages {
        name: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 查看一条投递的元数据。
    Message {
        name: String,
        id: String,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 下载原始 RFC 822 邮件。
    Raw {
        name: String,
        id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
    /// 从 RFC 822 文件建立可靠出站投递。
    Send {
        name: String,
        file: PathBuf,
        #[arg(long)]
        from: String,
        #[arg(long = "to", required = true)]
        recipients: Vec<String>,
        #[arg(long, env = "RF_NODE")]
        node: String,
        #[arg(long, env = "RF_CLUSTER_SECRET")]
        secret: String,
    },
}

#[derive(clap::Args)]
struct EmailCreateArgs {
    name: String,
    #[arg(long)]
    domain: String,
    #[arg(long)]
    mx_hostname: String,
    #[arg(long)]
    bucket: String,
    #[arg(long, default_value = "mail")]
    object_prefix: String,
    #[arg(long)]
    routes: Option<PathBuf>,
    #[arg(long, default_value = "")]
    description: String,
    #[arg(long, default_value_t = 26_214_400)]
    max_message_bytes: u64,
    #[arg(long, default_value_t = 1_000)]
    inbound_per_minute: u32,
    #[arg(long, default_value_t = 1_000)]
    outbound_per_minute: u32,
    #[arg(long, default_value_t = 30)]
    retention_days: u16,
    #[arg(long, default_value = "rf")]
    dkim_selector: String,
    #[arg(long, default_value = "")]
    dkim_public_key: String,
    /// 节点本地 DKIM 私钥环境变量名；绝不接收私钥正文。
    #[arg(long, default_value = "")]
    dkim_private_key_env: String,
    #[arg(long)]
    rotate_verification: bool,
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
}

fn secret_bytes(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim()).context("cluster secret must be hex")?;
    b.try_into()
        .map_err(|_| anyhow::anyhow!("cluster secret must be 32 bytes"))
}

fn device_expiry(days: Option<u32>) -> Result<Option<u64>> {
    let Some(days) = days else {
        return Ok(None);
    };
    if !(1..=3_650).contains(&days) {
        anyhow::bail!("设备有效期必须介于 1 天和 3650 天之间");
    }
    let duration = u64::from(days)
        .checked_mul(24 * 60 * 60 * 1_000)
        .context("设备有效期溢出")?;
    Ok(Some(
        rf::node::now_ms()
            .checked_add(duration)
            .context("设备到期时间溢出")?,
    ))
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

async fn verified_worker_head(
    client: &PeerClient,
    node: &str,
    worker: &str,
) -> Result<(
    rf_core::manifest::WorkerManifest,
    [u8; 32],
    rf_core::identity::SignerId,
)> {
    if !rf_core::manifest::valid_name(worker) {
        anyhow::bail!("Worker 名称无效");
    }
    let status = client.status(node).await?;
    let operator: rf_core::identity::SignerId = status
        .get("operator")
        .and_then(serde_json::Value::as_str)
        .context("节点状态中缺少 operator")?
        .parse()
        .map_err(|error| anyhow::anyhow!("节点返回的管理员身份无效：{error}"))?;
    let envelopes = client.worker_log(node, worker).await?;
    let chain = rf_core::manifest::verify_chain(&envelopes, &operator)
        .map_err(|error| anyhow::anyhow!("Worker 透明日志验证失败：{error}"))?;
    let manifest = chain
        .last()
        .filter(|manifest| !manifest.deleted)
        .cloned()
        .with_context(|| format!("Worker {worker} 不存在或已删除"))?;
    let digest = envelopes
        .last()
        .map(rf_core::envelope::Envelope::digest)
        .context("Worker 透明日志为空")?;
    Ok((manifest, digest, operator))
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
        Cmd::Secret { cmd } => match cmd {
            SecretCmd::List {
                worker,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let (manifest, _, _) = verified_worker_head(&client, &node, &worker).await?;
                for binding in rf::worker_secret::encrypted_secrets_checked(&manifest)?.keys() {
                    println!("{binding}");
                }
                Ok(())
            }
            SecretCmd::Put {
                worker,
                binding,
                from_file,
                node,
                key,
                secret,
            } => {
                let cluster_secret = secret_bytes(&secret)?;
                let client = PeerClient::new(cluster_secret);
                let operator = operator_key(key)?;
                let (manifest, digest, configured_operator) =
                    verified_worker_head(&client, &node, &worker).await?;
                if operator.signer_id() != configured_operator {
                    anyhow::bail!("管理员密钥与节点配置的管理员身份不匹配");
                }
                let bytes = if from_file.as_os_str() == "-" {
                    use std::io::Read as _;
                    let mut bytes = Vec::new();
                    std::io::stdin().read_to_end(&mut bytes)?;
                    bytes
                } else {
                    std::fs::read(&from_file)
                        .with_context(|| format!("无法读取 Secret 文件 {}", from_file.display()))?
                };
                let mut value = String::from_utf8(bytes).context("Secret 文件必须是 UTF-8 文本")?;
                let updated_result = rf::worker_secret::put_manifest_secret(
                    manifest,
                    digest,
                    &cluster_secret,
                    &binding,
                    &value,
                );
                value.zeroize();
                let updated = updated_result?;
                let version = updated.version;
                let envelope = rf_core::envelope::Envelope::seal_any(&updated, &operator);
                client.post_manifest(&node, &envelope).await?;
                println!("已加密写入 {worker} 的 Secret {binding}，发布 v{version}");
                Ok(())
            }
            SecretCmd::Delete {
                worker,
                binding,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let operator = operator_key(key)?;
                let (manifest, digest, configured_operator) =
                    verified_worker_head(&client, &node, &worker).await?;
                if operator.signer_id() != configured_operator {
                    anyhow::bail!("管理员密钥与节点配置的管理员身份不匹配");
                }
                let updated =
                    rf::worker_secret::delete_manifest_secret(manifest, digest, &binding)?;
                let version = updated.version;
                let envelope = rf_core::envelope::Envelope::seal_any(&updated, &operator);
                client.post_manifest(&node, &envelope).await?;
                println!("已删除 {worker} 的 Secret {binding}，发布 v{version}");
                Ok(())
            }
        },
        Cmd::Cron { cmd } => match cmd {
            CronCmd::List {
                worker,
                dlq,
                limit,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let runs = client.cron_runs(&node, &worker, dlq, limit).await?;
                println!("{}", serde_json::to_string_pretty(&runs)?);
                Ok(())
            }
            CronCmd::Fire {
                worker,
                expression,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let run = client
                    .cron_fire(&node, &worker, expression.as_deref())
                    .await?;
                println!("{}", serde_json::to_string_pretty(&run)?);
                Ok(())
            }
            CronCmd::Replay {
                worker,
                id,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let run = client
                    .cron_replay(&node, &worker, &id)
                    .await?
                    .with_context(|| format!("Cron DLQ 记录 {id} 不存在"))?;
                println!("{}", serde_json::to_string_pretty(&run)?);
                Ok(())
            }
            CronCmd::Delete {
                worker,
                id,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                if !client.cron_delete_dlq(&node, &worker, &id).await? {
                    anyhow::bail!("Cron DLQ 记录 {id} 不存在");
                }
                println!("Cron DLQ 记录 {id} 已删除");
                Ok(())
            }
        },
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
            D1Cmd::Batch {
                name,
                file,
                node,
                secret,
            } => {
                let raw = std::fs::read(&file)
                    .with_context(|| format!("reading D1 batch {}", file.display()))?;
                if raw.is_empty() || raw.len() > 64 * 1024 * 1024 {
                    anyhow::bail!("D1 batch JSON must be 1 byte..64 MiB");
                }
                let value: serde_json::Value = serde_json::from_slice(&raw)?;
                let statements: Vec<rf::d1::Statement> =
                    serde_json::from_value(value.get("statements").cloned().unwrap_or(value))?;
                if statements.is_empty() || statements.len() > 100 {
                    anyhow::bail!("D1 batch must contain 1..100 statements");
                }
                let client = PeerClient::new(secret_bytes(&secret)?);
                let output = client.d1_batch(&node, &name, &statements).await?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                Ok(())
            }
            D1Cmd::Import {
                name,
                file,
                node,
                secret,
            } => {
                let raw = std::fs::read_to_string(&file)
                    .with_context(|| format!("reading D1 SQL import {}", file.display()))?;
                if raw.is_empty() || raw.len() > 64 * 1024 * 1024 {
                    anyhow::bail!("D1 SQL import must be 1 byte..64 MiB");
                }
                let statements = rf::d1bind::import_statements(&raw)?;
                if statements.is_empty() || statements.len() > 10_000 {
                    anyhow::bail!("D1 SQL import must contain 1..10,000 statements");
                }
                if statements
                    .iter()
                    .any(|statement| statement.sql.len() > 1024 * 1024)
                {
                    anyhow::bail!("one D1 import statement exceeds 1 MiB");
                }
                let client = PeerClient::new(secret_bytes(&secret)?);
                let mut changes = 0u64;
                for chunk in statements.chunks(100) {
                    let output = client.d1_batch(&node, &name, chunk).await?;
                    changes = changes.saturating_add(output["rows_affected"].as_u64().unwrap_or(0));
                }
                println!(
                    "imported {} statements in {} atomic batches ({} changes)",
                    statements.len(),
                    statements.len().div_ceil(100),
                    changes
                );
                Ok(())
            }
            D1Cmd::Export {
                name,
                output,
                force,
                node,
                secret,
            } => {
                if output.exists() && !force {
                    anyhow::bail!(
                        "refusing to overwrite {}; pass --force to replace it",
                        output.display()
                    );
                }
                let client = PeerClient::new(secret_bytes(&secret)?);
                let bytes = client.d1_export(&node, &name).await?;
                if !bytes.starts_with(b"SQLite format 3\0") {
                    anyhow::bail!("node returned an invalid SQLite 3 snapshot");
                }
                std::fs::write(&output, &bytes)
                    .with_context(|| format!("writing D1 snapshot {}", output.display()))?;
                println!(
                    "exported {name} to {} ({} bytes)",
                    output.display(),
                    bytes.len()
                );
                Ok(())
            }
            D1Cmd::Backup {
                name,
                bucket,
                prefix,
                node,
                secret,
            } => {
                let backup = PeerClient::new(secret_bytes(&secret)?)
                    .d1_backup(&node, &name, &bucket, &prefix)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&backup)?);
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
                storage_policy,
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
                if storage_policy && !rclone_prefix.is_empty() {
                    anyhow::bail!("--storage-policy 不能与 --rclone-prefix 同时使用");
                }
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
                    storage_policy: storage_policy
                        .then(|| rf::storage_policy::DEFAULT_POLICY_NAME.to_string()),
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
            R2Cmd::MultipartList {
                bucket,
                prefix,
                cursor,
                limit,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let uploads = client
                    .r2_multipart_list(&node, &bucket, &prefix, cursor.as_deref(), limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&uploads)?);
                Ok(())
            }
            R2Cmd::MultipartInspect {
                bucket,
                upload_id,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let upload = client
                    .r2_multipart_detail(&node, &bucket, &upload_id)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&upload)?);
                Ok(())
            }
            R2Cmd::MultipartAbort {
                bucket,
                upload_id,
                node,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                client
                    .r2_multipart_abort(&node, &bucket, &upload_id)
                    .await?;
                println!("R2 分片上传 {upload_id} 已终止，暂存分片已进入安全回收队列");
                Ok(())
            }
        },
        Cmd::Storage { cmd } => match cmd {
            StorageCmd::Show { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&client.storage_status(&node).await?)?
                );
                Ok(())
            }
            StorageCmd::Configure {
                new_bucket_backend,
                shard_remotes,
                shard_prefix,
                d1_backups_file,
                node,
                key,
                secret,
            } => {
                let backend = match new_bucket_backend.as_str() {
                    "local" => rf::storage_policy::NewBucketBackend::Local,
                    "rclone-sharded" => rf::storage_policy::NewBucketBackend::RcloneSharded,
                    _ => unreachable!("clap validates storage backend"),
                };
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(
                        &node,
                        rf::storage_policy::STORAGE_POLICY_KIND,
                        rf::storage_policy::DEFAULT_POLICY_NAME,
                    )
                    .await?;
                let existing_backups = head
                    .as_ref()
                    .filter(|view| !view.resource.deleted)
                    .map(|view| rf::storage_policy::policy_spec(&view.resource))
                    .transpose()?
                    .map(|policy| policy.d1_backups)
                    .unwrap_or_default();
                let d1_backups = match d1_backups_file {
                    Some(path) => {
                        serde_json::from_slice::<Vec<rf::storage_policy::D1BackupPolicy>>(
                            &std::fs::read(&path).with_context(|| {
                                format!("读取 D1 自动备份策略 {}", path.display())
                            })?,
                        )
                        .context("D1 自动备份策略文件必须是 JSON 数组")?
                    }
                    None => existing_backups,
                };
                let record = rf::storage_policy::prepare_after(
                    rf::storage_policy::StoragePolicy {
                        schema: rf::storage_policy::STORAGE_POLICY_SCHEMA,
                        new_bucket_backend: backend,
                        shard_remotes,
                        shard_prefix,
                        d1_backups,
                    },
                    head.as_ref(),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!("存储策略已更新至 v{}", record.version);
                Ok(())
            }
            StorageCmd::Probe { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&client.storage_probe(&node).await?)?
                );
                Ok(())
            }
        },
        Cmd::Hostname { cmd } => match cmd {
            HostnameCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let claims = client
                    .resource_heads(&node, Some(rf::hostname::HOSTNAME_CLAIM_KIND))
                    .await?
                    .into_iter()
                    .filter(|view| !view.resource.deleted)
                    .map(|view| {
                        let spec = rf::hostname::claim_spec(&view.resource)?;
                        Ok(serde_json::json!({
                            "name": view.resource.name,
                            "version": view.resource.version,
                            "digest": view.digest,
                            "hostname": spec.hostname,
                            "verified": spec.verified_at_ms.is_some(),
                            "verified_at_ms": spec.verified_at_ms,
                            "txt_name": spec.txt_name(),
                            "txt_value": spec.txt_value(),
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                println!("{}", serde_json::to_string_pretty(&claims)?);
                Ok(())
            }
            HostnameCmd::Claim {
                hostname,
                node,
                key,
                secret,
            } => {
                let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(
                        &node,
                        rf::hostname::HOSTNAME_CLAIM_KIND,
                        &rf::hostname::claim_name(&hostname),
                    )
                    .await?;
                if let Some(view) = head.as_ref().filter(|view| !view.resource.deleted) {
                    let spec = rf::hostname::claim_spec(&view.resource)?;
                    println!(
                        "域名 {} 已存在所有权声明（v{}）",
                        hostname, view.resource.version
                    );
                    println!("请配置 TXT  {}", spec.txt_name());
                    println!("TXT 值      {}", spec.txt_value());
                    return Ok(());
                }
                let record =
                    rf::hostname::prepare_claim_after(&hostname, None, None, false, head.as_ref())?;
                let spec = rf::hostname::claim_spec(&record)?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!(
                    "域名 {} 的所有权声明已创建（v{}）",
                    hostname, record.version
                );
                println!("请配置 TXT  {}", spec.txt_name());
                println!("TXT 值      {}", spec.txt_value());
                println!("配置生效后运行：rf hostname verify {hostname}");
                Ok(())
            }
            HostnameCmd::Verify {
                hostname,
                node,
                key,
                secret,
            } => {
                let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(
                        &node,
                        rf::hostname::HOSTNAME_CLAIM_KIND,
                        &rf::hostname::claim_name(&hostname),
                    )
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("域名 {hostname} 尚未创建所有权声明"))?;
                let spec = rf::hostname::claim_spec(&head.resource)?;
                let verification = client.hostname_verification(&node, &hostname).await?;
                if !verification.verified {
                    anyhow::bail!(
                        "DNS TXT 尚未匹配；请在 {} 配置 {}（当前观测：{}）",
                        verification.txt_name,
                        verification.txt_value,
                        verification.observed.join(", ")
                    );
                }
                if spec.verified_at_ms.is_some() {
                    println!("域名 {hostname} 已通过验证，无需重复签署");
                    return Ok(());
                }
                let record = rf::hostname::prepare_claim_after(
                    &hostname,
                    Some(spec),
                    Some(verification.checked_at_ms),
                    false,
                    Some(&head),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!(
                    "域名 {hostname} 已通过 DNS 验证并启用（v{}）",
                    record.version
                );
                Ok(())
            }
            HostnameCmd::Delete {
                hostname,
                node,
                key,
                secret,
            } => {
                let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(
                        &node,
                        rf::hostname::HOSTNAME_CLAIM_KIND,
                        &rf::hostname::claim_name(&hostname),
                    )
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("域名 {hostname} 的所有权声明不存在"))?;
                let spec = rf::hostname::claim_spec(&head.resource)?;
                let record = rf::hostname::prepare_claim_after(
                    &hostname,
                    Some(spec),
                    None,
                    true,
                    Some(&head),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!("域名 {hostname} 的所有权已撤销（v{}）", record.version);
                Ok(())
            }
        },
        Cmd::Binary { cmd } => match cmd {
            BinaryCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let binaries = client
                    .resource_heads(&node, Some(rf::binary::BINARY_KIND))
                    .await?
                    .into_iter()
                    .filter(|view| !view.resource.deleted)
                    .map(|view| {
                        let spec = rf::binary::binary_spec(&view.resource)?;
                        Ok(serde_json::json!({
                            "name": view.resource.name,
                            "version": view.resource.version,
                            "digest": view.digest,
                            "spec": spec,
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                println!("{}", serde_json::to_string_pretty(&binaries)?);
                Ok(())
            }
            BinaryCmd::Upload(arguments) => {
                let BinaryUploadArgs {
                    name,
                    file,
                    description,
                    rclone_remote,
                    rclone_prefix,
                    os_arch,
                    default_timeout_ms,
                    max_stdin_bytes,
                    max_output_bytes,
                    allow_network,
                    allow_r2,
                    required_tags,
                    suspended,
                    node,
                    key,
                    secret,
                } = *arguments;
                let storage = match rclone_remote {
                    Some(remote) => rf::objectstore::StorageLocation::Rclone {
                        remote,
                        prefix: rclone_prefix,
                    },
                    None if rclone_prefix.is_empty() => rf::objectstore::StorageLocation::Local,
                    None => anyhow::bail!("--rclone-prefix 必须与 --rclone-remote 一起使用"),
                };
                let bytes = std::fs::read(&file)
                    .with_context(|| format!("读取 Binary 文件 {}", file.display()))?;
                if bytes.is_empty() || bytes.len() > rf::binary::MAX_BINARY_BYTES {
                    anyhow::bail!("Binary 文件必须介于 1 字节和 200 MiB 之间");
                }
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::binary::BINARY_KIND, &name)
                    .await?;
                let (sha256, size_bytes, storage) =
                    client.binary_put_blob(&node, &bytes, &storage).await?;
                let spec = rf::binary::BinarySpec {
                    schema: rf::binary::BINARY_SCHEMA,
                    description,
                    sha256,
                    size_bytes,
                    storage,
                    os_arch: os_arch.unwrap_or_else(|| rf::binary::current_os_arch().into()),
                    default_timeout_ms,
                    max_stdin_bytes,
                    max_output_bytes,
                    allow_network,
                    allow_r2,
                    required_tags,
                    suspended,
                };
                let record = rf::binary::prepare_after(&name, spec, false, head.as_ref())?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!(
                    "Binary {} 已发布 v{}（{} 字节，SHA-256 {}）",
                    record.name,
                    record.version,
                    size_bytes,
                    record
                        .spec()?
                        .get("sha256")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                );
                Ok(())
            }
            BinaryCmd::Configure(arguments) => {
                let BinaryConfigureArgs {
                    name,
                    description,
                    default_timeout_ms,
                    max_stdin_bytes,
                    max_output_bytes,
                    allow_network,
                    allow_r2,
                    required_tags,
                    clear_required_tags,
                    suspended,
                    node,
                    key,
                    secret,
                } = *arguments;
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::binary::BINARY_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Binary {name} 不存在"))?;
                let mut spec = rf::binary::binary_spec(&head.resource)?;
                if let Some(description) = description {
                    spec.description = description;
                }
                if let Some(default_timeout_ms) = default_timeout_ms {
                    spec.default_timeout_ms = default_timeout_ms;
                }
                if let Some(max_stdin_bytes) = max_stdin_bytes {
                    spec.max_stdin_bytes = max_stdin_bytes;
                }
                if let Some(max_output_bytes) = max_output_bytes {
                    spec.max_output_bytes = max_output_bytes;
                }
                if let Some(allow_network) = allow_network {
                    spec.allow_network = allow_network;
                }
                if let Some(allow_r2) = allow_r2 {
                    spec.allow_r2 = allow_r2;
                }
                if clear_required_tags {
                    spec.required_tags.clear();
                } else if !required_tags.is_empty() {
                    spec.required_tags = required_tags;
                }
                if let Some(suspended) = suspended {
                    spec.suspended = suspended;
                }
                let record = rf::binary::prepare_after(&name, spec, false, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!(
                    "Binary {} 执行策略已更新至 v{}",
                    record.name, record.version
                );
                Ok(())
            }
            BinaryCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::binary::BINARY_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("Binary {name} 不存在"))?;
                let spec = rf::binary::binary_spec(&head.resource)?;
                let record = rf::binary::prepare_after(&name, spec, true, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Binary {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
        },
        Cmd::Exit { cmd } => match cmd {
            ExitCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let rules = client
                    .resource_heads(&node, Some(rf::exit::EXIT_RULE_KIND))
                    .await?
                    .into_iter()
                    .filter(|view| !view.resource.deleted)
                    .map(|view| {
                        let spec = rf::exit::exit_rule_spec(&view.resource)?;
                        Ok(serde_json::json!({
                            "name": view.resource.name,
                            "version": view.resource.version,
                            "digest": view.digest,
                            "spec": spec,
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let status = client.status(&node).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "rules": rules,
                        "exit_node": status.get("exit_node"),
                        "peers": status.get("peers"),
                    }))?
                );
                Ok(())
            }
            ExitCmd::Apply {
                name,
                file,
                node,
                key,
                secret,
            } => {
                let bytes = std::fs::read(&file)
                    .with_context(|| format!("读取出口规则文件 {}", file.display()))?;
                let spec: rf::exit::ExitRuleSpec =
                    serde_json::from_slice(&bytes).context("出口规则文件不是有效 JSON")?;
                spec.validate()?;
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::exit::EXIT_RULE_KIND, &name)
                    .await?;
                let record = rf::resource::prepare_after(
                    rf::exit::EXIT_RULE_KIND,
                    &name,
                    serde_json::to_value(spec)?,
                    false,
                    head.as_ref(),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!("出口规则 {} 已发布至 v{}", record.name, record.version);
                Ok(())
            }
            ExitCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::exit::EXIT_RULE_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("出口规则 {name} 不存在"))?;
                let spec = rf::exit::exit_rule_spec(&head.resource)?;
                let record = rf::resource::prepare_after(
                    rf::exit::EXIT_RULE_KIND,
                    &name,
                    serde_json::to_value(spec)?,
                    true,
                    Some(&head),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!("出口规则 {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
        },
        Cmd::Device { cmd } => match cmd {
            DeviceCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let now = rf::node::now_ms();
                let known_rules = client
                    .resource_heads(&node, Some(rf::exit::EXIT_RULE_KIND))
                    .await?
                    .into_iter()
                    .filter(|view| {
                        !view.resource.deleted && rf::exit::exit_rule_spec(&view.resource).is_ok()
                    })
                    .map(|view| view.resource.name)
                    .collect::<std::collections::BTreeSet<_>>();
                let devices = client
                    .resource_heads(&node, Some(rf::exit::DEVICE_KIND))
                    .await?
                    .into_iter()
                    .filter(|view| !view.resource.deleted)
                    .map(|view| {
                        let spec = rf::exit::device_spec(&view.resource)?;
                        let rules_ready = spec
                            .allowed_rules
                            .iter()
                            .all(|rule| known_rules.contains(rule));
                        Ok(serde_json::json!({
                            "name": view.resource.name,
                            "version": view.resource.version,
                            "digest": view.digest,
                            "label": spec.label,
                            "token_prefix": spec.token_prefix,
                            "allowed_rules": spec.allowed_rules,
                            "created_at_ms": spec.created_at_ms,
                            "expires_at_ms": spec.expires_at_ms,
                            "revoked_at_ms": spec.revoked_at_ms,
                            "suspended": spec.suspended,
                            "rules_ready": rules_ready,
                            "active": spec.active(now) && rules_ready,
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                println!("{}", serde_json::to_string_pretty(&devices)?);
                Ok(())
            }
            DeviceCmd::Create {
                name,
                label,
                rules,
                expires_in_days,
                node,
                key,
                secret,
            } => {
                let expires_at_ms = device_expiry(expires_in_days)?;
                let client = PeerClient::new(secret_bytes(&secret)?);
                if client
                    .resource_head(&node, rf::exit::DEVICE_KIND, &name)
                    .await?
                    .is_some()
                {
                    anyhow::bail!("设备 {name} 已存在；删除后的名称也不能复用");
                }
                let (record, token) =
                    rf::exit::mint_device_record(&name, label, rules, expires_at_ms)?;
                let token = Zeroizing::new(token);
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                let published = client.post_resource(&node, &envelope).await;
                if published.is_ok() {
                    println!("设备 {} 已注册至 v{}", record.name, record.version);
                    println!("一次性设备令牌（请立即保存，无法找回）：");
                    println!("{}", token.as_str());
                }
                published?;
                Ok(())
            }
            DeviceCmd::Configure {
                name,
                label,
                rules,
                expires_in_days,
                clear_expiry,
                suspended,
                node,
                key,
                secret,
            } => {
                if clear_expiry && expires_in_days.is_some() {
                    anyhow::bail!("--clear-expiry 不能与 --expires-in-days 同时使用");
                }
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::exit::DEVICE_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("设备 {name} 不存在"))?;
                let mut spec = rf::exit::device_spec(&head.resource)?;
                if spec.revoked_at_ms.is_some() {
                    anyhow::bail!("设备 {name} 已撤销，不能重新启用");
                }
                if let Some(label) = label {
                    spec.label = label;
                }
                if !rules.is_empty() {
                    spec.allowed_rules = rules;
                }
                if clear_expiry {
                    spec.expires_at_ms = None;
                } else if expires_in_days.is_some() {
                    spec.expires_at_ms = device_expiry(expires_in_days)?;
                }
                if let Some(suspended) = suspended {
                    spec.suspended = suspended;
                }
                spec.validate()?;
                let record = rf::resource::prepare_after(
                    rf::exit::DEVICE_KIND,
                    &name,
                    serde_json::to_value(spec)?,
                    false,
                    Some(&head),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!("设备 {} 已更新至 v{}", record.name, record.version);
                Ok(())
            }
            DeviceCmd::Revoke {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::exit::DEVICE_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("设备 {name} 不存在"))?;
                let mut spec = rf::exit::device_spec(&head.resource)?;
                if spec.revoked_at_ms.is_some() {
                    anyhow::bail!("设备 {name} 已撤销");
                }
                spec.revoked_at_ms = Some(rf::node::now_ms());
                spec.suspended = true;
                let record = rf::resource::prepare_after(
                    rf::exit::DEVICE_KIND,
                    &name,
                    serde_json::to_value(spec)?,
                    false,
                    Some(&head),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!("设备 {} 的令牌已永久撤销", record.name);
                Ok(())
            }
            DeviceCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::exit::DEVICE_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("设备 {name} 不存在"))?;
                let spec = rf::exit::device_spec(&head.resource)?;
                let record = rf::resource::prepare_after(
                    rf::exit::DEVICE_KIND,
                    &name,
                    serde_json::to_value(spec)?,
                    true,
                    Some(&head),
                )?;
                client
                    .post_resource(
                        &node,
                        &rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?),
                    )
                    .await?;
                println!("设备 {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
            DeviceCmd::Proxy {
                control,
                name,
                token_file,
                listen,
            } => {
                let metadata = std::fs::metadata(&token_file)
                    .with_context(|| format!("读取设备令牌文件 {}", token_file.display()))?;
                if !metadata.is_file() || metadata.len() > 512 {
                    anyhow::bail!("设备令牌文件必须是普通小文件");
                }
                let mut token = std::fs::read_to_string(&token_file)
                    .with_context(|| format!("读取设备令牌文件 {}", token_file.display()))?;
                token = token.trim().to_string();
                if !token.starts_with(rf::exit::DEVICE_TOKEN_PREFIX)
                    || token.len() != rf::exit::DEVICE_TOKEN_PREFIX.len() + 43
                {
                    token.zeroize();
                    anyhow::bail!("设备令牌格式无效");
                }
                let _ = tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "info".into()),
                    )
                    .try_init();
                println!("设备代理监听 {listen}；SOCKS5 与 HTTP 代理共用此端口");
                rf::exitproxy::run_device_proxy(control, name, token, listen).await
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
                file,
                content_type,
                delay_seconds,
                node,
                secret,
            } => {
                let raw = match file {
                    Some(path) => std::fs::read(&path)
                        .with_context(|| format!("读取队列消息文件 {}", path.display()))?,
                    None => body.unwrap_or_default().into_bytes(),
                };
                let (body, body_base64) = match content_type.as_str() {
                    "json" | "v8" => (
                        serde_json::from_slice(&raw).context("队列 JSON/V8 消息体必须是 JSON")?,
                        None,
                    ),
                    "text" => (
                        serde_json::Value::String(
                            String::from_utf8(raw).context("队列 text 消息文件必须是 UTF-8")?,
                        ),
                        None,
                    ),
                    "bytes" => (
                        serde_json::Value::Null,
                        Some(base64::engine::general_purpose::STANDARD.encode(raw)),
                    ),
                    _ => anyhow::bail!("--content-type 必须是 json、text、bytes 或 v8"),
                };
                let client = PeerClient::new(secret_bytes(&secret)?);
                let ids = client
                    .queue_send(
                        &node,
                        &name,
                        &[rf::queue::SendMessage {
                            body,
                            content_type,
                            body_base64,
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
            AnalyticsCmd::Query {
                name,
                sql,
                file,
                params,
                limit,
                node,
                secret,
            } => {
                let sql = match file {
                    Some(path) => std::fs::read_to_string(&path)
                        .with_context(|| format!("读取 Analytics SQL 文件 {}", path.display()))?,
                    None => sql.unwrap_or_default(),
                };
                let params = params
                    .into_iter()
                    .map(|value| {
                        serde_json::from_str(&value)
                            .with_context(|| format!("Analytics 参数不是有效 JSON：{value}"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let result = PeerClient::new(secret_bytes(&secret)?)
                    .analytics_query(&node, &name, &sql, params, limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
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
                transform_sql,
                transform_sql_file,
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
                let transform_sql =
                    match transform_sql_file {
                        Some(path) => Some(std::fs::read_to_string(&path).with_context(|| {
                            format!("读取 Pipeline SQL 文件 {}", path.display())
                        })?),
                        None => transform_sql,
                    };
                let spec = rf::pipeline::PipelineSpec {
                    description,
                    output_bucket: bucket,
                    output_key_template: key_template,
                    batch_max_bytes,
                    batch_max_seconds,
                    schema,
                    transform_sql,
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
                cron,
                webhook,
                hostnames,
                max_concurrent_instances,
                max_concurrent_instances_per_group,
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
                let tokens = head
                    .as_ref()
                    .and_then(|head| rf::workflow::workflow_spec(&head.resource).ok())
                    .map(|spec| spec.tokens)
                    .unwrap_or_default();
                let spec = rf::workflow::WorkflowSpec {
                    description,
                    worker,
                    entrypoint,
                    suspended,
                    suspend_reason,
                    retention_days,
                    instance_retries,
                    instance_timeout_seconds,
                    cron,
                    webhook_enabled: webhook,
                    hostnames,
                    tokens,
                    max_concurrent_instances,
                    max_concurrent_instances_per_group,
                };
                let record =
                    rf::workflow::prepare_workflow_after(&name, spec, false, head.as_ref())?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Workflow {} 已更新至 v{}", record.name, record.version);
                Ok(())
            }
            WorkflowCmd::TokenCreate {
                name,
                label,
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
                let mut spec = rf::workflow::workflow_spec(&head.resource)?;
                let (token, plaintext) = rf::workflow::mint_token(label)?;
                let id = token.id.clone();
                spec.tokens.push(token);
                let record = rf::workflow::prepare_workflow_after(&name, spec, false, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("token_id={id}\ntoken={plaintext}");
                Ok(())
            }
            WorkflowCmd::TokenRevoke {
                name,
                id,
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
                let mut spec = rf::workflow::workflow_spec(&head.resource)?;
                let before = spec.tokens.len();
                spec.tokens.retain(|token| token.id != id);
                if before == spec.tokens.len() {
                    anyhow::bail!("Workflow Webhook 令牌不存在：{id}");
                }
                if spec.webhook_enabled && spec.tokens.is_empty() {
                    spec.webhook_enabled = false;
                }
                let record = rf::workflow::prepare_workflow_after(&name, spec, false, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("Workflow {name} Webhook 令牌 {id} 已撤销");
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
                concurrency_group,
                node,
                secret,
            } => {
                let input = serde_json::from_str(&input).context("Workflow 输入必须是有效 JSON")?;
                let instance = PeerClient::new(secret_bytes(&secret)?)
                    .workflow_create(
                        &node,
                        &name,
                        idempotency_key.as_deref(),
                        concurrency_group.as_deref(),
                        input,
                    )
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
        Cmd::Email { cmd } => match cmd {
            EmailCmd::List { node, secret } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let records = client
                    .resource_heads(&node, Some(rf::email::EMAIL_DOMAIN_KIND))
                    .await?;
                let mut domains = Vec::new();
                for view in records.into_iter().filter(|view| !view.resource.deleted) {
                    let spec = rf::email::email_domain_spec(&view.resource)?;
                    let verification = client
                        .email_verification(&node, &view.resource.name)
                        .await
                        .ok()
                        .flatten();
                    domains.push(serde_json::json!({
                        "name": view.resource.name,
                        "version": view.resource.version,
                        "digest": view.digest,
                        "spec": spec,
                        "verification": verification,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&domains)?);
                Ok(())
            }
            EmailCmd::Create(args) => {
                let EmailCreateArgs {
                    name,
                    domain,
                    mx_hostname,
                    bucket,
                    object_prefix,
                    routes,
                    description,
                    max_message_bytes,
                    inbound_per_minute,
                    outbound_per_minute,
                    retention_days,
                    dkim_selector,
                    dkim_public_key,
                    dkim_private_key_env,
                    rotate_verification,
                    suspended,
                    suspend_reason,
                    node,
                    key,
                    secret,
                } = *args;
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::email::EMAIL_DOMAIN_KIND, &name)
                    .await?;
                let previous = head
                    .as_ref()
                    .and_then(|head| rf::email::email_domain_spec(&head.resource).ok());
                let routes = match routes {
                    Some(path) => serde_json::from_str(
                        &std::fs::read_to_string(&path)
                            .with_context(|| format!("无法读取邮件路由文件 {}", path.display()))?,
                    )
                    .context("邮件路由文件必须是 EmailRoute JSON 数组")?,
                    None => previous
                        .as_ref()
                        .map(|spec| spec.routes.clone())
                        .unwrap_or_default(),
                };
                let verification_challenge = if rotate_verification {
                    rf::email::generate_verification_challenge()
                } else {
                    previous
                        .as_ref()
                        .map(|spec| spec.verification_challenge.clone())
                        .unwrap_or_else(rf::email::generate_verification_challenge)
                };
                let spec = rf::email::EmailDomainSpec {
                    description,
                    domain,
                    verification_challenge,
                    mx_hostname,
                    bucket,
                    object_prefix,
                    routes,
                    max_message_bytes,
                    inbound_per_minute,
                    outbound_per_minute,
                    retention_days,
                    dkim_selector,
                    dkim_public_key,
                    dkim_private_key_env,
                    suspended,
                    suspend_reason,
                };
                let record = rf::email::prepare_email_domain_after(
                    &name,
                    spec.clone(),
                    false,
                    head.as_ref(),
                )?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("邮件域 {} 已更新至 v{}", record.name, record.version);
                println!("请配置 TXT  {}", spec.ownership_txt_name());
                println!("TXT 值      {}", spec.ownership_txt_value());
                println!("请配置 MX   {} -> {}", spec.domain, spec.mx_hostname);
                if !spec.dkim_public_key.is_empty() {
                    println!("请配置 TXT  {}", spec.dkim_txt_name());
                    println!("DKIM 值     {}", spec.dkim_public_key);
                }
                Ok(())
            }
            EmailCmd::Delete {
                name,
                node,
                key,
                secret,
            } => {
                let client = PeerClient::new(secret_bytes(&secret)?);
                let head = client
                    .resource_head(&node, rf::email::EMAIL_DOMAIN_KIND, &name)
                    .await?
                    .filter(|view| !view.resource.deleted)
                    .with_context(|| format!("邮件域 {name} 不存在"))?;
                let spec = rf::email::email_domain_spec(&head.resource)?;
                let record = rf::email::prepare_email_domain_after(&name, spec, true, Some(&head))?;
                let envelope = rf_core::envelope::Envelope::seal_any(&record, &operator_key(key)?);
                client.post_resource(&node, &envelope).await?;
                println!("邮件域 {} 已删除（v{}）", record.name, record.version);
                Ok(())
            }
            EmailCmd::Verify { name, node, secret } => {
                let verification = PeerClient::new(secret_bytes(&secret)?)
                    .email_verify(&node, &name)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&verification)?);
                Ok(())
            }
            EmailCmd::Messages {
                name,
                limit,
                node,
                secret,
            } => {
                let messages = PeerClient::new(secret_bytes(&secret)?)
                    .email_messages(&node, &name, limit)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&messages)?);
                Ok(())
            }
            EmailCmd::Message {
                name,
                id,
                node,
                secret,
            } => {
                let message = PeerClient::new(secret_bytes(&secret)?)
                    .email_message(&node, &name, &id)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&message)?);
                Ok(())
            }
            EmailCmd::Raw {
                name,
                id,
                output,
                node,
                secret,
            } => {
                let raw = PeerClient::new(secret_bytes(&secret)?)
                    .email_message_raw(&node, &name, &id)
                    .await?;
                std::fs::write(&output, raw)
                    .with_context(|| format!("无法写入 {}", output.display()))?;
                println!("邮件原文已写入 {}", output.display());
                Ok(())
            }
            EmailCmd::Send {
                name,
                file,
                from,
                recipients,
                node,
                secret,
            } => {
                let raw = std::fs::read(&file)
                    .with_context(|| format!("无法读取 RFC 822 文件 {}", file.display()))?;
                let metadata = rf::email::EmailSendMetadata {
                    mail_from: from,
                    recipients,
                };
                let queued = PeerClient::new(secret_bytes(&secret)?)
                    .email_send(&node, &name, &metadata, &raw)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&queued)?);
                Ok(())
            }
        },
        Cmd::Requests {
            worker,
            hostname,
            status_class,
            limit,
            json,
            node,
            secret,
        } => {
            if !rf_core::manifest::valid_name(&worker) {
                anyhow::bail!("Worker 名称无效");
            }
            if status_class.is_some_and(|class| !(2..=5).contains(&class)) {
                anyhow::bail!("--status-class 必须是 2、3、4 或 5");
            }
            let client = PeerClient::new(secret_bytes(&secret)?);
            let candidates = client.live_api_candidates(&node).await?;
            let results = futures_util::future::join_all(candidates.iter().map(|base| {
                let client = client.clone();
                let base = base.clone();
                let worker = worker.clone();
                let hostname = hostname.clone();
                async move {
                    (
                        base.clone(),
                        client
                            .worker_request_logs(
                                &base,
                                &worker,
                                hostname.as_deref(),
                                status_class,
                                limit,
                            )
                            .await,
                    )
                }
            }))
            .await;
            let mut snapshots = Vec::new();
            let mut unavailable = Vec::new();
            for (base, result) in results {
                match result {
                    Ok(snapshot) => snapshots.push(snapshot),
                    Err(_) => unavailable.push(base),
                }
            }
            if snapshots.is_empty() {
                anyhow::bail!("所有存活节点的请求日志均暂时不可用");
            }
            let merged = rf::observability::merge_snapshots(&snapshots, limit);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "worker": worker,
                        "nodes": snapshots.iter().map(|snapshot| serde_json::json!({
                            "id": snapshot.node,
                            "label": snapshot.label,
                        })).collect::<Vec<_>>(),
                        "unavailable_nodes": unavailable,
                        "hostnames": merged.hostnames,
                        "hours": merged.hours,
                        "entries": merged.entries,
                        "privacy": "不记录查询参数、请求头、请求体、Cookie、IP 或 User-Agent",
                    }))?
                );
                return Ok(());
            }
            let total: u64 = merged
                .hours
                .iter()
                .map(|hour| {
                    hour.status_2xx
                        + hour.status_3xx
                        + hour.status_4xx
                        + hour.status_5xx
                        + hour.other
                })
                .sum();
            println!(
                "{worker}：{} 个节点可用，{} 个节点暂不可用，24 小时 {total} 次请求",
                snapshots.len(),
                unavailable.len()
            );
            let labels: std::collections::BTreeMap<&str, &str> = snapshots
                .iter()
                .map(|snapshot| (snapshot.node.as_str(), snapshot.label.as_str()))
                .collect();
            for entry in merged.entries {
                println!(
                    "{}  {:<4} {:<3} {:>6}ms  {:<16}  {}{}  v{}",
                    format_request_time(entry.called_at_ms),
                    entry.status_code,
                    entry.method,
                    entry.duration_ms,
                    labels
                        .get(entry.node.as_str())
                        .copied()
                        .unwrap_or(entry.node.as_str()),
                    entry.hostname,
                    entry.path,
                    entry.version,
                );
            }
            Ok(())
        }
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

fn format_request_time(timestamp_ms: u64) -> String {
    let seconds = (timestamp_ms / 1_000).min(i64::MAX as u64) as i64;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| timestamp_ms.to_string())
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
    if sandbox.is_none() {
        warnings.push("bubblewrap was not found; Binary Deliver execution is unavailable");
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
    let email_tls = if cfg.email.enabled {
        let mx = cfg.email.mx_hostname.as_deref().unwrap_or_default();
        let cert = cfg.data_dir.join("certs").join(format!("{mx}.crt"));
        let key = cfg.data_dir.join("certs").join(format!("{mx}.key"));
        let cert_exists = cert.is_file();
        let key_exists = key.is_file();
        if cert_exists != key_exists {
            warnings
                .push("email STARTTLS certificate is incomplete; both .crt and .key are required");
        } else if !cert_exists {
            warnings.push("email is enabled without a materialized STARTTLS certificate");
        }
        if let Some(acme) = &cfg.acme {
            if !acme.hostnames.iter().any(|hostname| hostname == mx) && !cert_exists {
                warnings.push("email MX hostname is not included in ACME hostnames");
            }
        }
        cert_exists && key_exists
    } else {
        false
    };
    let exit_tls = if cfg.exit.enabled {
        let advertise = cfg.exit.advertise.as_deref().unwrap_or_default();
        let hostname = advertise
            .rsplit_once(':')
            .map(|(hostname, _)| hostname)
            .unwrap_or_default();
        let cert_dir = cfg.data_dir.join("certs");
        let exact = cert_dir.join(format!("{hostname}.crt")).is_file()
            && cert_dir.join(format!("{hostname}.key")).is_file();
        let wildcard = hostname.split_once('.').is_some_and(|(_, parent)| {
            cert_dir.join(format!("_wildcard.{parent}.crt")).is_file()
                && cert_dir.join(format!("_wildcard.{parent}.key")).is_file()
        });
        if !exact && !wildcard {
            warnings.push("exit is enabled without a materialized TLS certificate for its advertised hostname");
        }
        if let Some(acme) = &cfg.acme {
            let covered = acme.hostnames.iter().any(|candidate| {
                candidate == hostname
                    || candidate.strip_prefix("*.").is_some_and(|parent| {
                        hostname
                            .split_once('.')
                            .is_some_and(|(_, rest)| rest == parent)
                    })
            });
            if !covered && !exact && !wildcard {
                warnings.push("exit advertised hostname is not included in ACME hostnames");
            }
        }
        exact || wildcard
    } else {
        false
    };
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
        "github_app_configured": rf::github::app_configured_build(&cfg.build),
        "github_ssh_configured": cfg.build.github_ssh_key.as_deref().is_some_and(|path| path.is_file())
            && cfg.build.github_known_hosts.as_deref().is_some_and(|path| path.is_file()),
        "object_storage": {
            "local_dir": cfg.storage.local_dir,
            "rclone": rclone_version,
            "rclone_configured": cfg.storage.rclone_config.is_some(),
        },
        "email": {
            "enabled": cfg.email.enabled,
            "smtp_listen": cfg.email.smtp_listen,
            "mx_hostname": cfg.email.mx_hostname,
            "outbound": cfg.email.outbound,
            "max_sessions": cfg.email.max_sessions,
            "starttls_ready": email_tls,
        },
        "exit": {
            "enabled": cfg.exit.enabled,
            "listen": cfg.exit.listen,
            "advertise": cfg.exit.advertise,
            "max_sessions": cfg.exit.max_sessions,
            "tls_ready": exit_tls,
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
        if cfg.email.enabled {
            println!(
                "email: {} as {} (STARTTLS {})",
                cfg.email
                    .smtp_listen
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unavailable".into()),
                cfg.email.mx_hostname.as_deref().unwrap_or("unavailable"),
                if email_tls { "ready" } else { "not ready" }
            );
        } else {
            println!("email: disabled");
        }
        if cfg.exit.enabled {
            println!(
                "device exit: {} -> {} (TLS {})",
                cfg.exit
                    .listen
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unavailable".into()),
                cfg.exit.advertise.as_deref().unwrap_or("unavailable"),
                if exit_tls { "ready" } else { "not ready" }
            );
        } else {
            println!("device exit: disabled");
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
    let emailbind_port = rf::emailbind::serve(node.clone()).await?;
    node.set_emailbind_port(emailbind_port);
    tracing::info!("Email binding on 127.0.0.1:{emailbind_port}");
    let servicebind_port = rf::servicebind::serve(node.clone()).await?;
    node.set_servicebind_port(servicebind_port);
    tracing::info!("Worker Service binding on 127.0.0.1:{servicebind_port}");
    let binarybind_port = rf::binarybind::serve(node.clone()).await?;
    node.set_binarybind_port(binarybind_port);
    tracing::info!("Binary Deliver binding on 127.0.0.1:{binarybind_port}");

    let _gossip = rf::gossip::start(node.clone()).await?;
    durable.spawn_ensurer();
    durable.spawn_checkpointer();
    rf::gossip::spawn_blob_fetcher(node.clone());
    rf::pipeline::spawn_driver(node.clone());
    rf::d1_backup::spawn_driver(node.clone());
    rf::workflow::spawn_driver(node.clone());
    rf::flow::spawn_driver(node.clone());
    rf::email::spawn_driver(node.clone());
    tracing::info!("gossip on {}", node.cfg.gossip.listen);

    rf::exitproxy::serve(node.clone()).await?;

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
    rf::observability::spawn(node.clone());

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
    let _smtp_thread = rf::email::spawn_smtp_server(node.clone())?;
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
