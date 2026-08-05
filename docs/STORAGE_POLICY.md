# rclone 存储策略与零迁移分片

RandallFlare 可以把 R2 对象内容分散到任意 rclone remote，例如 Cloudflare R2、
S3、Google Drive、B2 或本地挂载。控制平面只复制 remote 名称；endpoint、访问密钥
和 rclone 配置始终留在节点本地，不会进入签名资源、Gossip、审计响应或浏览器。

## 1. 工作方式

全局 `default` 存储策略是一条管理员签名、带版本和前序摘要的平台资源。一个 R2
bucket 在创建时可以选择该策略；这不会把既有 bucket 自动改成 rclone。

每次写入按以下顺序执行：

1. 完整计算内容的 SHA-256；
2. 将摘要前 32 位按大端无符号整数解释；
3. 对策略中有序 remote 数量取模；
4. 将内容写到 `<前缀>/<完整 SHA-256>`；
5. 在 bucket 的 D1 元数据中提交具体 `remote` 和当时的前缀。

分片盘故意使用扁平文件名，不建立摘要前缀目录。这适合有单盘对象数上限的后端，
并使相同内容天然复用同一个地址。元数据记录的是实际位置，而不是以后重新计算的
位置，因此增加 remote 只影响后续新内容，旧对象不移动、也不会因分片数变化而失联。

重新排列 remote 或修改前缀同样只影响后续写入。仍保存对象或 multipart 分片的
remote 不能从策略删除；节点会查询所有 bucket 的多数派元数据并拒绝有破坏性的签名
变更。需要退役一个 remote 时，应先把相关对象复制并重建元数据，或删除这些对象，
确认“实际存储分布”为零后再移除。

## 2. 节点本地配置

先在每个承担存储工作的节点准备权限为 `0600` 的 rclone 配置。示例只展示结构，
不要把真实凭据写进仓库：

```ini
[drive-00]
type = s3
provider = Cloudflare
endpoint = https://ACCOUNT_ID.r2.cloudflarestorage.com
access_key_id = 从节点环境或受保护文件注入
secret_access_key = 从节点环境或受保护文件注入

[drive-01]
type = s3
provider = Other
endpoint = https://s3.example.net
access_key_id = 从节点环境或受保护文件注入
secret_access_key = 从节点环境或受保护文件注入
```

在 `rf.toml` 中只引用该本地文件：

```toml
[storage]
local_dir = "/var/lib/rf/objects"
rclone_binary = "/usr/bin/rclone"
rclone_config = "/etc/rclone/rclone.conf"
rclone_timeout_seconds = 1800
```

配置了 rclone 的节点会公开经过认证的 `rclone` 能力标签。策略 bucket 的 Worker
会自动要求相应存储能力；请求落到不具备 rclone 的节点时，R2 数据面也可以通过集群
加密 peer API 借用一个可达的 rclone 节点。remote 名称必须在所有承担该职责的节点上
表示同一套后端。

## 3. 创建策略和 bucket

以下命令在管理员设备执行。集群密钥和管理员私钥应通过受保护环境提供，不要写进
shell 历史或文档：

```bash
rf storage configure \
  --new-bucket-backend rclone-sharded \
  --remote drive-00 \
  --remote drive-01 \
  --shard-prefix randallflare/objects

rf storage show
rf storage probe
rf r2 bucket-create assets --storage-policy --public
```

`new-bucket-backend` 只是控制台和 CLI 新建 bucket 时采用的默认选择；真正的数据
后端仍固定在每个 bucket 的签名定义中。切回 `local` 不会修改或迁移现有策略 bucket。

中文控制台的“存储策略”页面提供：

- 策略版本、摘要、默认后端和有序 remote 编辑器；
- 对所有存活节点执行的有上限并发 remote 探测；
- 按真实 `remote + prefix` 聚合的 bucket、对象引用数和逻辑字节分布；
- 需要管理员设备签名的一次性变更审批。

## 4. multipart、回收和故障恢复

multipart 的每一个 part 都先计算自己的摘要，并把具体位置写入 D1。完成上传时，
节点按各 part 的实际位置逐个读取和校验，在对象盘的专用暂存目录顺序组装，同时计算
最终 SHA-256；内存占用不会随最终对象大小增长。摘要确认后，文件通过 `rclone rcat`
流式发布到最终内容地址，再提交 D1 元数据。成功或失败都会删除暂存文件；进程崩溃
留下的文件会在 24 小时后由生命周期任务回收。旧版本数据库会在线增加位置列，并用
上传会话原有的位置回填。中止、过期清理和引用安全的延迟回收也使用被固定的位置，
不会套用后来变化的策略。

控制台的 R2 bucket 详情会分页列出活动 multipart 会话、分片数量、暂存字节和到期
时间，并可查看每个分片的 ETag。管理员主动终止会话后，元数据先从 D1 多数派移除，
底层本地/rclone 内容再进入延迟、引用安全的回收队列。CLI 对应命令为
`rf r2 multipart-list`、`multipart-inspect` 与 `multipart-abort`。

读取会重新计算 SHA-256。摘要不符、remote 不可达、D1 多数派不可用或所有 rclone
节点离线时，请求明确失败，不会悄悄返回其他内容。运维时可先在“节点可达性”矩阵
确认所有节点，再观察“实际存储分布”，最后添加新盘或调整默认值。

当前直接上传和单个 part 上限为 63 MiB，每个上传最多 10,000 个 part。rclone
multipart 的完成与发布已是有界内存的文件流。公网 R2 域名与 S3 GET/HEAD/Range
在返回响应前会把远端对象流式落入临时 spool，核对完整 SHA-256 后再从文件流输出；
客户端中断会立即删除 spool，进程崩溃残留由生命周期任务回收。这优先保证“不返回
未经验证的字节”，首次读取会多一次落盘等待。

Worker binding、跨节点借用以及上传请求体的多 GiB 流仍在兼容性清单中分别跟踪。
本地单节点后端最多组装 512 MiB；本地多节点的大对象在流式副本协议完成前会安全
拒绝，生产大对象应使用 rclone 策略。存储策略不会替代后端自身的版本控制、跨区域
复制和备份策略。
