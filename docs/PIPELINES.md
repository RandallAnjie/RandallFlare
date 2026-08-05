# RandallFlare Pipeline

Pipeline 把 HTTP 或 Worker 绑定收到的事件先规范化、校验和转换，再提交到独立的
D1 法定多数账本。后台节点通过带期限租约生成确定性 gzip JSONL 批次并写入签名
R2 bucket；该 bucket 可以使用本地存储，也可以使用 rclone 策略和分片。

公网入口会把分块请求边接收边写入自动清理的临时文件，不会在异步 HTTP 任务中
保留完整请求体。NDJSON 与纯文本随后逐行解析；JSON 对象或数组从临时文件直接
反序列化。请求仍严格限制为 32 MiB 和 10000 个事件，空请求、超限请求和无效
UTF-8/JSON 都会在写入 D1 前失败。

## 创建

```bash
rf pipeline create event-archive \
  --bucket data-lake \
  --hostname ingest.example.com \
  --schema '{"type":"object","required":["kind","amount"]}' \
  --transform-sql 'INSERT INTO archive SELECT kind, amount * 1.1 AS gross FROM events WHERE amount > 0'
```

较长的 SQL 可以放在文件中：

```bash
rf pipeline create event-archive --bucket data-lake \
  --transform-sql-file ./pipeline.sql
```

定义、Schema、SQL、输出位置、域名和暂停状态全部进入操作员签名资源链。接收
Bearer 令牌只保存 SHA-256；明文由 `rf pipeline token-create` 或控制台显示一次。

## SQL 转换

每个请求形成一个临时的 `events` 表。JSON 对象的一层字段成为同名列：布尔值、
整数、浮点数和字符串保留 SQLite 标量类型；数组和对象保存为 JSON 文本，可用
`json_extract`、`json_each` 等 JSON 函数处理。完整原始事件位于
`__rf_event` 列。

```sql
INSERT INTO archive
SELECT
  user_id,
  UPPER(event_type) AS event_type,
  amount * 1.1 AS amount_with_tax,
  json_extract(metadata, '$.region') AS region
FROM events
WHERE event_type = 'purchase' AND amount > 0;
```

也可直接写 `SELECT ... FROM events`。sink 名称用于与 Cloudflare Pipelines 配置
保持同形；当前 RandallFlare Pipeline 只有一个签名 R2 输出，因此不会把 sink
名称用于寻址。筛选为零行是正常结果：请求成功，但不会向耐久队列加入事件。

转换执行有以下硬边界：

- SQL 最长 64 KiB，只允许无参数只读 `SELECT` / `WITH` 查询；
- 每批最多展开 256 个输入字段，输出 1 至 256 个具名且不重复的列；
- 输出最多 10,000 行、32 MiB；
- 先按输入 JSON Schema 校验，后执行 SQL，再提交转换结果；
- SQL 出错时整次请求失败，不会产生半批事件。

这使转换结果在进入 D1 前已经确定。节点在上传后、提交批次审计前崩溃时，接管
节点会根据同一组事件 ID 计算相同 `batchId` 和对象键，安全覆盖而不会产生第二个
逻辑批次。

## 接收

Worker 绑定：

```json
{
  "name": "producer",
  "main": "index.js",
  "pipelines": { "ARCHIVE": "event-archive" }
}
```

```js
await env.ARCHIVE.send([
  { user_id: "u1", event_type: "purchase", amount: 20 },
  { user_id: "u2", event_type: "view", amount: 0 },
]);
```

HTTP 接收支持 JSON 单事件、JSON 数组、`{"events": [...]}`、NDJSON 和 UTF-8
纯文本。自定义或默认域名上的 `/send` 使用 Bearer 令牌；每个请求正文上限
32 MiB、最多 10,000 个事件。

## 批次与恢复

`batch_max_bytes` 或 `batch_max_seconds` 任一阈值达到后即可刷新。直接对象上限
以上自动改用 R2 multipart；失败会释放 D1 租约并保留事件。可在中文控制台或
CLI 查看深度、失败原因与输出对象：

```bash
rf pipeline status event-archive
rf pipeline batches event-archive --limit 100
rf pipeline flush event-archive
```
