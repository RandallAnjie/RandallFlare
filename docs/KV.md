# 去中心化 KV

RandallFlare KV 是按命名空间划分的 HLC/LWW CRDT。写入可以发送到任意节点，随后通过
加密反熵在集群中收敛；同一键并发写入用 `(HLC, 写入节点, 值摘要)` 确定唯一结果。
删除写入墓碑，TTL 在读取和列举时立即生效，墓碑及长期过期值经过安全窗口后回收。

Worker 使用 Cloudflare 兼容的 `get`、`getWithMetadata`、`put`、`delete`、`list` 与批量
`get`。单值最大 25 MiB，metadata 最大 1,024 字节；相对 TTL 和绝对过期时间至少应在
60 秒之后。`list` 每页最多 1,000 个键并返回可继续使用的不透明游标。

## 中文控制台

“KV 存储”页面每页显示 100 个键及大小、TTL 和 metadata 状态，可以按前缀翻页。编辑器
支持 UTF-8 或 Base64 二进制值、相对 TTL、绝对时间以及任意 JSON metadata。以 `__rf`
开头的内部命名空间始终禁止从控制台或个人 API 令牌写入。

“导出 JSON”会读取当前命名空间和前缀下的全部可见键，保留原始二进制、绝对过期时间
与 metadata。导入会先完整校验版本、重复键、Base64、大小、metadata 和过期时间，再
开始逐键写入；同名键按 KV 的正常写入语义覆盖，已经过期的键会跳过。单次迁移最多
10,000 个键、64 MiB 原始值，每个值仍受 25 MiB 上限约束。导出格式为：

```json
{
  "version": 1,
  "namespace": "assets",
  "prefix": "images/",
  "entries": [
    {
      "key": "images/logo",
      "value_base64": "AAECAw==",
      "expiration": 2000000000,
      "metadata": { "contentType": "image/png" }
    }
  ]
}
```

KV 是最终一致的数据结构，因此导出期间发生的并发写入可能落在导出游标的前后两个
快照中；需要强一致事务或可重复快照的数据应使用 D1 或 Durable Objects。
