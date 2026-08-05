# KV / D1 数据变更审计

RandallFlare 的签名资源历史证明“配置由谁修改、版本如何衔接”；数据变更审计则证明
“某次 KV 或 D1 变更确实发生过”，但不复制业务数据。

每条 KV 证明只包含命名空间、操作类型、键的 SHA-256、值与到期时间组合的
SHA-256、字节数、HLC 和写入节点。每条 D1 证明只包含数据库名、Raft epoch/序号、
序列化命令的 SHA-256 与字节数。键名、KV 值、SQL 和参数从不进入审计表、API、
控制台或归档对象。

KV entry 与其证明在同一个 redb 写事务中提交；同一 HLC/writer/content 会生成相同
审计 ID，因此反熵复制到其他节点后可以安全去重。D1 证明只在 Raft entry 成功提交
并应用后生成；每个副本根据 database/epoch/sequence/command digest 得到相同 ID。
控制台和集群 API 会合并所有当前可达节点的观察结果。

## CLI 与归档

```bash
rf audit list --limit 500
rf audit list --before-ms 1785772800000 --limit 1000
rf audit archive --bucket compliance --prefix data-audit
```

`archive` 聚合并去重当前窗口内最多 10000 条证明，按时间正序写成 gzip JSONL，
然后通过普通 R2 写入路径发布。因此 `compliance` bucket 可以使用本地多数副本、固定
rclone remote 或签名 rclone 分片策略。对象 custom metadata 记录格式、条数及首尾
时间；内容仍只有摘要证明。

中文控制台“安全与访问 → 签名与数据变更审计”提供同样的查看与归档操作。节点本地
证明默认保留 30 天；需要更长留存时，应定期归档到带生命周期和配额的 R2 bucket。
归档成功不会提前删除本地证明，重复归档会生成不同时间戳对象，可由 bucket 生命周期
统一管理。

