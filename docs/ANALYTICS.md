# RandallFlare Analytics Engine

Analytics 数据集是操作员签名资源；事件存入每个数据集独立的 D1 法定多数账本。
Worker 绑定保留熟悉的 `blobs`、`doubles`、`indexes` 形状，每类最多 20 项。

```json
{
  "name": "api",
  "main": "index.js",
  "analytics": { "METRICS": "web-metrics" }
}
```

```js
env.METRICS.writeDataPoint({
  blobs: ["pageview", "/pricing"],
  doubles: [42.5, 1],
  indexes: ["visitor-1"],
});
```

写入由 `waitUntil` 在当前请求结束后完成。每批最多 100 个数据点、1 MiB；字符串
维度单项最多 5 KiB，数值必须有限。可选 `retention_days` 在后续写入时清理过期
事件。

## SQL 视图

每个数据集提供只读的 `events` 视图：

| 列 | 含义 |
| --- | --- |
| `id` | 事件 ID |
| `timestamp` / `ts_ms` | 事件毫秒时间戳 |
| `created_at_ms` | 接收时间 |
| `blob1` … `blob20` | 字符串 blob 槽位 |
| `double1` … `double20` | 数值槽位 |
| `index1` … `index20` | 索引字符串槽位 |
| `_sample_interval` | 当前为 1；查询可提前按采样兼容方式加权 |

示例：

```sql
SELECT
  blob1 AS event_type,
  COUNT(*) AS events,
  SUM(double1 * _sample_interval) AS total,
  AVG(double1) AS average
FROM events
WHERE timestamp >= ?1
GROUP BY blob1
ORDER BY events DESC;
```

CLI 参数按 JSON 解码：

```bash
rf analytics query web-metrics \
  'SELECT blob1, COUNT(*) AS events FROM events WHERE timestamp >= ?1 GROUP BY blob1' \
  --param 1785859200000 --limit 1000
```

也可使用 `--file ./query.sql`。中文控制台的数据集详情页提供 SQL、参数数组和结果
工作台；统一鉴权 API 为 `POST /api/v1/analytics/{dataset}/query`，需要
`analytics:read` 权限。

查询只接受 `SELECT` / `WITH`，最长 64 KiB、最多 100 个绑定参数。服务端用外层
查询强制限制结果，最大返回 9,999 行，并在还有更多行时设置 `truncated: true`。
底层 D1 仍会验证编译后的 SQLite 语句为只读，查询无法借由 API 修改事件账本。

## 快速统计

无需 SQL 时可直接使用：

```bash
rf analytics stats web-metrics
rf analytics events web-metrics --limit 100
rf analytics group web-metrics --dimension blob --dimension-index 0 \
  --double-index 0 --limit 20
```

这些接口与 SQL 查询都从 D1 leader 读取，避免在节点切换期间看到落后的副本。
