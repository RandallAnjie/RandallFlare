# 去中心化 Workflow

Workflow 把长时间任务拆成可重放步骤。定义是管理员签名、带版本和前序摘要的平台
资源；实例、步骤、信号、租约和审计事件写入该 Workflow 独享的 D1 多数派账本。
执行节点消失后，租约到期，其他节点从最后一个已提交步骤继续。

## 定义与版本冻结

每个新实例会把当前定义版本、入口类、系统重试次数和单次推进超时复制进实例行。
以后编辑 Workflow 只影响新实例，正在睡眠、等待信号或等待系统重试的旧实例不会在
恢复时突然采用另一套入口或重试策略。实例详情会显示它实际冻结的定义版本。

`max_concurrent_instances` 在认领实例的同一条 D1 条件更新中检查。`0` 表示不额外
限制；非零值限制 `running` 实例数，不会把耐久睡眠或等待信号的实例算作占用者。

`max_concurrent_instances_per_group` 对调用方选择的命名并发组施加第二层限制。
例如，所有客户仍可全局并发，但同一 `customer:10001` 组只能有一个实例在运行。
组名和当时的组限额一起冻结在实例行，后续修改定义不会改变已创建实例的排队语义。
全局限额和组限额在同一条 D1 比较并更新中原子执行，多节点竞争不会超发。

## 触发方式

- 手动、CLI 和 Worker 绑定：调用 `create({ id, params })`；幂等键重复时返回原实例。
- 命名并发组：Worker 调用 `create({ id, concurrencyGroup, params })`；CLI 使用
  `rf workflow trigger ... --concurrency-group customer:10001`。
- Cron：保存标准五字段 UTC 表达式。所有节点都可计算时间，但
  `cron:v<定义版本>:<分钟>` 的 D1 唯一键保证每个定义版本每分钟至多创建一次。
- Webhook：`POST /`、`POST /hook` 或 `POST /v1/run`，正文必须是最大 4 MiB 的 JSON。
  `Idempotency-Key` 请求头会成为实例幂等键。
  `X-Workflow-Concurrency-Group` 可选请求头指定命名并发组。

默认 Webhook 域名是 `workflow-<名称>.<ingress.default_domain>`，也可在签名定义中
增加自定义域名。域名完成全局 DNS TXT 所有权验证后才会启用入口；启用 ACME 后，
这些已验证域名进入同一证书发现流程。

## Webhook 认证

先在中文控制台的 Workflow 详情签发令牌，或运行：

```bash
rf workflow token-create order-flow --label production
```

明文以 `rfw_` 开头，只显示一次；平台只保存 SHA-256、公开 ID、标签、尾号和创建
时间。调用方通过 `Authorization: Bearer <token>` 或 `X-Workflow-Token` 发送令牌：

```bash
curl https://workflow-order-flow.example.com/hook \
  -H 'Authorization: Bearer rfw_...' \
  -H 'Idempotency-Key: order-1001' \
  -H 'Content-Type: application/json' \
  --data '{"orderId":"1001"}'
```

撤销最后一个令牌时，平台同时关闭 Webhook，避免出现已公开但永远无法认证的入口。
令牌变更与其他 Workflow 变更一样需要管理员签名并传播到集群。

## 故障与边界

步骤结果写入成功后，重放只读取结果而不重新执行用户函数。睡眠和等待信号会释放
推进租约；执行中的节点故障则由五分钟栅栏租约和一分钟心跳检测。系统级错误使用
实例冻结的重试预算及指数退避。用户明确抛出的失败进入终态，不会被当成基础设施
错误无限重试。

生产验收仍应覆盖多 VPS 在步骤提交、HTTP 响应丢失、心跳中断和领导者切换等崩溃
点的长时间压力测试。
