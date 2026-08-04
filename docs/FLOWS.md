# RandallFlare Flow 使用指南

Flow 是 RandallFlare 的去中心化可视化编排器。流程定义是经过管理员签名的
平台资源，定义及其版本链通过集群复制；每个 Flow 的运行、步骤和审计事件则
写入独立的 D1 微型仲裁组。集群没有调度主节点，任何合格节点都可以领取带有
栅栏令牌的运行租约，节点失联后其余节点会从已提交步骤继续执行。

管理后台的“Flow 编排”页面提供独立的流程列表、设置、拖拽画布、节点检查器、
Webhook 令牌、运行历史、步骤明细和审计时间线。也可以用 CLI 导入或导出画布
使用的 `FlowGraph` JSON。

## 触发方式与域名

一个 Flow 只能有一个触发器：

- `manual`：从后台、CLI 或加密节点 API 手动触发。
- `webhook`：从公开域名接收 JSON `POST` 请求。
- `cron`：采用标准五段 Cron 表达式，由所有节点确定性计算，幂等键防止重复。

配置了 `ingress.default_domain` 后，名为 `order-sync` 的 Flow 自动得到
`flow-order-sync.<default_domain>`；签名定义里的自定义域名也会生效。Webhook
接受 `/`、`/hook` 和 `/v1/run` 三个路径，并使用以下任一种请求头鉴权：

```text
Authorization: Bearer <一次显示的 Flow 令牌>
X-Flow-Token: <一次显示的 Flow 令牌>
```

令牌明文只在签发时显示一次。签名资源中只保存 SHA-256 哈希、公开 ID、标签、
末四位和签发时间。可随时单独撤销令牌。

默认触发为异步模式并返回 HTTP 202。添加 `?wait=1` 或 `?sync=1` 后，节点最多
等待 25 秒：完成时以 HTTP 200 返回最终 `output`，失败时以 HTTP 502 返回错误，
超时仍以 HTTP 202 返回运行 ID。`Idempotency-Key` 请求头用于安全重试；同一
Flow 中相同键始终指向第一次创建的运行。

```bash
curl -X POST 'https://flow-order-sync.example.com/v1/run?wait=1' \
  -H 'Authorization: Bearer <FLOW_TOKEN>' \
  -H 'Idempotency-Key: order-2026-0001' \
  -H 'Content-Type: application/json' \
  --data '{"order":{"id":"2026-0001"}}'
```

## 图、路由与错误处理

图最多包含 500 个节点和 2,000 条边，必须是有向无环图，并且恰好包含一个
触发器。分支的输出端口是 `true` / `false`；循环的端口是 `each` / `done`；
节点失败时可选择：

- `stop`（默认）：停止整个运行并保留失败步骤与审计记录。
- `continue`：将 `{ "error": "…" }` 作为输出继续默认路径。
- `branch`：走节点的 `error` 输出端口。

每次运行冻结创建瞬间的图和资源版本，因此之后编辑 Flow 不会改变正在运行的
实例。运行支持取消、终态重试、按状态筛选、保留期清理和最大并发限制。

循环节点会把 `each` 子图的每一次迭代单独持久化；节点崩溃后只恢复未提交的
迭代。单次循环最多 1,000 项，循环体暂不允许嵌套另一个循环。子 Flow 作为
封装模块内联运行，父节点得到子 Flow 的最终输出；最多嵌套三层。与参考实现
一致，子 Flow 内的循环节点会被跳过，应把耐久循环放在顶层 Flow。

## 模板表达式

节点配置中的字符串可使用 `{{ … }}`。如果整个字段只有一个表达式，返回值会
保留 JSON 类型；混合文本则插值为字符串。可用根对象如下：

| 表达式 | 含义 |
| --- | --- |
| `input` / `json` / `$` | 当前节点输入 |
| `trigger` | 本次运行最初的完整触发输入 |
| `nodes.<节点 ID>` | 任意已完成节点的输出 |
| `nodes.<节点标签>` | 按非空标签读取节点输出 |
| `item` | 当前循环项目，循环外为 `null` |
| `now` / `$now` | 当前 UTC RFC 3339 时间 |

支持点号、数组下标和方括号路径；条件表达式支持 `==`、`!=`、`>=`、`<=`、
`>`、`<`。条件节点还可配置 `truthy`、`eq`、`ne`、`gt`、`lt`、`contains`。

```json
{
  "template": {
    "orderId": "{{ trigger.order.id }}",
    "risk": "{{ nodes.risk_lookup.score }}",
    "message": "order={{ input.id }} at {{ now }}"
  }
}
```

## 内置节点

| 节点 | 主要能力 |
| --- | --- |
| Trigger | 手动、Webhook 或 Cron 入口 |
| Transform | 类型保持的模板或安全路径表达式 |
| Branch | 条件路由 |
| Loop | 耐久逐项子图和完成分支 |
| Worker | 调用已部署 Worker |
| HTTP | 公网 HTTP(S)，DNS 解析固定且阻断回环、内网、链路本地和地址映射绕过 |
| KV | `get`、`put`、`delete`、`list` |
| D1 | 参数化 SQL |
| R2 | `get`、`put`、`delete`、`list`，支持元数据和二进制 Base64 |
| Queue | `send`、`receive` |
| Analytics | 写入数据点 |
| Pipeline | 向耐久 Pipeline 写入事件 |
| Workflow | 创建或取得耐久 Workflow 实例 |
| Subflow | 内联调用另一份已签名 Flow 并返回输出 |
| Email | 仅在节点启用可选邮件能力时发送或路由邮件 |

Worker、KV、D1、R2、Queue、Analytics、Pipeline、Workflow 和子 Flow 的名称来自
签名配置，不允许用请求输入伪造资源绑定。

## 凭据与网络安全

Flow 图不接受 `secret`、`token`、`password`、`privateKey` 等秘密字段。需要
HTTP 鉴权时只填写形如 `RF_FLOW_CREDENTIAL_*` 的环境变量名；变量值保留在
节点本地，内容必须是 JSON，可描述请求头或 Bearer 凭据。失败告警同样只保存
`RF_FLOW_CREDENTIAL_*` 环境变量名。任何凭据值、Webhook 明文令牌和邮件私钥
都不会进入签名资源、D1 运行日志或浏览器会话。

HTTP 和告警节点不跟随重定向，并在连接前解析、过滤并固定公网地址，从而防止
利用 DNS 重绑定访问节点管理面或云元数据服务。节点输入与输出各限制为 4 MiB，
图 JSON 限制为 768 KiB。

## CLI

以下环境变量只用于示例占位，请在管理员设备上提供实际值；不要把它们写进
仓库或 shell 历史。

```bash
export RF_NODE='<NODE>:7382'
export RF_CLUSTER_SECRET='<64_HEX_CLUSTER_SECRET>'
export RF_OPERATOR_KEY="$PWD/operator.key"

# 从后台导出的 FlowGraph JSON 创建 Webhook Flow，并签发首个令牌
rf flow create order-sync --graph ./order-sync.flow.json \
  --trigger webhook --webhook-token-label production

rf flow list
rf flow token-create order-sync --label rotation
rf flow token-revoke order-sync <TOKEN_ID>
rf flow trigger order-sync --input '{"order":{"id":"2026-0001"}}' \
  --idempotency-key order-2026-0001
rf flow runs order-sync --status failed --limit 50
rf flow run order-sync <RUN_ID>
rf flow retry order-sync <RUN_ID>
rf flow cancel order-sync <RUN_ID>
rf flow stats order-sync
```

删除 Flow 会写入可审计墓碑，不会在节点间制造“旧定义复活”。历史运行由该
Flow 的签名保留天数清理；删除定义前应先导出需要长期保存的审计数据。
