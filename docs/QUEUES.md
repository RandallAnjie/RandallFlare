# RandallFlare Queues

RandallFlare Queue 是签名资源。队列定义写入平台资源哈希链；就绪、租约、重试、
死信和计数器写入该队列独立的 D1 微型法定多数账本，因此更换消费节点不会丢失
已经提交的消息。

## Worker 绑定

在 `rf.json` 中把绑定名映射到队列名：

```json
{
  "name": "orders-api",
  "main": "index.js",
  "queues": { "ORDERS": "orders" }
}
```

生产者接口与 Workers Queues 保持同形：

```js
await env.ORDERS.send({ orderId: "RF-1001" });
await env.ORDERS.send("立即处理", { contentType: "text" });
await env.ORDERS.send(new Uint8Array([0, 1, 2, 255]), {
  contentType: "bytes",
  delaySeconds: 30,
});
await env.ORDERS.sendBatch([
  { body: { orderId: "RF-1002" }, contentType: "json" },
  { body: "普通文本", contentType: "text" },
]);
```

`contentType` 可取 `json`、`v8`、`text` 或 `bytes`。Worker 默认使用 `v8`；当前
`v8` 模式完整保留 JSON 可表达的结构化克隆子集，循环引用、`Map`、`Set`、
`BigInt` 等原生 V8 专有值会明确失败，不会静默改写。`bytes` 在消费者侧还原为
`Uint8Array`，文本还原为字符串，其余类型还原为 JSON 值。

```js
export default {
  async queue(batch, env, context) {
    for (const message of batch.messages) {
      try {
        await handle(message.body);
        message.ack();
      } catch (error) {
        message.retry({ delaySeconds: 10, error: String(error) });
      }
    }
  },
};
```

处理程序正常返回时，未显式重试的消息会自动确认。也可使用 `batch.ackAll()`、
`batch.retryAll()`。每次投递的 `message.attempts` 从 1 开始。

## 创建、暂停与恢复

```bash
rf queue create orders --consumer orders-api --batch-size 10 \
  --max-retries 3 --retention-seconds 604800

rf queue create orders --consumer orders-api --suspended
rf queue create orders --consumer orders-api
```

暂停只冻结租约领取和消费者投递，生产者仍然能写入。恢复后，积压消息继续按照
`available_at_ms` 和消息 ID 的稳定顺序领取。这个语义适合维护、排空消费者和
无损发布。

## CLI 调试与死信

```bash
rf queue send orders '{"orderId":"RF-1003"}' --content-type json
rf queue send orders '纯文本消息' --content-type text
rf queue send orders --file ./payload.bin --content-type bytes
rf queue stats orders
rf queue dead orders --limit 100
rf queue redrive orders MESSAGE_ID
```

单条消息的实际正文上限是 128 KiB；一次批量请求最多 100 条，单条延迟最多
12 小时。死信保留正文类型和二进制数据，重投不会把二进制误转成 JSON。

## 投递与故障语义

- D1 法定多数提交完成后，生产请求才成功。
- 消费者通过带期限的租约领取消息；节点崩溃后租约到期即可重投。
- 达到重试预算后消息进入耐久死信表；配置了死信目标队列时会保留原 ID 和类型。
- `total_produced`、`total_consumed`、就绪、在途与死信深度可从 CLI 和中文控制台查看。
- 预览部署不会接收生产 Queue 消费事件。
