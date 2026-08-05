# Durable Objects：原生 workerd 与去中心化故障接管

RandallFlare 直接启用当前固定版本 workerd 的 Durable Object namespace 与 SQLite
存储，不在 JavaScript 前面模拟一套私有 API。Worker 因此可以使用 `idFromName()`、
`get()`/`getByName()`、`DurableObjectState`、键值存储、SQL、事务、alarm 与
WebSocket Hibernation API；RandallFlare 负责它们在多节点环境中的唯一所有权、持久化
快照、路由与恢复。

## 1. 绑定

在统一的 Worker（包含原 Pages）项目 `rf.json` 中声明导出的类：

```json
{
  "name": "rooms",
  "main": "index.js",
  "durable_objects": {
    "ROOMS": {
      "class_name": "Room",
      "enable_sql": true
    }
  }
}
```

`unique_key` 通常不需要手写，部署器会根据项目与类名生成稳定值。它控制 namespace
身份，不能在已有数据上随意更换。`enable_sql` 打开原生 SQLite 存储；普通 Storage
API 同样可用。

## 2. 一致性与所有权

每个包含 Durable Object 的生产 Worker 拥有独立的 D1 三节点微仲裁组。当前 Raft
epoch 只有一个节点获准启动该 Worker 的 workerd 实例；其他公网入口会把请求转给
这个所有者。产生响应的请求返回浏览器前，节点会对 workerd SQLite 文件执行 WAL
checkpoint、压缩快照并提交到多数派。

alarm、`waitUntil()` 与 WebSocket 消息可能在普通 HTTP 响应之后继续修改状态。所有者
每秒检查一次存储目录；内容摘要没有变化时不写 Raft，有变化时提交新快照。因此应用
仍应遵守 Durable Object 的幂等事件设计，不应把未等待的内存变量当成持久化确认。

单节点测试时仲裁组退化为一成员。生产可用性至少需要三个彼此独立的节点。仅用于隔离
开发的逃生开关会跳过分布式 fencing：

```toml
[runtime]
allow_local_durable_objects = true
```

## 3. Alarm

原生 `storage.setAlarm()`、`getAlarm()` 与 `deleteAlarm()` 的数据和对象 SQLite 一起
进入多数派快照。所有者进程在 alarm 到期前退出时，新所有者恢复 workerd 存储后会
继续触发它。

alarm handler 抛出未捕获异常时，当前固定版 workerd 使用指数退避，最多自动重试
六次；handler 收到 `{ retryCount, isRetry }`。这是至少一次执行，业务代码必须幂等。
需要超出自动预算长期重试时，应在最后一次尝试前写入业务状态并重新
`setAlarm()`，而不是依赖无限自动重试。

## 4. WebSocket 与 Hibernation

普通 Worker WebSocket 和 Durable Object WebSocket 都保留原始 HTTP/1.1 Upgrade；
RandallFlare 不解码、重编码应用帧，因此文本、二进制、ping/pong、关闭帧与子协议都
由浏览器和 workerd 直接协商。DO 可以使用推荐的 Hibernation API：

```js
export class Room {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch() {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, ["room"]);
    server.serializeAttachment({ joinedAt: Date.now() });
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(socket, message) {
    await this.ctx.storage.put("lastMessage", String(message));
    socket.send("ok");
  }
}
```

访问者命中的节点不是所有者时，握手元数据先经过既有的集群 HMAC 与 XChaCha20-
Poly1305 信封；101 之后的长连接按 32 KiB 分帧，每帧使用独立随机 nonce、方向和严格
递增序号进行认证加密。浏览器不会看到节点传输头，集群网络也不会出现明文 WebSocket
载荷。

物理节点或 workerd 进程消失时，已经建立的 TCP/WebSocket 连接无法凭空迁移，客户端
会收到断开并应带退避重连。新握手会路由到新所有者；它在启动 workerd 前恢复最后一份
多数派快照。RandallFlare 的三节点端到端测试覆盖了“非所有者入口连接 → WebSocket
写状态 → 所有者退出 → 新所有者恢复 → 重连继续写入”的完整路径。

## 5. 运维边界

- placement 标签决定新建 DO 仲裁组的候选节点；已有仲裁组的在线迁移仍应按节点维护
  流程逐台执行，不能同时停止多数派。
- 大量长连接会占用入口节点与所有者的文件描述符。systemd `LimitNOFILE`、反向代理
  Upgrade 透传、空闲超时和四层负载均衡超时都必须相应调高。
- 自定义域名必须先完成全局 TXT 所有权验证并取得 TLS 证书；系统默认域名立即可用。
- 连接断开后的重连、alarm 和其他至少一次事件都可能重复到达。应用层使用对象存储中
  的版本号或幂等键消除副作用。
