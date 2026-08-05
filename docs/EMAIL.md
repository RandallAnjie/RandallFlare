# RandallFlare 去中心化邮件指南

RandallFlare 的邮件能力不是中心化邮件 SaaS。邮件域定义和路由经过管理员签名并
随集群复制；每个邮件域拥有独立的 D1 法定人数账本；原始 RFC 822 邮件写入普通
R2 bucket，因此同一套能力可以使用本地多数派副本或节点侧 rclone 远端。只有显式
启用 `[email]` 的节点才监听 SMTP、领取入站处理和出站投递任务。

## 1. 选择邮件节点

普通 Worker、存储和管理节点不需要启用邮件角色。邮件节点至少需要：

- 公网 TCP 25 入站和出站可达；部分 VPS 服务商默认封禁 25 端口；
- 一个稳定的 MX 主机名，例如 `mx1.example.com`，其 A/AAAA 和 PTR 应相互对应；
- `<data_dir>/certs/<mx_hostname>.crt` 与 `.key`，用于入站 STARTTLS；
- 如果允许出站，为每个邮件域提供节点本地 DKIM 私钥环境变量。

节点配置示例：

```toml
[email]
enabled = true
smtp_listen = "0.0.0.0:25"
mx_hostname = "mx1.example.com"
outbound = true
max_sessions = 64
```

`mx_hostname` 同时是 SMTP EHLO 名称、域名验证所要求的 MX 目标，以及 STARTTLS
证书文件名。证书在进程启动时载入；首次物化或替换证书后应重启邮件节点。
可以把 MX 主机名加入 `[acme].hostnames`，也可以通过受信任的外部 ACME 客户端把
证书放入上述目录。

DKIM 私钥绝不能进入 TOML、签名资源、浏览器或 Git。邮件域定义只保存形如
`RF_EMAIL_DKIM_SUPPORT` 的环境变量名；PEM（RSA PKCS#1 或 PKCS#8）仅写入获准
出站的邮件节点 `/etc/rf.env`。不拥有该变量的节点不会领取该域的出站租约。

## 2. 创建存储与邮件域

先创建保存原文的 R2 bucket。该 bucket 可以使用本地存储，也可以使用签名定义中
的 rclone backend；rclone 凭据仍只存在各节点的配置文件中。

```bash
rf r2 bucket-create mail-archive
```

在中文管理后台的“邮件路由”页面可以完成全部配置。也可以准备路由文件：

```json
[
  {
    "id": "support",
    "priority": 0,
    "enabled": true,
    "match": "exact",
    "value": "support@example.com",
    "destination": { "type": "worker", "worker": "support-worker" }
  },
  {
    "id": "orders",
    "priority": 10,
    "enabled": true,
    "match": "prefix",
    "value": "order+",
    "destination": {
      "type": "forward",
      "addresses": ["archive@example.net"]
    }
  },
  {
    "id": "catch-all",
    "priority": 100,
    "enabled": true,
    "match": "catch_all",
    "destination": { "type": "drop" }
  }
]
```

匹配顺序固定为精确地址、地址前缀、兜底；同类规则中 `priority` 数字较小者先
执行。没有匹配路由的 SMTP 收件地址会被拒绝。

```bash
rf email create support-mail \
  --domain example.com \
  --mx-hostname mx1.example.com \
  --bucket mail-archive \
  --routes routes.json \
  --dkim-selector rf \
  --dkim-public-key 'v=DKIM1; k=rsa; p=填入公钥内容' \
  --dkim-private-key-env RF_EMAIL_DKIM_SUPPORT
```

管理后台的公开会话仍采用一次性管理员批准；CLI 直连则由管理员密钥签署资源。
定义中不存在私钥正文。

## 3. 发布并验证 DNS

创建邮件域后会得到准确的 DNS 值。通常需要发布：

| 类型 | 名称 | 值 |
| --- | --- | --- |
| TXT | `_randallflare-verify.example.com` | 后台显示的所有权验证值 |
| MX | `example.com` | 优先级 10，目标 `mx1.example.com` |
| TXT | `rf._domainkey.example.com` | 签名定义中的 DKIM 公钥值 |
| TXT | `example.com` | `v=spf1 mx -all`（按实际发信节点调整） |
| TXT | `_dmarc.example.com` | 建议先使用 `v=DMARC1; p=none` 观察，再逐步收紧 |

RandallFlare 把所有权 TXT、精确 MX 和已配置的 DKIM 作为就绪条件；SPF 会展示但
不阻止入站。DNS 生效后在后台点“立即检查 DNS”，或运行：

```bash
rf email verify support-mail
```

所有验证快照都写入邮件域的 D1 账本。未验证域不会接收入站，也不会建立出站
投递。

## 4. Worker 入站处理

在 Worker 设置的 Email 绑定中添加 `MAIL=support-mail`，并为路由指定该 Worker。
默认导出对象可以实现 `email()`：

```js
export default {
  async email(message, env, context) {
    const subject = message.headers.get("subject") || "（无主题）";

    if (message.from.endsWith("@blocked.example")) {
      message.setReject("发件域不受信任");
      return;
    }

    if (subject.includes("订单")) {
      await message.forward("orders@example.net", {
        "X-RandallFlare-Route": "orders"
      });
    }

    context.waitUntil(env.METRICS?.writeDataPoint({
      blobs: ["email", message.to],
      doubles: [message.rawSize]
    }));
  }
};
```

`message` 提供 `from`、`to`、`headers`、`raw`（ReadableStream）、`rawSize`、
`authResults`、`spf`、`dkim`、`dmarc`、`setReject(reason)` 与
`forward(recipient, headers?)`。Worker 处理失败会进入耐久重试；转发有稳定幂等
ID 和最多五跳的循环保护。

同一 Email 绑定也可以可靠发信。原文会先进入 R2 与 D1，再由符合能力条件的节点
投递：

```js
await env.MAIL.send({
  from: "noreply@example.com",
  to: "customer@example.net",
  raw: `From: RandallFlare <noreply@example.com>\r
To: customer@example.net\r
Subject: 已收到你的请求\r
Content-Type: text/plain; charset=utf-8\r
\r
我们已经收到你的请求。\r
`
});
```

发件人的域必须等于绑定邮件域。当前一次 `send()` 建立一个收件人投递；需要群发时
分别调用以保持每个收件人的状态、重试和审计彼此独立。

## 5. Flow 邮件节点

Flow 的 `email` 节点可以使用完整 `raw`，也可以由平台生成纯文本 RFC 822：

```json
{
  "domain": "support-mail",
  "from": "noreply@example.com",
  "to": ["customer@example.net"],
  "subject": "处理完成",
  "body": "{{ nodes.result }}"
}
```

`body` 缺省时使用该节点输入。节点返回每个收件人的排队 ID 和 R2 对象键；Flow
步骤完成表示邮件已经耐久排队，并不表示远端 MX 已经接受。

## 6. 投递、重试与保留

- 每个收件人拥有独立状态和法定人数租约；节点崩溃后其他合格节点可接管；
- 出站直接查询收件域 MX，按优先级尝试，并使用机会式 STARTTLS；Null MX 会永久
  拒绝；
- 入站 SMTP 宣告 `SMTPUTF8` 和 `8BITMIME`；国际化本地部保留原文，域名部统一转为
  小写。出站只在信封需要时发送 `SMTPUTF8`；远端 MX 不支持时记为永久失败；
- 临时失败最多尝试五次，退避为 30 秒、2 分钟、8 分钟、32 分钟和 128 分钟；
- 永久失败或重试耗尽后，平台生成 `multipart/report` / `message/global-delivery-status`
  DSN，以空逆向路径写回原发件人的本域签名路由。DSN 具有 D1 栅栏租约、稳定消息
  ID、最多五次重试和完整审计；`Auto-Submitted` 会阻断退信环；
- SPF、DKIM、DMARC 与完整 `Authentication-Results` 会随入站记录保存；
- 原文按 `<prefix>/<direction>/<年>/<月>/<日>/<id>.eml` 写入 R2；
- 达到签名 `retention_days` 后，只有终态记录会被清理；仍被其他收件人引用的共享
  原文不会提前删除；
- 后台可以查看投递状态、错误、认证结果和 R2 键，并下载原始 `.eml`。

## 7. 运维边界

本功能是可验证、可接管的邮件路由与投递底座，并不假装解决公网邮件信誉。生产
发信仍需要正确 PTR、稳定 IP、域名预热、退信监控及各收件服务商策略。当前不会
替你建立集中式用户邮箱、IMAP/POP3 账户或网页收件箱；邮件应由 Worker、可靠
转发或外部邮箱系统消费。

排障时只查看元数据，避免把邮件原文或 DKIM 私钥粘贴到日志：

```bash
rf email list
rf email messages support-mail --limit 50
rf email message support-mail <message-id>
journalctl -u rf -n 200 --no-pager
```
