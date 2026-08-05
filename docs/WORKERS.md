# Worker 绑定与加密 Secret

RandallFlare 将脚本 Worker 与静态 Pages 统一为同一种签名部署单元。一个项目可以只有
模块、只有静态资源，也可以同时包含两者；域名、版本、代码源、构建结果和所有平台绑定
都由同一条可验证清单历史管理。

自定义域名可先随清单发布，但在完成全局 DNS TXT 所有权验证前不会进入公网路由或自动
证书队列；系统分配的默认域名不受影响。完整流程见
[自定义域名与 DNS 所有权](./HOSTNAMES.md)。

## Worker Service Binding

在 `rf.json` 中将绑定名映射到目标 Worker：

```json
{
  "name": "frontend",
  "main": "index.js",
  "services": {
    "BACKEND": "backend"
  }
}
```

模块代码直接使用 workerd 原生 Service Binding：

```js
export default {
  async fetch(request, env) {
    return env.BACKEND.fetch(request);
  }
};
```

绑定不是任意 URL。rf 为每个绑定生成只指向 `127.0.0.1` 的 workerd external
service，并注入来源与目标身份。回环代理在每次请求时重新读取当前签名清单，确认调用方
确实获准访问该目标，再解析目标在本节点上的当前动态端口。用户请求头不能选择其他
Worker；目标重启也不要求调用方重新部署。当前版本要求目标模块 Worker 在同一节点运行；
面向 placement/DO 所有者的加密节点间回退仍在后续验收范围内。

绑定名必须是 JavaScript 标识符，目标必须是合法 Worker 名称，不能绑定自身。不同平台
绑定、普通环境变量与 Secret 之间不允许重名。

## 代码与文件版本

项目详情页的“代码”标签页可以直接创建、查看、编辑、重命名和删除模块或静态文件，
也可以用本地文件替换二进制内容、切换文件类型和更改入口模块。编辑器不会就地修改
正在运行的文件：每次保存都会上传新的内容寻址 Blob，校验 SHA-256，然后以当前签名
清单为父版本生成 `version + 1` 的新清单。公共管理后台仍须经过一次性批准；旧版本
保持不可变，可以从部署历史回滚。

单个文件上限为 25 MiB，一次批量更新最多 256 个操作、64 MiB，版本中最多 5000 个
文件。浏览器内只直接打开不超过 5 MiB 的文件；更大的文件仍显示摘要，并允许整体
替换。路径必须是安全的相对路径，不能覆盖 RandallFlare 自动生成的绑定适配模块。
GitHub 来源项目也能紧急编辑，但下一次仓库构建会以仓库内容为准覆盖手工版本，界面会
明确提示这一点。

## ZIP / TAR 导入与可复现导出

“新建 Worker”页面既可以选择一个含 `rf.json` 的完整目录，也可以直接上传 `.zip`、
`.tar`、`.tar.gz` 或 `.tgz`。本地管理后台的路径输入框同样接受目录或上述压缩包。
压缩包可以在最外层多包一层项目目录；除此之外，目录结构与普通 Worker 包完全相同。

节点在内存中展开压缩包，不会把归档路径写入宿主机文件系统。导入最多接受 2,048 个
普通文件、64 MiB 压缩包和 64 MiB 展开内容，路径深度最多 64 层；绝对路径、`..`、
反斜杠、控制字符、符号链接、硬链接、设备文件以及其他 TAR/ZIP 特殊条目都会被拒绝。
展开后仍会执行普通目录部署的 `rf.json`、入口模块、绑定名和保留路径校验。

项目详情页可以导出 ZIP 或 TAR.GZ；API 还接受 `format=tar`。导出会按路径排序，并固定
时间戳、所有者和权限元数据，因此相同 Worker 版本会得到逐字节相同的归档。导出的
`rf.json` 会还原环境变量、所有平台绑定、域名、Cron、兼容性配置和节点约束，模块与
静态资源则从内容寻址 Blob 重新取回并核对大小及 SHA-256。加密 Secret 无论如何都不会
出现在导出包中；重新导入后须单独安全写入 Secret。这是备份和迁移边界，不是 Secret
读取接口。

兼容性日期和标志也属于签名清单，例如：

```json
{
  "name": "frontend",
  "main": "index.js",
  "compatibility_date": "2026-08-04",
  "compatibility_flags": ["nodejs_compat"]
}
```

标志只允许 ASCII 字母、数字、下划线和连字符，不能重复；每个版本最多 128 个。节点
按清单把它们原样写入 workerd 配置，因此可用标志以该 RandallFlare 版本固定的 workerd
版本为准。

## Cron 执行、历史与死信

清单中的 `crons` 使用标准五段表达式。每个有本地运行实例的节点都计算相同的分钟边界，
再通过集群 Claim 为 `(Worker, 表达式, 分钟)` 选出唯一执行者；在网络分区下仍保持与
Cloudflare 一致的至少一次语义。获胜节点不会把内部入口暴露到公网，而是使用每次启动
随机生成、仅存于当前进程的事件令牌调用 workerd 中真正的 `scheduled()` 导出。

每次自动执行最多尝试三次，失败后分别等待 30 秒和 60 秒。每次尝试都会写入该 Worker
独立的 D1 微仲裁数据库，包括计划时间、实际开始/结束时间、节点、HTTP 状态和最多
400 字节的错误摘要。普通记录保留 7 天；耗尽预算的最后一次失败进入 DLQ，保留到管理
员重放或删除。重放只执行一次，并在新记录中链接原 DLQ ID。

控制台的“触发器”页可以手动触发、查看历史和处理 DLQ；CLI 对应命令为：

```bash
rf cron list frontend
rf cron fire frontend --expression '*/5 * * * *'
rf cron list frontend --dlq
rf cron replay frontend <run-id>
rf cron delete frontend <run-id>
```

手动触发指定表达式时，该表达式必须存在于当前签名清单；省略则向 `scheduled()` 发送
`manual`。纯静态 Worker 没有 JavaScript 运行时，因此不能触发 Cron。

## 写入后不可回读的 Secret

Secret 不属于 `rf.json`，也不会混入普通环境变量编辑框。通过 HTTPS 管理后台写入，或
让 CLI 从文件/标准输入读取：

```bash
rf secret put frontend API_TOKEN --from-file ./api-token.txt
printf %s '由密码管理器提供的值' | rf secret put frontend API_TOKEN --from-file -
rf secret list frontend
rf secret delete frontend API_TOKEN
```

`list` 只列出变量名。控制台 GET 接口和 Worker 详情也只返回名称；不存在读取值或读取
密文的管理接口。相同名称再次 `put` 会使用全新随机 nonce 安全替换。

加密流程如下：

1. 从 32 字节集群密钥用 HMAC-SHA-256 和独立域标签派生 Worker Secret 密钥；
2. 用 XChaCha20-Poly1305、随机 24 字节 nonce 加密 UTF-8 值；
3. Worker 名称与绑定名进入 AEAD 附加认证数据，密文不能复制到其他 Worker 或变量名；
4. 只有 nonce 与密文进入操作员签名清单，并随清单在节点间复制；
5. 每个节点启动该 Worker 时才解密，生成的版本目录为 `0700`，临时配置文件为 `0600`；
   workerd 开始监听后立即删除含明文的配置，进程异常退出时再由密文清单重建。

拥有集群密钥和节点主机权限的成员属于同一个信任域，因此能够解密 Secret。若不同工作
负载需要相互隔离，应使用不同 RandallFlare 集群或后续的独立密钥域，而不是把不受信任
节点加入同一集群。公共管理后台在非 HTTPS 模式下拒绝并禁用 Secret 写入。
