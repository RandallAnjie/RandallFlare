# Worker 绑定与加密 Secret

RandallFlare 将脚本 Worker 与静态 Pages 统一为同一种签名部署单元。一个项目可以只有
模块、只有静态资源，也可以同时包含两者；域名、版本、代码源、构建结果和所有平台绑定
都由同一条可验证清单历史管理。

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
