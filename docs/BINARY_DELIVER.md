# Binary Deliver

Binary Deliver 允许 Worker 调用受管理员签名约束的 Linux 原生程序。它不是一个可以
随意执行宿主命令的 shell：程序内容、目标架构、资源上限、节点要求以及网络和 R2
权限都进入可验证的资源历史，每次调用都会重新检查当前 Worker 清单和 Binary 定义。

## 创建与绑定

在管理员设备上传文件；省略 `--rclone-remote` 时，内容进入本地内容地址存储并可从
已认证的集群节点按需修复：

```bash
export RF_NODE=节点地址:7382
export RF_CLUSTER_SECRET='64位十六进制集群密钥'
export RF_OPERATOR_KEY=~/.rf/operator.key

rf binary upload ffmpeg ./ffmpeg \
  --description '音视频转码' \
  --default-timeout-ms 30000 \
  --max-stdin-bytes 10485760 \
  --max-output-bytes 10485760 \
  --allow-r2
```

使用 rclone 时，remote 凭据只存在于节点本地的 rclone 配置中，不进入签名资源：

```bash
rf binary upload ffmpeg ./ffmpeg \
  --rclone-remote archive \
  --rclone-prefix randallflare/binaries
```

也可在中文管理后台的“Binary Deliver”页面上传和编辑策略。公开控制台会生成一次性
批准请求；节点不接触管理员私钥。

在 `rf.json` 中把资源绑定到 Worker：

```json
{
  "name": "media-worker",
  "main": "index.js",
  "binaries": {
    "FFMPEG": "ffmpeg"
  },
  "r2_buckets": {
    "OUTPUTS": "media-output"
  }
}
```

## Worker API

```js
export default {
  async fetch(request, env) {
    const result = await env.FFMPEG.exec({
      args: ["-version"],
      stdin: "可选的 UTF-8 输入",
      // 二进制输入改用 stdinBase64；也可传 Uint8Array/ArrayBuffer，包装层会编码。
      timeoutMs: 10_000,
      env: { LANG: "C.UTF-8" },
      outputFiles: [
        {
          path: "result.mp4",
          bucket: "OUTPUTS",
          key: "jobs/123/result.mp4",
          contentType: "video/mp4"
        }
      ]
    });
    return Response.json(result);
  }
};
```

返回值包含 `ok`、`exitCode`、`stdout`、`stderr`、截断标记、`durationMs`、超时状态和
各个 R2 输出文件的独立结果。非 UTF-8 输出使用 `stdoutBase64` 或 `stderrBase64`。
R2 输出只允许写入调用 Worker 已绑定的 bucket；路径会经过规范化和符号链接逃逸
检查。

## 安全边界

- 只接受 workerd 发往回环绑定服务的请求，并校验来源 Worker 与 binding 名称。
- 按 SHA-256 验证上传、远端读取、缓存与修复内容；缓存文件权限为 `0500`。
- 每次执行创建新的 bubblewrap 命名空间和私有工作目录；不挂载节点数据目录、配置、
  集群密钥或宿主 `/etc`。
- 默认创建独立网络命名空间。只有 Binary 的 `allow_network` 和集群出站策略同时允许，
  才共享节点网络。
- 环境变量默认清空。`BD_` 前缀由平台保留，用来传递可信的 Worker、Binary、摘要和
  临时目录身份。
- 参数数量和长度、stdin、stdout、stderr、执行时间和输出文件数量都有硬上限；达到
  时间或输出上限会终止整个进程。
- 定义指定的节点标签和目标架构必须匹配；节点只有检测到 bubblewrap 时才上报
  `binary` 系统能力。
- 仍被任何有效 Worker 清单引用的 Binary 无法删除。先移除 Worker binding，再写入
  Binary 墓碑。

## 策略变更与暂停

不替换文件即可修改策略；未给出的 CLI 选项会保留当前值：

```bash
rf binary configure ffmpeg --allow-network=false --suspended=true
rf binary configure ffmpeg --suspended=false --clear-required-tags
```

策略更新不需要重新部署 Worker。绑定服务在每次 `exec()` 时读取最新签名定义，所以
暂停、节点标签和权限变更立即生效。删除和所有更新都会进入同一条防回滚哈希链。
