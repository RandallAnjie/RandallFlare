# 设备与出口网络

RandallFlare 的设备网络没有账户中心，也不会把集群密钥交给手机、电脑或路由器。
管理员签名两类可审计资源：分流规则与客户端设备；节点通过加密 Gossip 得到同一份
定义，设备只持有一个随机令牌。资源链仅保存令牌的 SHA-256 和显示前缀，明文在
创建时显示一次，无法找回。

## 1. 数据流与信任边界

设备运行 `rf device proxy`，在回环地址同时提供 SOCKS5 TCP/UDP 与 HTTP 代理。它通过 HTTPS
从任意公共 RandallFlare 节点读取自己的签名配置，然后按规则执行：

- `DIRECT`：由设备本机解析并连接，允许访问设备所在局域网；
- `REJECT` / `REJECT-*`：在本机拒绝；
- `nearest`：并发探测当前 Gossip 中的出口端点，选 TCP 延迟最低者；
- 指定节点：只使用签名配置中固定的节点身份。

跨网段流量采用 TLS 内的 SOCKS5 用户名/密码认证。用户名是设备 ID，密码是
一次性设备令牌。出口节点重新解析目标并重新执行同一份签名规则，所以篡改客户端
不能把出口变成开放代理，也不能绕过设备的规则范围。

本地 UDP 采用标准 SOCKS5 `UDP ASSOCIATE`：应用先保留 TCP 控制连接，再把 RFC 1928
UDP 数据帧发往代理返回的临时回环端口。`DIRECT` 数据报从设备本机发出；指定/最近
出口的数据报则在一次经过认证的 TLS 会话中复用传输。出口对每个数据报重新解析 DNS、
过滤公网地址并执行签名规则，而不是只相信建立会话时的目标。跨节点不额外开放裸 UDP
端口，也不会把设备令牌放进数据报。支持域名、IPv4、IPv6 和最多 65,507 字节载荷；
RFC 1928 的应用层 `FRAG` 分片会明确拒绝。当前每条 association 按顺序完成数据报
往返，DNS 等请求/响应协议可直接使用；高并发 QUIC、实时音视频和多区域吞吐仍需生产
压测后再设定容量指标。出口侧五分钟没有新数据报会回收 TLS association，本地代理在
下一次数据报到来时自动重新认证并建立连接。

出口侧拒绝回环、RFC 1918、CGNAT、链路本地、云元数据、文档/基准、组播、保留地址，
并额外阻断可能把私有 IPv4 编码进去的 NAT64、6to4 与其他转换前缀。DNS 解析在出口
侧完成，实际拨号只使用经过检查的解析结果，避免 DNS 重绑定。

## 2. 启用可选出口节点

普通节点无需启用出口角色，仍可管理、复制和验证规则。选定的出口节点增加：

```toml
[exit]
enabled = true
listen = "0.0.0.0:7443"
advertise = "exit.example.com:7443"
max_sessions = 512
connect_timeout_seconds = 15
```

`advertise` 必须是小写 DNS 主机名和端口，不能使用裸 IP；TLS 客户端需要通过 SNI
选择证书。把 `exit.example.com` 或覆盖它的单层通配符加入 `[acme].hostnames`，或者
把证书对放到：

```text
<data_dir>/certs/exit.example.com.crt
<data_dir>/certs/exit.example.com.key
```

防火墙开放所配置的 TCP 端口。`rf doctor --config /etc/rf.toml` 会检查监听配置、
公开端点和已物化证书，但不会读取或打印私钥内容。节点启用后会通过 Gossip 声明
`exit` 能力与公开端点；没有静态出口目录或中心调度器。

## 3. 创建签名规则

在中文管理后台进入“设备与出口”，可以编辑规则、策略映射和签名快照。CLI 使用完整
`ExitRuleSpec` JSON：

```json
{
  "schema": 1,
  "description": "团队默认分流",
  "enabled": true,
  "priority": 0,
  "format": "surge",
  "config": "DOMAIN-SUFFIX,example.com,Proxy\nIP-CIDR,203.0.113.0/24,REJECT\nFINAL,DIRECT",
  "providers": {},
  "policy_exits": {
    "Proxy": { "type": "nearest" },
    "DIRECT": { "type": "direct" },
    "REJECT": { "type": "reject" }
  }
}
```

```bash
rf exit apply team-default rule.json \
  --node node.example.com:7382 \
  --secret "$RF_CLUSTER_SECRET" \
  --key ~/.rf/operator.key

rf exit list --node node.example.com:7382 --secret "$RF_CLUSTER_SECRET"
```

支持 Surge 的 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、
`IP-CIDR6`、`RULE-SET`、`GEOIP`、`FINAL`，以及 Clash `rules:` / provider
`payload:` 的同类语法。进程、User-Agent 和正则等终端不可可靠观察的规则会被忽略，
绝不会被误解释为兜底规则。

每个非内置策略都必须显式绑定出口；缺少映射会拒绝发布，不能静默降级为 DIRECT。
具体节点的格式为：

```json
{ "type": "node", "node_id": "64位十六进制节点身份" }
```

`RULE-SET` 的 URL 与 `geoip:CC` 只是 `providers` 对象中的键，对应值必须是管理员
审阅过的完整文本快照。设备和出口不会再从 URL 下载内容，因而 GitHub 文件变化、
DNS 劫持或上游失陷不会改变已经签名的行为。更新快照必须发布新的资源版本。

## 4. 注册设备并运行代理

管理后台只允许通过 HTTPS 签发设备令牌。CLI 示例：

```bash
rf device create randall-phone \
  --label "Randall 的手机" \
  --rule team-default \
  --expires-in-days 365 \
  --node node.example.com:7382 \
  --secret "$RF_CLUSTER_SECRET" \
  --key ~/.rf/operator.key
```

把输出的 `rfd_…` 立即写入权限为 `0600` 的文件，不要放入命令行参数、Git、聊天记录
或 shell 历史：

```bash
install -d -m 0700 ~/.rf/devices
umask 077
read -r DEVICE_TOKEN
printf '%s\n' "$DEVICE_TOKEN" > ~/.rf/devices/randall-phone.token
unset DEVICE_TOKEN

rf device proxy \
  --control https://node.example.com \
  --name randall-phone \
  --token-file ~/.rf/devices/randall-phone.token \
  --listen 127.0.0.1:7388
```

浏览器或系统可以把 `127.0.0.1:7388` 同时配置为 SOCKS5 与 HTTP 代理。SOCKS5
客户端可在同一个 TCP 控制入口申请临时 UDP 回环端口；普通 HTTP 代理支持绝对 URL，
HTTPS 使用 `CONNECT`。本地监听必须保持在回环地址；如需为整个
局域网提供代理，应在主机防火墙、身份认证与独立隧道中显式处理，而不是直接暴露此
无认证的本地入口。

每台设备必须明确选择至少一条规则。规则按 `priority` 从小到大、同优先级按资源名
排序，首个匹配项生效。设备记录先于规则抵达新节点时，配置读取和出口认证会失败关闭，
不会临时降级为直连。配置每 30 秒刷新；短暂断网时保留最后一份已验证配置。

## 5. 生命周期与应急处置

```bash
# 暂停，不销毁令牌
rf device configure randall-phone --suspended \
  --node node.example.com:7382 --secret "$RF_CLUSTER_SECRET" \
  --key ~/.rf/operator.key

# 永久撤销；不能重新启用
rf device revoke randall-phone \
  --node node.example.com:7382 --secret "$RF_CLUSTER_SECRET" \
  --key ~/.rf/operator.key

# 删除签名定义
rf device delete randall-phone \
  --node node.example.com:7382 --secret "$RF_CLUSTER_SECRET" \
  --key ~/.rf/operator.key
```

暂停、撤销、到期与删除会在下一次配置请求以及每次出口 SOCKS 握手时独立检查。
撤销记录进入签名哈希链；已撤销设备不能恢复。如果令牌遗失但仍需同名设备，先删除
旧定义，再使用新的设备 ID 注册，以免把旧历史与新身份混淆。

客户端设备、出口规则与其他平台资源使用同一套管理员签名审批。设备令牌摘要在通用
资源 API、管理列表和安全审计中都被隐藏；出口节点的 TLS 私钥、集群密钥、rclone
凭据及邮件密钥始终只存在节点本地。
