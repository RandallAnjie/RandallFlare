# 自定义域名与 DNS 所有权

RandallFlare 的 Workers（静态 Pages 已合并）、R2 公开 bucket、Pipeline、Workflow 与
Flow 共用一套去中心化域名目录。每个节点都从签名资源独立推导同一结果，不依赖中心
账户数据库或 `bigrandall.io`。

节点通过 `ingress.default_domain` 为资源确定性生成默认域名。默认域名属于集群配置，
始终直接生效。业务清单里的自定义域名则必须存在有效的 `hostname_claim` 签名资源，且
该资源已记录成功的 DNS TXT 检查；否则域名只保留在清单中，不加入入口路由，也不会被
ACME 自动发现。撤销声明会立即停止所有引用该域名的公开路由和自动续期。

## CLI 流程

```bash
rf hostname claim api.example.com
# 按输出配置：
# _randallflare-verify.api.example.com TXT
# rf-hostname-verification=<唯一挑战值>

rf hostname verify api.example.com
rf hostname list
```

`verify` 由所连接节点使用系统 DNS 解析器查询 TXT。完全匹配后，CLI 才会用管理员私钥
签署后继版本。私钥不发送给节点，集群密钥和任何 DNS 提供商令牌也不会写入声明。

控制台“域名与证书”页面提供相同流程。公共控制台中的“创建声明”“确认验证”和“撤销”
均分别产生一次短期管理员批准；节点没有私钥，无法自行伪造验证结果。

## DNS 与 HTTPS

所有权 TXT 只证明域名控制权，不承载流量。验证后仍需把业务域名的 A/AAAA 或 CNAME
指向 RandallFlare 公网节点或已配置的轮换目标。若节点启用了 ACME 的资源域名发现，
验证后的域名会进入集群 Claim 选举，由唯一节点执行 DNS-01，证书随后经集群 KV 同步并
热加载。手动证书与配置中显式列出的 ACME 域名仍可独立使用。

声明资源名是域名 SHA-256 的确定性摘要；资源内容再次校验摘要与小写 DNS 主机名，避免
同名替换。热路径以平台资源 KV 的本地代数缓存已验证集合，资源写入或 gossip 合并会使
缓存失效，因此入口请求不需要逐次扫描资源历史。
