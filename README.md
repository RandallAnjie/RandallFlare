# RandallFlare

An edge platform with **no control plane**. Every node runs the same
~6 MB static binary (~7 MB RSS at runtime); coordination happens
through gossip, operator-signed manifests, and claim-based (抢单)
scheduling. Built to leave every spare MB of a cheap VPS to V8.

Where Cloudflare decentralizes the data plane and keeps a central
control plane, RandallFlare has neither a center nor special nodes:
deploy to any node and gossip does the rest; kill any node and the
others keep serving (and evict its DNS record via a claimed task).

See [DESIGN.md](./DESIGN.md) for the architecture and consistency
model.

## Status: v0.1 (pre-release)

Working today, verified by a two-node e2e suite:

- SWIM gossip membership (chitchat) + HMAC-authed anti-entropy sync
- Operator-signed worker manifests as a convergent CRDT
- Content-addressed blob sync (modules + static assets)
- **Workers and Pages merged**: a worker = ES modules + an optional
  static asset tree; assets serve natively from every node
- KV: last-write-wins CRDT with HLC, tombstones, TTL, ~gossip-window
  propagation (CF KV consistency contract)
- Claim engine (抢单): signed, HLC-ordered, deterministically
  adjudicated leases — used for cron ticks and DNS reconciliation
- Cron triggers (at-least-once, CF parity)
- DNS self-registration + claimed stray-record cleanup (Cloudflare
  API), with a partition guard
- workerd process supervision (config generation + lifecycle)
- Static stability: nodes boot and serve entirely from local disk
- **Verifiable history**: per-worker manifest hash chain + transparency
  log (`rf log` audits it offline), periodic anchor digests via a
  claimed task (webhook-pluggable to any on-chain relayer), and
  operators can be an **Ethereum wallet** (`rf keygen --eth`,
  `operator = "0x…"`, EIP-191 signatures)

v0.2: TLS/ACME via claims, native workerd kvNamespace bindings,
overlay transport for non-public nodes, self-update on. v0.3:
per-object micro-quorums for D1/Durable Objects.

## Build

```bash
cargo build --release          # → target/release/rf (musl-friendly, no C deps beyond zstd)
cargo test                     # 60 tests incl. a real two-node e2e
```

## Run a cluster

```bash
# once, on your laptop: operator identity + cluster secret
rf keygen

# on every node: rf.toml
data_dir = "/var/lib/rf"
label = "hk-1"
operator = "<operator public key hex>"
cluster_secret = "<same 32-byte hex on every node>"
public = true                        # false = inner node (no DNS/ingress)

[gossip]
listen = "0.0.0.0:7381"
seeds = ["node-a.example.com:7381"]  # any existing node(s); empty on the first

[peer_api]
listen = "0.0.0.0:7382"

[ingress]
http = "0.0.0.0:80"

[dns]                                # optional, public nodes
hostname = "edge.example.com"
zone = "example.com"
my_ipv4 = "203.0.113.7"
# token read from $CF_API_TOKEN

rf run --config rf.toml
```

## Deploy a worker

```bash
my-worker/
  rf.json          # {"name":"site","main":"index.js","assets":"public",
                   #  "hostnames":["site.example.com"],"crons":["*/5 * * * *"],
                   #  "env":{"K":"V"},"kv":{"CACHE":"ns1"}}
  index.js         # omit "main" entirely for a pure static site
  public/…

export RF_NODE=any-node:7382 RF_CLUSTER_SECRET=…
rf deploy ./my-worker            # deploy to one node = deploy to all
rf status
rf kv put ns1 greeting hello
rf worker-delete site
```
