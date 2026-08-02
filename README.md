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
- **One product: workers.** A worker = ES modules + an optional
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

Also in: HTTPS ingress (SNI cert store, hot-reload, wildcard files,
self-signed fallback) and **native workerd kvNamespace bindings** —
`env.CACHE.get/put/list` verified against a real workerd binary.

**ACME is claim-driven**: renewal for each hostname is a claimed task —
one node wins, orders via DNS-01 (Cloudflare TXT), and the issued cert
replicates cluster-wide through KV (verified end-to-end against
Let's Encrypt's pebble test server).

**D1 (v0.3 phase 1)**: replicated SQLite over per-database
micro-quorums. Each database gets a rendezvous-hashed 3-node Raft
group — consensus is sharded per object, no node is special. Writes
commit through a majority; killing the leader loses nothing
(e2e-verified). `rf d1 create mydb`, `rf d1 exec mydb "INSERT …"
--params '[…]'` against any node — requests chase the leader
automatically.

**Durable Objects (v0.3 phase 2, groundwork)**: manifests and `rf.json`
can declare native workerd Durable Object namespaces, including SQLite
storage. Local-disk persistence is verified against real workerd across
an rf restart. It is deliberately opt-in (the
`allow_local_durable_objects = true` setting under `[runtime]`) and intended only for a single-node
development cluster until quorum ownership and snapshot replication land;
multi-node execution without fencing would permit split-brain objects.

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
https = "0.0.0.0:443"   # SNI certs from <data_dir>/certs/<host>.crt/.key
                        # (certbot output works; hot-reloaded, wildcard
                        # via _wildcard.<domain>.crt; self-signed
                        # fallback until you drop certs in)

[dns]                                # optional, public nodes
hostname = "edge.example.com"
zone = "example.com"
# my_ipv4 = "203.0.113.7"           # auto-detected when omitted
# token read from $CF_API_TOKEN

[acme]                               # optional: auto-issue TLS certs
email = "you@example.com"
hostnames = ["edge.example.com", "*.edge.example.com"]
# zone/token default to [dns]'s. One node claims each renewal task,
# orders via DNS-01, and the cert replicates to every node's
# <data_dir>/certs through cluster KV.

rf run --config rf.toml
```

As a service: `infra/rf.service` (put `CF_API_TOKEN=…` in `/etc/rf.env`,
config at `/etc/rf.toml`, binary at `/usr/local/bin/rf`).

> The peer API encrypts every remote request and response with
> XChaCha20-Poly1305 using a key derived from the cluster secret. A
> per-request nonce, metadata-bound AEAD, HMAC clock window, and replay
> cache protect worker env, KV, D1, blobs, and snapshots on untrusted
> networks. Only the public `/v1/ping` health check remains plaintext.

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

Durable Object bindings use the exported class name; `unique_key` is
optional and receives a stable deployment-derived value:

```json
{
  "name": "counter",
  "main": "index.js",
  "durable_objects": {
    "COUNTER": { "class_name": "Counter", "enable_sql": true }
  }
}
```

For current single-node development only, enable the safety gate:

```toml
[runtime]
allow_local_durable_objects = true
```
