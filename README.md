# RandallFlare

An edge platform with **no control plane**. Every node runs the same
~12 MB release binary (7–10 MB idle RSS on x86_64 Linux); coordination happens
through gossip, operator-signed manifests, and claim-based (抢单)
scheduling. Built to leave every spare MB of a cheap VPS to V8.

Where Cloudflare decentralizes the data plane and keeps a central
control plane, RandallFlare has neither a center nor special nodes:
deploy to any node and gossip does the rest; kill any node and the
others keep serving (and evict its DNS record via a claimed task).

See [DESIGN.md](./DESIGN.md) for the architecture and consistency
model. For a repeatable first-server rollout, use the
[VPS deployment runbook](./docs/DEPLOYMENT.md).

## Status: v0.3 (pre-release)

Working today, verified by multi-process fault-injection e2e tests:

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

**Durable Objects (v0.3 phase 2)**: native workerd namespaces and SQLite
storage run under a per-Worker 3-node micro-quorum. Only the epoch-fenced
owner runs workerd; every other ingress forwards to it. Before a response
is acknowledged, rf checkpoints and compresses the DO SQLite directory and
commits it to a majority. Killing the owner elects another node, restores
the committed snapshot on its independent disk, and continues without
losing acknowledged state (real three-node workerd e2e).

## Build

```bash
cargo build --release          # → target/release/rf (musl-friendly, no C deps beyond zstd)
cargo test                     # unit, chaos, and real multi-process e2e tests
```

Tagged releases build a static `x86_64-unknown-linux-musl` artifact named
`rf-linux-x86_64` plus its `.sha256` sidecar. Those names are also the
self-updater's contract.

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
advertise = "203.0.113.7:7381"       # dialable public/overlay address
seeds = ["node-a.example.com:7381"]  # any existing node(s); empty on the first

[peer_api]
listen = "0.0.0.0:7382"
advertise = "203.0.113.7:7382"

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

[update]                             # optional self-update from releases
enabled = false                      # hardened service uses external upgrades
# repo = "RandallAnjie/RandallFlare"
# interval_minutes = 30

rf run --config rf.toml
```

For a systemd deployment, use `infra/deploy-vps.sh` or `infra/install.sh`.
The supplied unit runs as an unprivileged `rf` user; config and environment
files are `root:rf` mode `0640`. See the
[deployment runbook](./docs/DEPLOYMENT.md) for firewall, credentials,
installation, smoke testing, and upgrades.

> Gossip datagrams and every peer API request/response are encrypted with
> XChaCha20-Poly1305 using a key derived from the cluster secret. A
> per-request nonce, metadata-bound AEAD, HMAC clock window, and replay
> cache protect worker env, KV, D1, blobs, and snapshots on untrusted
> networks. Only the public `/v1/ping` health check remains plaintext.
> Transport v2 binds captured requests to the intended node identity;
> upgrade all nodes together because older plaintext/v1 peers are not
> accepted by a v0.3 node.

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
rf kv list ns1 --prefix greet
rf kv delete ns1 greeting
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

Distributed quorum ownership is the default. For isolated development
only, the local-disk escape hatch bypasses quorum fencing:

```toml
[runtime]
allow_local_durable_objects = true
```
