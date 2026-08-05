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

## Status: v0.9.0 (pre-release)

Working today, verified by multi-process fault-injection e2e tests:

- SWIM gossip membership (chitchat) + HMAC-authed anti-entropy sync
- Operator-signed worker manifests as a convergent CRDT
- Content-addressed blob sync (modules + static assets)
- **One product: workers.** A worker = ES modules + an optional
  static asset tree; assets serve natively from every node
- KV: last-write-wins CRDT with HLC, tombstones, TTL, ~gossip-window
  propagation (CF KV consistency contract), metadata/bulk reads, cursor
  pagination, and binary-safe bounded console import/export
- Claim engine (抢单): signed, HLC-ordered, deterministically
  adjudicated leases — used for cron ticks and DNS reconciliation
- **Durable Cron triggers**: signed five-field schedules are claim-deduplicated
  across live runtimes, invoke the real workerd `scheduled()` export through a
  process-random internal token, retry failures after 30/60 seconds, and retain
  attempts plus DLQ/replay state in a per-Worker D1 micro-quorum. History,
  manual fire, replay and DLQ deletion are available in CLI and Chinese UI.
- DNS self-registration + claimed stray-record cleanup (Cloudflare
  API), with a partition guard
- workerd process supervision (config generation + lifecycle)
- Static stability: nodes boot and serve entirely from local disk
- **Verifiable history**: per-worker manifest hash chain + transparency
  log (`rf log` audits it offline), periodic anchor digests via a
  claimed task (webhook-pluggable to any on-chain relayer), and
  operators can be an **Ethereum wallet** (`rf keygen --eth`,
  `operator = "0x…"`, EIP-191 signatures)
- **Decentralized management console**: an unmatched/default ingress hostname
  opens the responsive admin UI directly. Operator-signed, stateless sessions
  are independently verified by every node; there is no account database or
  central authentication service. Worker changes use one-time CLI approval so
  operator private keys never live on nodes or in browsers.
- **Git-native Worker delivery**: connect a public or private GitHub repository,
  select a branch and monorepo root, run zero-config or bubblewrap-sandboxed
  builds, watch live logs, approve the exact output Manifest, and observe its
  rollout on every node. Push webhooks, immutable build history, runtime logs,
  and signed rollback are built in. Repository settings are operator-signed and
  replicated; tokens and build processes stay node-local.
- **Signed preview environments**: every immutable Worker history version can
  run at `v<version>-<worker>.<default_domain>` without advancing production.
  Verified GitHub Pull Request events build the exact head commit into
  `pr<number>-<worker>.<default_domain>`. Previews require operator approval,
  use isolated runtime/DO directories, expire independently on every node and
  are removed with signed tombstones. See [the preview guide](./docs/PREVIEWS.md).
- **Privacy-bounded request observability**: each ingress node batches Worker
  method, path, hostname, status and duration into its own redb state, retains
  seven days, and exposes only encrypted peer snapshots. The Chinese console
  merges all live nodes, labels runtime output by node, filters requests by
  hostname/status and renders a 24-hour status trend. Query strings, headers,
  bodies, cookies, client IPs and User-Agent values are never collected. See
  [the observability guide](./docs/OBSERVABILITY.md).
- **Signed node placement and draining**: authenticated system capabilities,
  operator-signed region/custom tags, per-Worker required tags and live
  deployment states form a decentralized scheduler. An ineligible public
  ingress forwards the exact immutable revision through the encrypted peer
  transport to an eligible ready node, where placement is verified again.
  Drain/suspend policies also remove nodes from DNS rotation, while previews
  and initial Durable Object quorum selection obey the same requirements. See
  [the node placement guide](./docs/NODES.md).
- **Cluster-wide security policy and scoped automation**: operator-signed
  quotas cover Worker count/size, custom hostnames, aggregate R2 objects/local
  bytes, request rate and Worker outbound networking. Personal API tokens are
  one-way SHA-256 credentials with exact read/write scopes, optional expiry and
  signed revocation; raw values are displayed once. The cookie-free `/api/v1`
  surface spans Workers, KV, D1, R2, Queues, Analytics, Pipelines, Workflows,
  Flows, Email, nodes and the transparency log. See
  [Security, API and S3 access](./docs/SECURITY_API.md).
- **R2-compatible object storage**: operator-signed buckets, per-bucket D1
  metadata quorums, content-addressed local replicas or node-local rclone
  remotes, quotas, metadata, ranges, conditions, delimiter listing,
  multipart upload, paged in-flight upload/part administration, lifecycle expiry
  and delayed reference-safe collection.
  Stock workerd receives native `R2Bucket` bindings; public buckets get
  `r2-<bucket>.<default_domain>` plus optional custom hostnames, CORS and
  ETag/Range-aware object delivery. Operator-signed, revocable S3 credentials
  support full-account or per-bucket read/write grants through the path-style
  Signature V4 endpoint at `/s3`, including multipart upload. Secret Access
  Keys are sealed cluster-wide and shown only once.
- **Signed zero-migration storage sharding**: policy-backed R2 buckets select
  an ordered rclone remote from the first 32 bits of each SHA-256 and persist
  the concrete remote/prefix per object and multipart part. Adding drives only
  changes future writes; old bytes remain pinned, destructive remote removal
  is rejected while references exist, and the Chinese console probes every
  live node and reports physical distribution. See
  [the storage-policy guide](./docs/STORAGE_POLICY.md).
- **Decentralized Queues**: operator-signed queue definitions and independent
  D1 micro-quorum ledgers provide delayed JSON/V8-compatible, UTF-8 text and
  binary messages, batches, visibility leases, bounded retries, durable dead
  letters and type-preserving redrive. Pausing stops consumption while keeping
  producer writes durable. Workers produce with `env.EVENTS.send()/sendBatch()`
  and consume with `queue(batch, env, context)`; real-workerd tests cover
  automatic acknowledgement, retry, dead-letter transitions and typed bodies.
  See [the Queues guide](./docs/QUEUES.md).
- **Decentralized Analytics Engine**: operator-signed datasets retain the
  Cloudflare-shaped `blobs` / `doubles` / `indexes` data-point model in an
  independent D1 micro-quorum. Workers call `env.METRICS.writeDataPoint()`;
  signed dataset CRUD, encrypted node APIs, recent-event browsing, hour/day
  counters, dimension/value aggregations and a bounded read-only SQL workbench
  over the flattened `events` view are available in the CLI, scoped API and
  Chinese console. The binding's `waitUntil` path and SQL aggregation are
  verified against real workerd. See [the Analytics guide](./docs/ANALYTICS.md).
- **Durable Pipelines**: authenticated JSON, JSON-array, NDJSON and plain-text
  ingest is JSON-Schema validated and committed to a per-Pipeline D1 quorum
  before delivery. Optional bounded, read-only SQL filters, projects and
  computes over the per-request `events` table using either `SELECT` or
  `INSERT INTO <sink> SELECT` syntax. Quorum leases produce deterministic,
  retry-safe gzip JSONL batches in R2, including buckets backed by rclone. Only
  bearer-token hashes are signed; plaintext is shown once. Public/custom ingest
  domains, automatic TLS discovery, Worker `env.ARCHIVE.send()`, SQL transforms,
  status/batch audit, CLI and the Chinese console are covered by real-workerd
  and public-ingress tests. See [the Pipeline guide](./docs/PIPELINES.md).
- **Privacy-preserving data audit**: KV keys/values and D1 SQL/parameters never
  enter the audit log; deterministic mutation proofs merge across live nodes
  and can be archived as gzip JSONL into local or rclone-backed R2. See
  [the data audit guide](./docs/DATA_AUDIT.md).
- **Durable Workflows**: operator-signed definitions use an independent D1
  micro-quorum for idempotent instances, replay logs, external signals and an
  append-only audit trail. Export a `WorkflowEntrypoint` from the same Worker;
  `step.do()` commits JSON results exactly once across replays, while
  `sleep()` / `sleepUntil()` and `waitForSignal()` park without occupying a
  process. Fenced five-minute leases, minute heartbeats, bounded system retry,
  pause/resume/terminate/restart, retention GC, definition-pinned instances,
  atomic concurrency caps, UTC Cron and token-authenticated Webhook triggers,
  Worker bindings, encrypted API, CLI and the Chinese instance/step timeline
  are exercised against real workerd. See [Workflow guide](./docs/WORKFLOWS.md).
- **Visual durable Flows**: a dedicated Chinese management page combines a
  draggable DAG canvas, node inspector, signed settings, one-time Webhook
  tokens and run/step/audit views. Manual, Cron and public Webhook triggers
  execute from version-frozen graphs in per-Flow D1 quorums with fenced
  leases, recovery, idempotency, cancellation, retry, retention and durable
  loop iterations. Worker, HTTP, KV, D1, R2, Queue, Analytics, Pipeline,
  Workflow and inline sub-Flow nodes share typed templates and cross-node
  outputs. Public Flow domains support asynchronous 202 responses or
  request/response mode with `?wait=1`; credentials remain node-local and
  outbound HTTP is protected against SSRF. See [the Flow guide](./docs/FLOWS.md).
- **Optional decentralized Email**: operator-signed domains define exact,
  prefix and catch-all routes to Workers, reliable forwards or drops. Selected
  MX nodes receive SMTP with optional STARTTLS, authenticate inbound RFC 822
  with SPF/DKIM/DMARC/ARC, archive immutable source in ordinary local or
  rclone-backed R2, and dispatch through fenced D1 leases. Outbound mail is
  durably queued per recipient, DKIM-signed using node-local keys, delivered
  directly to sorted MX targets with SMTPUTF8, opportunistic TLS, and RFC 8461
  MTA-STS discovery, durable policy caching, MX matching and strict STARTTLS
  enforcement. Permanent failure creates a crash-safe, loop-protected DSN
  through the sender's signed local route.
  Worker `email()` handlers, `env.MAIL.send()`, Flow email nodes, CLI/API,
  retention cleanup, encrypted audit API/CLI and a dedicated Chinese
  DNS/routing/delivery timeline are included. See [the Email guide](./docs/EMAIL.md).
- **Decentralized device and exit networking**: one-way device credentials
  fetch operator-signed Surge/Clash rules without exposing the cluster secret.
  A local SOCKS5/HTTP proxy performs DIRECT and REJECT decisions or opens a
  TLS-authenticated SOCKS tunnel to a specific/live-nearest exit. Exit nodes
  re-evaluate the same signed policy and resolve destinations themselves with
  strict private, metadata, transition-prefix and reserved-address SSRF
  blocking. Remote rule-set and GEOIP content is frozen into the signed
  resource, while exit roles remain optional node-local capabilities. CLI and
  a dedicated Chinese management page are included. See
  [the device and exit guide](./docs/DEVICE_EXIT.md).

Also in: HTTPS ingress (SNI cert store, hot-reload, wildcard files,
self-signed fallback) and **native workerd kvNamespace bindings** —
`env.CACHE.get/put/list` verified against a real workerd binary.

**ACME is claim-driven**: renewal for each hostname is a claimed task —
one node wins, orders via DNS-01 (Cloudflare TXT), and the issued cert
replicates cluster-wide through KV (verified end-to-end against
Let's Encrypt's pebble test server).

**D1**: replicated SQLite over per-database
micro-quorums. Each database gets a rendezvous-hashed 3-node Raft
group — consensus is sharded per object, no node is special. Writes
commit through a majority; killing the leader loses nothing
(e2e-verified). `rf d1 create mydb`, `rf d1 exec mydb "INSERT …"
--params '[…]'` against any node — requests chase the leader
automatically. Mixed read/write batches are one replicated SQLite transaction;
the Chinese console browses schema/rows/metrics, imports bounded SQL files and
downloads a portable online-backup snapshot from the current leader. Manual and
operator-signed scheduled backups write verified SQLite snapshots directly to
R2—including fixed or sharded rclone buckets—with multipart upload and retention
cleanup. See [the D1 guide](./docs/D1.md).

Worker manifests can bind a database with `"d1": {"DB":"mydb"}`.
The runtime exposes the familiar `env.DB.prepare(...).bind(...).all()/first()/run()/raw()`,
plus `exec()`, `batch()` and `withSession()`, while every operation is routed
to the database's current quorum leader.

**Durable Objects (v0.3 phase 2)**: native workerd namespaces and SQLite
storage run under a per-Worker 3-node micro-quorum. Only the epoch-fenced
owner runs workerd; every other ingress forwards to it. Before a response
is acknowledged, rf checkpoints and compresses the DO SQLite directory and
commits it to a majority. Killing the owner elects another node, restores
the committed snapshot on its independent disk, and continues without
losing acknowledged state (real three-node workerd e2e).
Native alarms retain `retryCount`/`isRetry` across process recovery. Ordinary
and hibernatable DO WebSockets preserve the real HTTP upgrade; cross-node
connections use an authenticated, sequence-bound XChaCha20-Poly1305 tunnel and
reconnect to restored state after owner loss. The pinned `workerd 2026-08-04`
test matrix covers namespace/ID/stub RPC, asynchronous and synchronous KV,
SQLite cursors and transactions, state/concurrency methods, alarm controls and
the Hibernation metadata/automatic-response surface. Cloudflare-only
jurisdiction enforcement and 30-day PITR are recorded as explicit differences,
not simulated guarantees. See
[the Durable Objects guide](./docs/DURABLE_OBJECTS.md).

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
default_domain = "workers.example.com" # every Worker gets
                                       # <worker>.workers.example.com

[dns]                                # optional, public nodes
hostname = "edge.example.com"
zone = "example.com"
# my_ipv4 = "203.0.113.7"           # auto-detected when omitted
# token read from $CF_API_TOKEN

[acme]                               # optional: auto-issue TLS certs
email = "you@example.com"
hostnames = ["edge.example.com", "*.edge.example.com"]
include_worker_hostnames = true      # exact Worker domains inside zone
dns_propagation_seconds = 20         # wait before asking the CA to validate
# zone/token default to [dns]'s. One node claims each renewal task,
# orders via DNS-01, and the cert replicates to every node's
# <data_dir>/certs through cluster KV.

[update]                             # optional self-update from releases
enabled = false                      # hardened service uses external upgrades
# repo = "RandallAnjie/RandallFlare"
# interval_minutes = 30

[build]                              # Git-backed Workers
enabled = true
git = "/usr/bin/git"
sandbox = "/usr/bin/bwrap"          # mandatory for custom build commands
github_token_env = "RF_GITHUB_TOKEN" # optional, private repositories only
github_app_id_env = "RF_GITHUB_APP_ID"
github_app_private_key_env = "RF_GITHUB_APP_PRIVATE_KEY_B64"
github_app_webhook_secret_env = "RF_GITHUB_APP_WEBHOOK_SECRET"
# github_ssh_key = "/etc/rf-github-deploy-key"       # mode 0600
# github_known_hosts = "/etc/rf-github-known-hosts" # pinned github.com keys
timeout_seconds = 1200

[storage]                            # optional rclone-backed R2 buckets
# local_dir = "/var/lib/rf/objects" # default shown; content-addressed
# rclone_binary = "/usr/bin/rclone" # set both lines to enable rclone
# rclone_config = "/etc/rclone/rclone.conf" # keep mode 0600, never commit
# rclone_timeout_seconds = 1800

[email]                              # optional SMTP-capable node role
enabled = false                      # ordinary nodes leave this false
# smtp_listen = "0.0.0.0:25"
# mx_hostname = "mx1.example.com"   # also the cert stem and signed MX target
# outbound = true

[exit]                               # optional TLS device-exit role
enabled = false                      # rules/devices can be managed everywhere
# listen = "0.0.0.0:7443"
# advertise = "exit.example.com:7443" # DNS hostname required for TLS SNI
# max_sessions = 512
# connect_timeout_seconds = 15
# max_sessions = 32

rf run --config rf.toml
```

`ingress.default_domain` does not create central allocation state or modify a
Worker's signed manifest. Every node derives the same hostname from the Worker
name, and the deterministic default route is reserved for that Worker. Point a
wildcard DNS record and certificate at the public nodes once; custom domains can
still be attached through signed Worker settings.

The same wildcard also covers public object buckets: bucket `assets` receives
`r2-assets.workers.example.com`. Bucket definitions replicate only a remote
name and path prefix. Provider credentials stay exclusively in each node's
`rclone_config`; `rf doctor` verifies the binary and config without printing
their contents.

For many rclone drives, create one signed global shard policy and opt new R2
buckets into it. Credentials are still node-local:

```bash
rf storage configure --new-bucket-backend rclone-sharded \
  --remote drive-00 --remote drive-01 --shard-prefix randallflare/objects
rf storage probe
rf r2 bucket-create assets --storage-policy --public
```

Each object's concrete shard remains in its D1 metadata, so policy expansion
requires no byte migration. Operational details and safe remote retirement are
covered in [rclone storage policy and sharding](./docs/STORAGE_POLICY.md).

For a systemd deployment, prefer `infra/install-release.sh`; it downloads the
GitHub Actions artifact directly on the VPS and verifies its checksum. The
lower-level `infra/install.sh` and local-development `infra/deploy-vps.sh` are
also available.
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
> accepted by current nodes.

## Management console

Open any public node directly; when no Worker owns the request hostname, ingress
serves the RandallFlare management interface:

```text
http://203.0.113.7/
```

The page shows a one-time code. Approve it from an operator machine using the
same GitHub Release binary:

```bash
export RF_NODE=203.0.113.7:7382
export RF_CLUSTER_SECRET="<cluster secret>"
export RF_OPERATOR_KEY="$PWD/first-vps/operator.key"
rf authorize ABC12-DEF34
```

The CLI fetches the exact challenge through the encrypted peer API and signs it
with the operator key. The resulting HttpOnly, SameSite session contains an
operator-signed grant rather than a centrally stored session ID, so every node
can validate it independently. KV and D1 operations use that grant directly.
Worker deploy/delete requests prepare a canonical manifest and display another
one-time code; `rf authorize <code>` signs that exact manifest before it can
enter the transparency log.

### GitHub builds

Open **Workers → Connect a GitHub repository**. The signed source record covers
the repository, branch, monorepo root, build command, output directory, private
token policy, and webhook policy. A zero-config source uses the selected output
directory as-is; it must contain `rf.json`. A custom command always executes in
`bubblewrap` with only the checkout writable and no RandallFlare credentials in
its environment.

For a private repository, prefer a GitHub App with read-only Contents and
read/write Checks plus Issues permissions. Put its App ID, base64-encoded PEM
private key and webhook HMAC secret in the build node environment:

```bash
RF_GITHUB_APP_ID=123456
RF_GITHUB_APP_PRIVATE_KEY_B64="$(base64 -w0 app.private-key.pem)"
RF_GITHUB_APP_WEBHOOK_SECRET="$(openssl rand -hex 32)"
```

Set the App callback to
`https://<management-domain>/api/webhooks/github-app` and subscribe to Push and
Pull request events. Installation tokens are minted per build, held only in
zeroizing memory, and are never persisted or replicated. PR previews update a
Check Run and one stable Chinese status comment without publishing the
RandallFlare approval code.

As a compatibility fallback, a read-only personal token can still be placed in
the environment of the build node:

```bash
RF_GITHUB_TOKEN=github_pat_…
```

For a repository-scoped SSH deploy key, use a `git@github.com:owner/repo.git`
source and configure both `build.github_ssh_key` and
`build.github_known_hosts`. RandallFlare requires the key file to be mode 0600,
sets `IdentitiesOnly`, and always keeps strict host-key verification enabled.

The console shows a per-Worker webhook URL and derived HMAC secret. Configure a
GitHub repository webhook for the push event and, when Pull Request previews
are enabled, the pull request event, with content type `application/json`.
Any cluster node can receive a verified event and build; the result still waits
for `rf authorize <code>` before production deployment or preview publication.
After approval, content-addressed blobs and the signed Manifest/resource
distribute peer-to-peer. See [PREVIEWS.md](./docs/PREVIEWS.md) for deterministic
domains, expiry and the preview data-access boundary.

Use HTTPS before treating a public management session as production-safe. The
first-VPS HTTP address is suitable for isolated testing, but HTTP cannot protect
session cookies from an on-path observer.

The loopback-only console remains available as an offline/emergency path:

```bash
rf console                         # http://127.0.0.1:7390
```

## Deploy a worker

```bash
my-worker/
  rf.json          # {"name":"site","main":"index.js","assets":"public",
                   #  "hostnames":["site.example.com"],"crons":["*/5 * * * *"],
                   #  "env":{"K":"V"},"kv":{"CACHE":"ns1"},
                   #  "r2":{"OBJECTS":"assets"},"d1":{"DB":"mydb"},
                   #  "queues":{"EVENTS":"events"},
                   #  "analytics":{"METRICS":"web-metrics"},
                   #  "pipelines":{"ARCHIVE":"event-archive"},
                   #  "workflows":{"ORDER_FLOW":"order-flow"},
                   #  "email":{"MAIL":"support-mail"},
                   #  "services":{"BACKEND":"api-worker"},
                   #  "binaries":{"FFMPEG":"ffmpeg"},
                   #  "compatibility_flags":["nodejs_compat"]}
  index.js         # omit "main" entirely for a pure static site
  public/…

export RF_NODE=any-node:7382 RF_CLUSTER_SECRET=…
rf deploy ./my-worker            # deploy to one node = deploy to all
# The console also imports ZIP/TAR/TAR.GZ and exports reproducible archives.
# Exported rf.json files retain bindings but intentionally omit write-only Secrets.
rf status
rf kv put ns1 greeting hello
rf kv list ns1 --prefix greet
rf kv delete ns1 greeting
rf d1 import mydb ./dump.sql
rf d1 export mydb --output ./mydb.sqlite
rf cron list site
rf cron fire site --expression '*/5 * * * *'
rf cron list site --dlq
rf cron replay site <run-id>
rf requests site --hostname site.example.com --status-class 5
rf binary upload ffmpeg ./ffmpeg --allow-r2
rf binary configure ffmpeg --allow-network=false --suspended=false
rf binary list
rf worker-delete site
```

Worker-to-Worker Service bindings are node-local capabilities backed by the
signed manifest. A module Worker calls `await env.BACKEND.fetch(request)`; the
loopback adapter rechecks that the caller is allowed to reach the named target
and resolves the target's current workerd port after every restart.

Sensitive values use encrypted Secret bindings rather than `env` in
`rf.json`. The console shows names only. The CLI also never accepts a value on
the command line:

```bash
printf %s 'value-from-a-password-manager' | rf secret put site API_TOKEN --from-file -
rf secret list site
rf secret delete site API_TOKEN
```

The first command encrypts the value with XChaCha20-Poly1305 before signing the
new manifest. Nodes decrypt it only into a mode-`0600` temporary workerd config
and remove that plaintext file as soon as workerd is listening.
Use HTTPS for the public console; the UI disables Secret writes on public HTTP.
See [Worker bindings and encrypted Secrets](./docs/WORKERS.md).
KV consistency, metadata, paging and migration are documented in
[去中心化 KV](./docs/KV.md).
D1 quorum consistency, atomic batches, schema inspection, SQL import and
portable SQLite snapshots are documented in [去中心化 D1](./docs/D1.md).

Binary Deliver definitions are signed and hash chained while their bytes are
content addressed on local replicas or an operator-selected rclone remote.
`env.FFMPEG.exec()` verifies the calling Worker and current Binary policy on
every invocation, then starts a fresh bubblewrap namespace with no host
filesystem and no network by default. See
[Binary Deliver](./docs/BINARY_DELIVER.md).

The project “Code” tab edits module and static files without mutating an old
deployment. Every save verifies content hashes and creates a new signed,
hash-chained manifest, so the change follows the same approval, distribution
and rollback path as a CLI or GitHub deployment. Binary files can be replaced
as whole files; large files remain metadata-only in the browser.

Workflow classes import RandallFlare's built-in runtime module; no npm package
or central orchestrator is required:

```js
import { WorkflowEntrypoint } from "randallflare:workers";

export class OrderWorkflow extends WorkflowEntrypoint {
  async run(input, step) {
    const order = await step.do("prepare", () => createOrder(input));
    await step.sleep("payment-window", "10 minutes");
    const payment = await step.waitForSignal("paid");
    return await step.do("confirm", () => confirmOrder(order, payment));
  }
}
```

Create the signed definition, trigger it with an idempotency key, and inspect
the durable timeline from any node:

```bash
rf workflow create order-flow --worker site --entrypoint OrderWorkflow
rf workflow trigger order-flow --idempotency-key order-1001 --input '{"orderId":"1001"}'
rf workflow instances order-flow
rf workflow signal order-flow <instance-id> paid --payload '{"method":"card"}'
```

Webhook plaintext is shown only once and only its SHA-256 verifier enters the
signed definition. The deterministic default endpoint is
`https://workflow-order-flow.<default-domain>/hook`:

```bash
rf workflow token-create order-flow --label production
rf workflow create order-flow --worker site --entrypoint OrderWorkflow \
  --webhook --cron '0 * * * *' --max-concurrent-instances 16
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
