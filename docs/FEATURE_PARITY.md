# RandallFlare feature-parity ledger

This ledger maps the RandallFlare surface in `bigrandall.io` to the
control-plane-less implementation in this repository. It is an acceptance
contract, not a marketing roadmap. A row is complete only when its API,
Worker binding, Chinese console UI, recovery behaviour, security boundary,
documentation, and end-to-end tests all pass.

Pages is intentionally not a separate product here. A Worker deployment may
contain modules, static assets, or both; an assets-only Worker is the Pages
equivalent and keeps the same domains, previews, Git history, bindings, logs,
and rollback model.

## Architectural translation

The reference implementation stores desired state in a central PostgreSQL
"plane" and lets agents poll it. RandallFlare replaces every such row with one
of four decentralized primitives:

| Reference responsibility | RandallFlare primitive |
| --- | --- |
| desired configuration | operator-signed, hash-chained resource records replicated through encrypted anti-entropy |
| immutable files | SHA-256 blobs on local replicas or an operator-selected rclone remote |
| eventually consistent data | HLC/LWW KV CRDT |
| non-mergeable mutable data | per-resource three-node micro-quorum |
| singleton/reconciliation work | signed expiring claims; all work is idempotent |
| user/account authorization | offline operator signatures and stateless browser grants |
| node eligibility | signed capability requirements matched against node-local capabilities |
| credentials | node-local environment/config only; never replicated in a resource record |

## Parity matrix

Legend: **done** is deployed and exercised on the test VPS; **partial** exists
but lacks part of the reference surface; **planned** has no complete public
surface yet.

### Nodes, security, and operations

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| encrypted membership and peer API | done | multi-VPS production soak |
| public/inner nodes, DNS rotation, TLS/ACME | done | multi-provider DNS adapters |
| decentralized browser authentication | done | hardware-wallet browser approval UX |
| signed audit/transparency history | partial | include every platform resource and mutation |
| node tags, placement requirements, drain/suspend | planned | signed capability declarations and routing fallback |
| topology, quotas, request metrics, DLQ | planned | replicated counters and retention policies |
| access tokens and scoped API credentials | planned | signed grants, revocation and least-privilege scopes |
| device/exit networking | planned | capability-tagged exits and encrypted tunnel enrolment |

### Workers (including Pages)

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| modules + static assets in one deploy unit | done | — |
| browser upload and CLI deploy | done | archive editor and per-file editing |
| GitHub source, sandboxed build, webhook deploy | done | GitHub App auth, PR checks/comments, SSH deploy keys |
| versions, hash-chain audit and rollback | done | version-pinned preview aliases |
| default/custom domains and wildcard TLS | done | custom-domain DNS ownership workflow |
| environment, KV bindings, Cron | done | KV metadata + bulk get verified; secret-value encryption and Cron replay/history remain |
| compatibility date | done | compatibility flags |
| runtime/build logs and cluster distribution | done | request logs, analytics and retention |
| previews and pull-request deployments | planned | deterministic preview hostnames and cleanup |
| service bindings and placement tags | planned | loopback/mesh service router |
| R2, D1, Queue, Analytics, Pipeline, Email, Binary bindings | partial | native R2, CF-shaped D1, Queue producer/consumer, Analytics Engine and Pipeline bindings + console editors done; remaining event-product bindings remain |

### Data and storage

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| KV get/put/delete/list/TTL | done | metadata and bulk get are workerd-tested; console pagination/import/export remain |
| D1 replicated SQL | partial | Worker prepare/bind/all/first/run/raw/exec/batch/withSession done; schema console, import/export, atomic batch and metrics remain |
| Durable Objects | partial | full CF API audit, alarm retry controls, websocket failover soak |
| R2 objects | partial | native binding + get/head/put/delete/list, metadata, ranges, conditions and delimiter cursors done; streaming multi-GiB IO remains |
| R2 multipart | partial | create/upload/complete/abort and ETags done; administrative upload listing remains |
| R2 public/custom domains and CORS | partial | signed hostnames, deterministic defaults, ACME discovery, CORS and Range delivery done; DNS ownership workflow remains |
| R2 credentials/grants/S3 API | planned | scoped keys, rotation and signature-v4 endpoint |
| R2 quotas/lifecycle/dedup/replication | partial | atomic bucket quotas, lifecycle, delayed cross-bucket orphan checks, local-majority writes and repair done; multi-node fault soak remains |
| rclone backend | partial | credential-isolated config, remote probe and verified read/write/delete done; streaming IO and read cache remain |
| storage policy/sharding | planned | deterministic remote selection and online migration |

### Eventing and orchestration

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| Queues | partial | signed definitions, per-queue D1 ledger, delayed JSON send/sendBatch binding, concurrent batching, quorum visibility leases, retry budget, 30-day dead letters, redrive, CLI/API and Chinese console are real-workerd tested; binary/v8 payload encoding, pause-aware producer policy and multi-node fault soak remain |
| Analytics Engine | partial | signed datasets, independent D1 ledger, 20-slot blobs/doubles/indexes data points, 100-point/1-MiB batching, retention, `writeDataPoint` waitUntil binding, encrypted API, CLI, hour/day counters, recent events, grouping/value aggregates and Chinese console are real-workerd tested; SQL-compatible query language, sampling and multi-node fault soak remain |
| Pipelines | partial | signed definitions, one-time bearer tokens stored only as SHA-256, default/custom domains, ACME discovery, 32-MiB JSON/array/events/NDJSON/text ingest, Draft JSON Schema validation, D1 durable staging, quorum leases, deterministic retry-safe keys, gzip JSONL, direct/multipart R2 output over local or rclone buckets, Worker binding, encrypted API, CLI, status/batch audit and Chinese console are real-workerd/public-ingress tested; streaming request bodies, transform stages and multi-node crash-point soak remain |
| Workflow | planned | idempotent instances, replayed steps, sleep, signals, retry/cancel/heartbeat |
| visual Flow | planned | versioned DAG, credentials, run history and built-in nodes |
| Binary Deliver | planned | signed binaries, content cache, sandboxed execution and bindings |

### Optional email nodes

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| capability-selected MX nodes | planned | `email` capability, DNS/ACME reconcile and health routing |
| inbound SMTP and routing | planned | RFC822 limits, exact/prefix/catch-all routes and durable dispatch |
| authentication results | planned | SPF, DKIM and Authentication-Results exposure |
| raw-message R2 archival | planned | local and rclone-backed buckets, attachments included |
| Worker email handler | planned | reject, forward and binding shims |
| outbound SMTP | planned | durable queue, retries, MX/TLS, DKIM signing, SPF gating and delivery log |

## Delivery order

1. Generic signed resource records and node capability reporting.
2. R2 metadata/data plane with local storage, then rclone and S3-compatible
   access. This is the substrate for Pipeline, email archives, binary delivery,
   previews, exports, and backups.
3. Worker binding expansion; KV/D1/DO parity and unified static-site workflows.
4. Queues, Analytics, Pipeline, Workflow and visual Flow.
5. Optional email nodes and end-to-end mail routing.
6. Cross-feature security, quota, audit, fault-injection and multi-node soak.

Every milestone is merged only after secret scans and CI. VPS upgrades always
download the checksum-verified GitHub Release artifact on the VPS itself.
