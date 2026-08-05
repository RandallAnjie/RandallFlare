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
| signed audit/transparency history | partial | Worker manifests and every signed platform resource are exposed through a redacted cluster audit; KV/D1 data-plane mutation export and archival remain |
| node tags, placement requirements, drain/suspend | partial | signed policies, system/custom/region tags, Worker constraints, encrypted exact-revision peer fallback, preview placement, DNS draining, capability-aware initial DO quorums and Chinese node UI are implemented and two-node tested; existing-DO owner migration and multi-VPS production soak remain |
| topology, quotas, request metrics, DLQ | partial | placement topology, privacy-bounded request history, aggregation, status trends and DLQs are done; signed Worker/hostname/R2/outbound quotas and deterministic per-live-node request admission are implemented; partition/fault soak remains |
| access tokens and scoped API credentials | partial | one-way signed tokens, exact read/write scopes, expiry/revocation, last-used telemetry, cookie-isolated `/api/v1` and Chinese UI are implemented; CLI management and production soak remain |
| device/exit networking | planned | capability-tagged exits and encrypted tunnel enrolment |

### Workers (including Pages)

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| modules + static assets in one deploy unit | done | — |
| browser upload and CLI deploy | done | signed per-file create/edit/rename/delete and binary replacement are done; ZIP/TAR import and export remain |
| GitHub source, sandboxed build, webhook deploy | done | signed PR preview builds are done; GitHub App auth, PR checks/comments and SSH deploy keys remain |
| versions, hash-chain audit and rollback | done | historical-version preview aliases, renewal and signed deletion are done |
| default/custom domains and wildcard TLS | done | custom-domain DNS ownership workflow |
| environment, encrypted Secrets, KV bindings, Cron | done | write-only XChaCha20-Poly1305 Secrets, names-only API/console, KV metadata + bulk get, and real scheduled-event Cron with D1 history/retry/DLQ/replay are verified |
| compatibility date and flags | done | compatibility date plus validated, signed workerd compatibility flags are done; the supported-flag catalogue must track the pinned workerd release |
| runtime/build/request logs and cluster distribution | done | runtime output and 7-day request history aggregate across live nodes; longer archival/export is optional future work |
| previews and pull-request deployments | partial | deterministic version/PR domains, isolated runtimes and DO disks, signed approval/tombstones, automatic expiry, ACME/blob repair, request observability and Chinese UI are implemented; GitHub check/comment reporting and multi-node fault soak remain |
| service bindings and placement tags | partial | signed node-local dynamic Service router, native `env.SERVICE.fetch()`, placement requirements and encrypted mesh fallback are done; multi-service cycle diagnostics remain |
| R2, D1, Queue, Analytics, Pipeline, Workflow, Email, Binary bindings | partial | native bindings and Chinese editors are implemented for every listed service, including per-call signed Binary authorization and R2 output publication; cross-service fault soak remains |

### Data and storage

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| KV get/put/delete/list/TTL | done | metadata and bulk get are workerd-tested; console pagination/import/export remain |
| D1 replicated SQL | partial | Worker prepare/bind/all/first/run/raw/exec/batch/withSession done; schema console, import/export, atomic batch and metrics remain |
| Durable Objects | partial | full CF API audit, alarm retry controls, websocket failover soak |
| R2 objects | partial | native binding + get/head/put/delete/list, metadata, ranges, conditions and delimiter cursors done; streaming multi-GiB IO remains |
| R2 multipart | partial | create/upload/complete/abort and ETags done; administrative upload listing remains |
| R2 public/custom domains and CORS | partial | signed hostnames, deterministic defaults, ACME discovery, CORS and Range delivery done; DNS ownership workflow remains |
| R2 credentials/grants/S3 API | partial | sealed Secret Access Keys, signed revocation/rotation, full-account or per-bucket grants, path-style Signature V4, conditional/ranged GET and multipart are implemented; SDK compatibility matrix and production soak remain |
| R2 quotas/lifecycle/dedup/replication | partial | atomic bucket quotas, lifecycle, delayed cross-bucket orphan checks, local-majority writes and repair done; multi-node fault soak remains |
| rclone backend | partial | credential-isolated config, bounded cluster-wide remote probes and verified read/write/delete done; streaming IO and read cache remain |
| storage policy/sharding | partial | signed defaults, first-32-bit ordered remote selection, flat SHA paths, per-object/per-multipart concrete pins, old-schema backfill, zero-migration expansion, destructive-removal admission, capability-aware peer borrowing, physical distribution, CLI/API and Chinese console are implemented and two-remote/D1 tested; multi-VPS provider fault soak remains |

### Eventing and orchestration

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| Queues | partial | signed definitions, per-queue D1 ledger, delayed JSON send/sendBatch binding, concurrent batching, quorum visibility leases, retry budget, 30-day dead letters, redrive, CLI/API and Chinese console are real-workerd tested; binary/v8 payload encoding, pause-aware producer policy and multi-node fault soak remain |
| Analytics Engine | partial | signed datasets, independent D1 ledger, 20-slot blobs/doubles/indexes data points, 100-point/1-MiB batching, retention, `writeDataPoint` waitUntil binding, encrypted API, CLI, hour/day counters, recent events, grouping/value aggregates and Chinese console are real-workerd tested; SQL-compatible query language, sampling and multi-node fault soak remain |
| Pipelines | partial | signed definitions, one-time bearer tokens stored only as SHA-256, default/custom domains, ACME discovery, 32-MiB JSON/array/events/NDJSON/text ingest, Draft JSON Schema validation, D1 durable staging, quorum leases, deterministic retry-safe keys, gzip JSONL, direct/multipart R2 output over local or rclone buckets, Worker binding, encrypted API, CLI, status/batch audit and Chinese console are real-workerd/public-ingress tested; streaming request bodies, transform stages and multi-node crash-point soak remain |
| Workflow | partial | signed definitions, per-Workflow D1 quorum, idempotent instances, exactly-once replay boundaries, step retry/timeout, durable sleep/sleepUntil, signals, fenced leases and heartbeats, crash replay, pause/resume/terminate/restart, retention, Worker binding and built-in module, encrypted API, CLI, audit timeline and Chinese console are real-workerd tested; cron/webhook triggers, version-pinned definitions, concurrency groups and multi-node crash-point soak remain |
| visual Flow | partial | signed/version-frozen DAGs, Vercel-style Chinese canvas and inspector, manual/webhook/cron triggers, one-way token hashes, synchronous Flow-as-API, idempotency, per-Flow D1 run/step/audit ledger, fenced recovery, cancellation/retry/retention/concurrency, durable loop subgraphs, typed templates, guarded inline subflows, SSRF-safe HTTP/local credentials, failure alerts, and Worker/KV/D1/R2/Queue/Analytics/Pipeline/Workflow nodes are real-daemon tested; Email now durably queues through signed mail domains; full JSONata grammar, nested loops in subflows and multi-node crash-point soak remain |
| Binary Deliver | partial | operator-signed definitions, SHA-256 local/rclone blobs, authenticated peer repair, executable cache, architecture/tag placement, fresh bubblewrap isolation, network/R2 policy gates, bounded stdin/stdout/stderr/timeouts, R2 output files, CLI/scoped API/Chinese console and native Worker binding are implemented and sandbox-tested; multi-node cache repair and production load soak remain |

### Optional email nodes

| Capability | State | Remaining acceptance work |
| --- | --- | --- |
| capability-selected MX nodes | partial | explicit node role, signed MX match, capability reporting, bounded SMTP pool and STARTTLS cert loading done; automatic certificate hot-reload, health-weighted placement and multi-MX soak remain |
| inbound SMTP and routing | partial | RFC 822 limits, verified domains, exact/prefix/catch-all routes, D1 leases, crash recovery, rate limits and terminal retention done; multi-node SMTP fault soak and DSN generation remain |
| authentication results | partial | SPF, DKIM, DMARC and full Authentication-Results are persisted/exposed; ARC and MTA-STS policy remain |
| raw-message R2 archival | partial | immutable source, metadata hashes, shared-recipient reference-safe retention and local/rclone buckets done; multi-GiB streaming remains |
| Worker email handler | partial | `email()` event, headers/raw stream, `setReject`, reliable idempotent `forward`, loop protection and `env.MAIL.send()` done; real-SMTP/workerd fault soak remains |
| outbound SMTP | partial | per-recipient durable queue, fenced leases, bounded exponential retry, direct sorted MX, Null MX, opportunistic TLS, node-local RSA DKIM signing, CLI/API/Flow and delivery console done; bounce/DSN processing, SMTPUTF8 and reputation automation remain |

## Delivery order

1. Generic signed resource records and node capability reporting.
2. R2 metadata/data plane with local storage, then rclone and S3-compatible
   access. This is the substrate for Pipeline, email archives, binary delivery,
   previews, exports, and backups.
3. Worker binding expansion; KV/D1/DO parity and unified static-site workflows.
4. Queues, Analytics, Pipeline, Workflow and visual Flow.
5. Optional email nodes and end-to-end mail routing (foundation complete; fault soak remains).
6. Cross-feature security, quota, audit, fault-injection and multi-node soak.

Every milestone is merged only after secret scans and CI. VPS upgrades always
download the checksum-verified GitHub Release artifact on the VPS itself.
