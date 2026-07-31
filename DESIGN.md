# RandallFlare — a control-plane-less edge platform

Cloudflare decentralizes the data plane but keeps a centralized control
plane (core datacenters). RandallFlare removes the control plane
entirely: **every node runs the same binary, no node is special.**
Coordination is sharded and emergent — gossip, signed manifests,
claim-based task scheduling, and (later) per-object micro-quorums.

The second design axiom: nodes are *cheap*. A 512 MB VPS must run V8
workloads, so the coordination layer has a hard memory budget of
single-digit MB RSS. Every byte we don't spend is a byte workerd gets.
This is why the daemon is Rust.

## What a node is

One static binary, `rf`. Every node runs:

- **gossip** — SWIM-style membership + state dissemination (cluster PSK).
- **manifest store** — operator-signed worker manifests, merged as a
  CRDT (higher version wins, deterministic tie-break by manifest hash).
- **blob store** — content-addressed (sha256) worker modules and static
  assets, fetched from any peer that has them, verified locally.
- **claim engine** — signed, HLC-timestamped claims over named tasks;
  deterministic adjudication. Used for every singleton job: cron ticks,
  DNS repair, ACME renewal.
- **runtime** — workerd child processes, one per active worker.
  *Workers and Pages are one product here*: a worker is modules plus an
  optional static asset tree (served via a disk service bound as
  `ASSETS`).
- **ingress** — rustls TLS, SNI/Host routing to local workerd, reverse
  proxy to a peer when the worker is pinned elsewhere.
- **KV** — LWW-CRDT with hybrid logical clocks, anti-entropy sync.
  Same eventual-consistency contract as CF KV (~propagation window).

Nodes may be **public** (in DNS rotation, terminate ingress) or
**inner** (reachable only over the overlay/peer links: storage, cron,
claim work — never in DNS). The flag is per-node config; nothing else
distinguishes them.

## Consistency model (the honest version)

Uniqueness in this system is *eventual uniqueness*: a claim may briefly
be held twice during a partition, and adjudication converges everyone
afterward. That is safe exactly where duplicate execution is safe:

| concern | mechanism | why duplication is safe |
|---|---|---|
| cron ticks | claim per (worker, tick) | at-least-once, CF parity |
| DNS repair | claim per repair task | reconcile is idempotent |
| ACME renewal | claim + TTL lease | duplicate issue only wastes rate limit |
| hostnames | signed claim, earliest-HLC wins | brief dual-serving, converges |
| deploys | signed manifest, version wins | old version briefly serves |
| KV | LWW + HLC | contract is eventual anyway |

What claims can NOT give you is a single writer for stateful storage
(D1/Durable Objects): two writers during a partition create histories
that cannot be merged. The plan there (later milestone) is **per-object
micro-quorums**: each database/DO gets a 3-node replica group chosen by
rendezvous hashing over the membership; writes need an epoch-fenced
lease from a majority of that group. Consensus exists, but it is
per-object and node-anonymous — still no distinguished node.

External dependencies that remain by necessity: the DNS zone (Cloudflare
API — the entry point has to resolve somewhere) and the ACME CA. Both
are consumed as claimed, idempotent tasks executed by whichever node
grabs them.

## Trust model

No central database means authority comes from signatures:

- **cluster PSK** — encrypts gossip, gates membership.
- **node keys** (ed25519) — sign claims and heartbeat-ish state.
- **operator key** (ed25519) — signs manifests and (later) user/token
  certificates. Verification is offline; no node needs to phone home.

Nodes are assumed non-Byzantine (operator-enrolled machines). Claims
are signed so a compromised PSK alone cannot forge deploys.

## Update path

Nodes self-update from GitHub Releases: check version, download the
matching target, verify sha256, atomic rename + re-exec. Disabled until
the repo is public.

## Crate layout

```
crates/rf-core   pure logic, no IO, no tokio: identity, HLC, envelopes,
                 claim adjudication, manifest CRDT, KV CRDT, cron parse.
                 Exhaustively unit/property tested.
crates/rf        the binary: gossip, storage (redb), blob sync, runtime,
                 ingress, DNS tasks, CLI. Thin IO around rf-core.
```

The split is the testing strategy: every decision the cluster makes is
a pure function in rf-core (events in, decisions out). The IO shell
stays too thin to hide bugs.

## Milestones

1. **v0.1** — gossip, manifests, blobs, claims, KV, workerd runtime,
   ingress, cron, DNS tasks, deploy CLI, two-node e2e. (This tree.)
2. **v0.2** — ACME via claims, overlay transport for inner nodes,
   self-update on.
3. **v0.3** — micro-quorum storage: D1 (SQLite home + WAL replication),
   Durable Objects with epoch-fenced leases.
