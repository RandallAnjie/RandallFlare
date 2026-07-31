# RandallFlare

An edge platform with **no control plane**. Every node runs the same
static binary; coordination happens through gossip, signed manifests,
and claim-based scheduling. Built to leave every spare MB of a cheap
VPS to V8.

See [DESIGN.md](./DESIGN.md) for the architecture.

## Build

```bash
cargo build --release          # → target/release/rf
```

## Quick start (single node)

```bash
rf keygen                      # node + operator keys under ~/.rf
rf run --listen 0.0.0.0:7381   # gossip port; --seed <host:port> to join
rf deploy ./my-worker          # rrangler-style config + modules + assets
```

Status: pre-v0.1, under active construction.
