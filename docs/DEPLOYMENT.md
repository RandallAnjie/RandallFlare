# First VPS deployment

This runbook installs one public RandallFlare node for functional testing. It
uses a static `rf` binary, a pinned official `workerd` build, a dedicated Linux
user, a hardened systemd unit, and an end-to-end smoke test.

## 1. VPS and firewall

Use an x86_64 systemd distribution with glibc 2.35 or newer. Ubuntu 22.04/24.04
and Debian 12 are suitable starting points. The host needs `curl`, `tar`,
`sha256sum`, `awk`, `sed`, and the standard user/systemd utilities.

Open only the required ports:

| Protocol | Port | Source | Purpose |
| --- | ---: | --- | --- |
| TCP | 22 | administrator IP | SSH |
| TCP | 80, 443 | public | Worker ingress |
| UDP | 7381 | future node IPs | encrypted gossip |
| TCP | 7382 | administrator and future node IPs | encrypted peer/operator API |

Do not expose 7382 to the whole internet unless necessary. `/v1/ping` is public;
all other peer API requests require the cluster secret. The install scripts do
not alter the host firewall.

RandallFlare only accepts operator-signed deployments, but `workerd` itself is
[documented as beta and not a hardened sandbox](https://github.com/cloudflare/workerd#security-considerations).
Run code controlled by the trusted operator only. The supplied service runs
both `rf` and its children as an unprivileged `rf` user.

## 2. Build and create credentials locally

From the repository root:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

mkdir -m 0700 first-vps
target/x86_64-unknown-linux-musl/release/rf keygen --dir first-vps
cp infra/rf.first.toml.example first-vps/rf.toml
chmod 0600 first-vps/operator.key first-vps/rf.toml
```

The key command prints an operator public ID and a random 64-character cluster
secret. Put those values into `first-vps/rf.toml`, then replace
`REPLACE_WITH_VPS_IP` with the VPS's public or private overlay IP. The private
operator key stays on the administrator machine; never copy it to a node.

The first node has `seeds = []`. Keep `cluster_id`, `cluster_secret`, and the
operator identity identical when adding later nodes.

Validate the finished config before connecting to the VPS:

```bash
target/x86_64-unknown-linux-musl/release/rf doctor \
  --config first-vps/rf.toml
```

If DNS or ACME is enabled, copy the environment template and add a zone-scoped
Cloudflare API token:

```bash
cp infra/rf.env.example first-vps/rf.env
chmod 0600 first-vps/rf.env
```

## 3. Install over SSH

Root SSH:

```bash
infra/deploy-vps.sh \
  --host root@203.0.113.7 \
  --config first-vps/rf.toml
```

For a non-root SSH account with passwordless sudo, add `--sudo`. Add
`--port PORT` for a nonstandard SSH port and `--env first-vps/rf.env` when the
optional environment file is needed.

The VPS downloads `@cloudflare/workerd-linux-64` version `1.20260804.1` from
the official npm registry and verifies pinned package and binary SHA-256 sums.
This exact build passed the repository's complete real-runtime e2e suite. To
avoid downloading on the server, first run:

```bash
infra/fetch-workerd.sh --output first-vps/workerd
infra/deploy-vps.sh \
  --host root@203.0.113.7 \
  --config first-vps/rf.toml \
  --workerd first-vps/workerd
```

The installer validates both executables and the config, installs secrets as
`root:rf` mode `0640`, enables `rf.service`, restarts it, and waits up to 30
seconds for the peer health endpoint. It prints service status and recent logs
if startup fails.

## 4. Run the full smoke test

Run this from the administrator machine after allowing its IP to reach TCP
7382. The two `.test` hostnames are sent as HTTP `Host` headers, so no DNS
record is needed:

```bash
export RF_BIN="$PWD/target/x86_64-unknown-linux-musl/release/rf"
export RF_NODE="203.0.113.7:7382"
export RF_INGRESS="http://203.0.113.7"
export RF_CLUSTER_SECRET="<the cluster secret>"
export RF_OPERATOR_KEY="$PWD/first-vps/operator.key"

infra/smoke-test.sh
```

The test verifies health, authenticated status, static deployment and ingress,
KV, D1, a real workerd Durable Object, and manifest transparency logs. It
leaves the two smoke Workers deployed for inspection. Set `RF_CLEANUP=1` to
tombstone them and remove the KV probe after a successful run. The reusable
`rf-smoke` D1 database remains because database deletion is intentionally not
implemented yet.

Useful VPS diagnostics:

```bash
systemctl status rf --no-pager
journalctl -u rf -n 200 --no-pager
/usr/local/bin/rf doctor --config /etc/rf.toml
/usr/local/bin/rf health --node 127.0.0.1:7382
```

## 5. Upgrade

Rebuild the static binary and run the deploy command without `--config`; the
installer preserves `/etc/rf.toml` and `/etc/rf.env` and atomically replaces the
binary before restarting the service:

```bash
infra/deploy-vps.sh --host root@203.0.113.7
```

The default hardened unit deliberately prevents the unprivileged daemon from
rewriting `/usr/local/bin/rf`, so `[update].enabled` must remain `false` for
this installation model.

One node proves the full functional path but provides no redundancy. D1 and
Durable Objects use a one-member quorum until more nodes join; use at least
three independent nodes before treating their availability as production-grade.
