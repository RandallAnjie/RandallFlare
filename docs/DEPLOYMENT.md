# First VPS deployment

This runbook installs one public RandallFlare node for functional testing. It
uses a static `rf` binary, a pinned official `workerd` build, a dedicated Linux
user, a hardened systemd unit, and an end-to-end smoke test.

## 1. VPS and firewall

Use an x86_64 systemd distribution with glibc 2.35 or newer. Ubuntu 22.04/24.04
and Debian 12 are suitable starting points. The host needs `curl`, `tar`,
`sha256sum`, `awk`, `sed`, `git`, `bubblewrap`, and the standard user/systemd
utilities. `git` checks out sources; `bubblewrap` is mandatory for any custom
build command:

```bash
apt-get update && apt-get install -y git bubblewrap
```

On Ubuntu 24.04, the release installer loads the repository's path-scoped
AppArmor profile for `/usr/bin/bwrap`. It permits bubblewrap's user namespace
without disabling `kernel.apparmor_restrict_unprivileged_userns` globally.

Open only the required ports:

| Protocol | Port | Source | Purpose |
| --- | ---: | --- | --- |
| TCP | 22 | administrator IP | SSH |
| TCP | 80, 443 | public | Worker ingress + default management UI |
| UDP | 7381 | future node IPs | encrypted gossip |
| TCP | 7382 | administrator and future node IPs | encrypted peer/operator API |

Do not expose 7382 to the whole internet unless necessary. `/v1/ping` is public;
all other peer API requests require the cluster secret. The install scripts do
not alter the host firewall.

RandallFlare only accepts operator-signed deployments, but `workerd` itself is
[documented as beta and not a hardened sandbox](https://github.com/cloudflare/workerd#security-considerations).
Run code controlled by the trusted operator only. The supplied service runs
both `rf` and its children as an unprivileged `rf` user.

## 2. Download the release and create credentials locally

Use the binary produced by GitHub Actions. Verify the published checksum before
using it to create or validate credentials:

```bash
RF_VERSION=v0.8.3
curl -fLO "https://github.com/RandallAnjie/RandallFlare/releases/download/$RF_VERSION/rf-linux-x86_64"
curl -fLO "https://github.com/RandallAnjie/RandallFlare/releases/download/$RF_VERSION/rf-linux-x86_64.sha256"
sha256sum --check --strict rf-linux-x86_64.sha256
chmod 0755 rf-linux-x86_64

mkdir -m 0700 first-vps
./rf-linux-x86_64 keygen --dir first-vps
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
./rf-linux-x86_64 doctor \
  --config first-vps/rf.toml
```

If DNS or ACME is enabled, copy the environment template and add a zone-scoped
Cloudflare API token:

```bash
cp infra/rf.env.example first-vps/rf.env
chmod 0600 first-vps/rf.env
```

## 3. Install the GitHub release on the VPS

Copy only configuration and optional environment secrets, then let the VPS
download and verify the GitHub-built artifact itself:

```bash
scp first-vps/rf.toml root@203.0.113.7:/root/rf.toml
scp first-vps/rf.env root@203.0.113.7:/root/rf.env  # only when used
ssh root@203.0.113.7
curl -fLo /tmp/install-randallflare-release.sh \
  https://raw.githubusercontent.com/RandallAnjie/RandallFlare/v0.8.3/infra/install-release.sh
bash /tmp/install-randallflare-release.sh \
  --version v0.8.3 --config /root/rf.toml --env /root/rf.env
```

Omit both `scp` of `rf.env` and `--env` when no environment file is needed.
For a non-root account, run the installer with `sudo`. Remove the temporary
configuration copies after installation; `/etc/rf.toml` and `/etc/rf.env` are
installed as `root:rf` mode `0640`.

The VPS downloads `@cloudflare/workerd-linux-64` version `1.20260804.1` from
the official npm registry and verifies pinned package and binary SHA-256 sums.
This exact build passed the repository's complete real-runtime e2e suite.
`workerd` is RandallFlare's local JavaScript runtime dependency; installing it
does not use an external account, tunnel, or control plane.

The installer validates both executables and the config, installs secrets as
`root:rf` mode `0640`, enables `rf.service`, restarts it, and waits up to 30
seconds for the peer health endpoint. It prints service status and recent logs
if startup fails.

## 4. Run the full smoke test

Run this from the administrator machine after allowing its IP to reach TCP
7382. The two `.test` hostnames are sent as HTTP `Host` headers, so no DNS
record is needed:

```bash
export RF_BIN="$PWD/rf-linux-x86_64"
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

## 5. Management console

Open the public node's default address. Unknown/unclaimed hostnames, including
the raw IP address, serve the RandallFlare management interface:

```text
http://203.0.113.7/
```

The browser displays a one-time code. Keep the operator private key on the
administrator machine and approve that code through the encrypted peer API:

```bash
export RF_NODE="203.0.113.7:7382"
export RF_CLUSTER_SECRET="<the cluster secret>"
export RF_OPERATOR_KEY="$PWD/first-vps/operator.key"
./rf-linux-x86_64 authorize ABC12-DEF34
```

The resulting short-lived session is signed by the operator and can be checked
by every cluster node without a central account or session database. Worker
deploy/delete actions display their own one-time approval code because the
operator signs the exact canonical manifest; nodes and browsers never receive
the private key. KV and D1 changes still require the signed session plus same-
origin CSRF proof.

HTTP is acceptable only for an isolated first-node test. Configure HTTPS before
production use. The legacy `rf console` loopback command remains available for
offline/emergency administration.

The Workers page also provides GitHub repository connection, sandboxed builds,
push webhooks, live build/runtime logs, cluster-wide rollout status, and signed
rollback. For a private repository, add a read-only `RF_GITHUB_TOKEN` to
`/etc/rf.env`; it remains local to this node and is stripped from the build
sandbox. Repository configuration and every produced Manifest still require a
one-time operator signature.

## 6. Upgrade

Run the release installer on the VPS without `--config`. It downloads the exact
tag from GitHub, verifies the checksum and embedded version, preserves
`/etc/rf.toml` and `/etc/rf.env`, and atomically replaces the binary before
restarting the service:

```bash
curl -fLo /tmp/install-randallflare-release.sh \
  https://raw.githubusercontent.com/RandallAnjie/RandallFlare/v0.8.3/infra/install-release.sh
sudo bash /tmp/install-randallflare-release.sh --version v0.8.3
```

The default hardened unit deliberately prevents the unprivileged daemon from
rewriting `/usr/local/bin/rf`, so `[update].enabled` must remain `false` for
this installation model.

One node proves the full functional path but provides no redundancy. D1 and
Durable Objects use a one-member quorum until more nodes join; use at least
three independent nodes before treating their availability as production-grade.
