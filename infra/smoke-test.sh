#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Required environment:
  RF_NODE=VPS_IP:7382
  RF_INGRESS=http://VPS_IP
  RF_CLUSTER_SECRET=<64 hex chars>
  RF_OPERATOR_KEY=/path/to/operator.key

Optional:
  RF_BIN=/path/to/rf       (default: rf on PATH)
  RF_CLEANUP=1             tombstone smoke Workers and delete the KV key
EOF
}

: "${RF_NODE:?$(usage)}"
: "${RF_INGRESS:?$(usage)}"
: "${RF_CLUSTER_SECRET:?$(usage)}"
: "${RF_OPERATOR_KEY:?$(usage)}"
RF_BIN=${RF_BIN:-rf}
RF_CLEANUP=${RF_CLEANUP:-0}
static_host="static.smoke.rf.test"
counter_host="counter.smoke.rf.test"
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
examples_dir="$script_dir/../examples"
ingress=${RF_INGRESS%/}

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
[[ -x "$RF_BIN" ]] || command -v "$RF_BIN" >/dev/null || {
  echo "rf executable not found: $RF_BIN" >&2
  exit 1
}
[[ -f "$RF_OPERATOR_KEY" ]] || { echo "operator key not found" >&2; exit 1; }

echo "1/6 node health and authenticated status"
"$RF_BIN" health --node "$RF_NODE"
"$RF_BIN" status --node "$RF_NODE" >/dev/null
console_body=$(curl --fail --silent --show-error --connect-timeout 3 --max-time 5 "$ingress/")
[[ "$console_body" == *"RandallFlare Console"* ]] || {
  echo "default ingress did not serve the RandallFlare management interface" >&2
  exit 1
}

echo "2/6 static asset deployment and ingress"
"$RF_BIN" deploy "$examples_dir/hello" --node "$RF_NODE" >/dev/null
static_body=""
for attempt in $(seq 1 30); do
  static_body=$(curl --fail --silent --show-error --connect-timeout 3 --max-time 5 \
    -H "Host: $static_host" "$ingress/" 2>/dev/null) && \
    [[ "$static_body" == *"RandallFlare smoke test"* ]] && break
  sleep 1
done
[[ "$static_body" == *"RandallFlare smoke test"* ]] || {
  echo "static Worker did not become reachable" >&2
  exit 1
}

echo "3/6 KV put/get/list"
run_id=$(date +%s)
"$RF_BIN" kv put rf-smoke probe "$run_id" --node "$RF_NODE"
kv_value=$("$RF_BIN" kv get rf-smoke probe --node "$RF_NODE")
[[ "$kv_value" == "$run_id" ]] || { echo "KV value mismatch" >&2; exit 1; }
"$RF_BIN" kv list rf-smoke --prefix pro --node "$RF_NODE" | grep -Fxq probe

echo "4/6 D1 create/write/read"
if ! d1_create_output=$("$RF_BIN" d1 create rf-smoke --node "$RF_NODE" 2>&1); then
  [[ "$d1_create_output" == *"409"* ]] || {
    echo "$d1_create_output" >&2
    exit 1
  }
fi
d1_exec_retry() {
  local sql=$1
  local params=${2:-[]}
  local output=""
  for attempt in $(seq 1 30); do
    if output=$("$RF_BIN" d1 exec rf-smoke "$sql" --params "$params" --node "$RF_NODE" 2>&1); then
      printf '%s' "$output"
      return 0
    fi
    sleep 1
  done
  echo "$output" >&2
  return 1
}
d1_exec_retry 'CREATE TABLE IF NOT EXISTS probes (id TEXT PRIMARY KEY)' >/dev/null
d1_exec_retry 'INSERT OR REPLACE INTO probes (id) VALUES (?1)' "[\"$run_id\"]" >/dev/null
d1_rows=$(d1_exec_retry 'SELECT id FROM probes WHERE id = ?1' "[\"$run_id\"]")
[[ "$d1_rows" == *"$run_id"* ]] || { echo "D1 row not returned" >&2; exit 1; }

echo "5/6 workerd + Durable Object deployment"
"$RF_BIN" deploy "$examples_dir/counter" --node "$RF_NODE" >/dev/null
counter_body=""
for attempt in $(seq 1 45); do
  counter_body=$(curl --fail --silent --show-error --connect-timeout 3 --max-time 8 \
    -H "Host: $counter_host" "$ingress/" 2>/dev/null) && \
    [[ "$counter_body" =~ ^[0-9]+$ ]] && break
  sleep 1
done
[[ "$counter_body" =~ ^[0-9]+$ ]] || {
  echo "Durable Object Worker did not become reachable" >&2
  exit 1
}

echo "6/6 transparency logs"
"$RF_BIN" log rf-smoke-static --node "$RF_NODE" >/dev/null
"$RF_BIN" log rf-smoke-counter --node "$RF_NODE" >/dev/null

if [[ "$RF_CLEANUP" == "1" ]]; then
  "$RF_BIN" worker-delete rf-smoke-static --node "$RF_NODE" >/dev/null
  "$RF_BIN" worker-delete rf-smoke-counter --node "$RF_NODE" >/dev/null
  "$RF_BIN" kv delete rf-smoke probe --node "$RF_NODE"
fi

echo "smoke test passed (DO counter=$counter_body, D1 probe=$run_id)"
