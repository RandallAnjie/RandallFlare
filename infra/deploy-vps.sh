#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: infra/deploy-vps.sh --host USER@HOST [options]

Copies a release binary and the deployment kit over SSH, then performs an
atomic install/restart and waits for the node health endpoint.

Options:
  --host USER@HOST    SSH destination (required).
  --port PORT         SSH port (default 22).
  --binary PATH       rf binary (default musl release artifact).
  --config PATH       Node config; required only for the first install.
  --env PATH          Optional /etc/rf.env source.
  --workerd PATH      Optional workerd binary; otherwise the VPS downloads it.
  --health-node ADDR  Health address as seen on the VPS (default 127.0.0.1:7382).
  --sudo              Run the remote installer through sudo.
  --no-start          Install and validate without starting the service.
EOF
}

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
host=""
ssh_port=22
binary="$repo_root/target/x86_64-unknown-linux-musl/release/rf"
config=""
env_file=""
workerd=""
health_node="127.0.0.1:7382"
use_sudo=0
no_start=0

while (($#)); do
  case "$1" in
    --host|--port|--binary|--config|--env|--workerd|--health-node)
      [[ $# -ge 2 ]] || { echo "$1 requires a value" >&2; exit 2; }
      case "$1" in
        --host) host=$2 ;;
        --port) ssh_port=$2 ;;
        --binary) binary=$2 ;;
        --config) config=$2 ;;
        --env) env_file=$2 ;;
        --workerd) workerd=$2 ;;
        --health-node) health_node=$2 ;;
      esac
      shift 2
      ;;
    --sudo) use_sudo=1; shift ;;
    --no-start) no_start=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$host" && "$host" != -* && "$host" =~ ^[a-zA-Z0-9_.@-]+$ ]] || {
  echo "--host must be a simple USER@HOST, hostname, or IPv4 address" >&2
  exit 2
}
[[ "$ssh_port" =~ ^[0-9]+$ ]] && ((ssh_port >= 1 && ssh_port <= 65535)) || {
  echo "invalid SSH port: $ssh_port" >&2
  exit 2
}
[[ "$health_node" =~ ^[a-zA-Z0-9_.:.-]+$ ]] || {
  echo "invalid --health-node value" >&2
  exit 2
}
[[ -f "$binary" ]] || { echo "file not found: $binary" >&2; exit 2; }
[[ -z "$config" || -f "$config" ]] || { echo "file not found: $config" >&2; exit 2; }
[[ -z "$env_file" || -f "$env_file" ]] || { echo "file not found: $env_file" >&2; exit 2; }
[[ -z "$workerd" || -f "$workerd" ]] || { echo "file not found: $workerd" >&2; exit 2; }
for command_name in ssh scp; do
  command -v "$command_name" >/dev/null || {
    echo "required command not found: $command_name" >&2
    exit 1
  }
done

ssh_args=(-p "$ssh_port")
scp_args=(-P "$ssh_port")
remote_dir=$(ssh "${ssh_args[@]}" -- "$host" 'mktemp -d /tmp/rf-deploy.XXXXXXXX')
remote_dir=${remote_dir//$'\r'/}
[[ "$remote_dir" =~ ^/tmp/rf-deploy\.[a-zA-Z0-9]+$ ]] || {
  echo "unexpected remote temporary directory: $remote_dir" >&2
  exit 1
}
cleanup() {
  ssh "${ssh_args[@]}" -- "$host" "rm -rf -- '$remote_dir'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

scp "${scp_args[@]}" -- \
  "$repo_root/infra/install.sh" \
  "$repo_root/infra/fetch-workerd.sh" \
  "$repo_root/infra/rf.service" \
  "$host:$remote_dir/"
scp "${scp_args[@]}" -- "$binary" "$host:$remote_dir/rf"
[[ -z "$config" ]] || scp "${scp_args[@]}" -- "$config" "$host:$remote_dir/rf.toml"
[[ -z "$env_file" ]] || scp "${scp_args[@]}" -- "$env_file" "$host:$remote_dir/rf.env"
[[ -z "$workerd" ]] || scp "${scp_args[@]}" -- "$workerd" "$host:$remote_dir/workerd"

remote_command=(bash "$remote_dir/install.sh" --binary "$remote_dir/rf" --health-node "$health_node")
[[ -z "$config" ]] || remote_command+=(--config "$remote_dir/rf.toml")
[[ -z "$env_file" ]] || remote_command+=(--env "$remote_dir/rf.env")
[[ -z "$workerd" ]] || remote_command+=(--workerd "$remote_dir/workerd")
[[ $no_start -eq 0 ]] || remote_command+=(--no-start)
if [[ $use_sudo -eq 1 ]]; then
  remote_command=(sudo "${remote_command[@]}")
fi

ssh "${ssh_args[@]}" -- "$host" "${remote_command[@]}"
echo "deployment to $host completed"
