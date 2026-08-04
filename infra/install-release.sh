#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo install-release.sh --version vX.Y.Z [options]

Downloads the GitHub Actions-built RandallFlare release directly on this
machine, verifies its SHA-256 sidecar, and delegates to the hardened installer.
No locally-built binary is uploaded.

Options:
  --version TAG       Exact release tag, for example v0.6.4 (required).
  --repo OWNER/REPO   GitHub repository (default RandallAnjie/RandallFlare).
  --config PATH       Install this node config. Required on first install.
  --env PATH          Install an EnvironmentFile.
  --workerd PATH      Install an already-downloaded workerd executable.
  --skip-workerd      Do not download workerd when it is not installed.
  --health-node ADDR  Peer API health address (default 127.0.0.1:7382).
  --no-start          Install and validate without starting systemd.
  -h, --help          Show this help.
EOF
}

version=""
repo="RandallAnjie/RandallFlare"
config=""
env_file=""
workerd=""
health_node="127.0.0.1:7382"
skip_workerd=0
no_start=0

while (($#)); do
  case "$1" in
    --version|--repo|--config|--env|--workerd|--health-node)
      [[ $# -ge 2 ]] || { echo "$1 requires a value" >&2; exit 2; }
      case "$1" in
        --version) version=$2 ;;
        --repo) repo=$2 ;;
        --config) config=$2 ;;
        --env) env_file=$2 ;;
        --workerd) workerd=$2 ;;
        --health-node) health_node=$2 ;;
      esac
      shift 2
      ;;
    --skip-workerd) skip_workerd=1; shift ;;
    --no-start) no_start=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
  echo "--version must be an exact release tag such as v0.6.4" >&2
  exit 2
}
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "invalid --repo; expected OWNER/REPO" >&2
  exit 2
}
[[ "$health_node" =~ ^[a-zA-Z0-9_.:.-]+$ ]] || {
  echo "invalid --health-node value" >&2
  exit 2
}
[[ -z "$config" || -f "$config" ]] || { echo "file not found: $config" >&2; exit 2; }
[[ -z "$env_file" || -f "$env_file" ]] || { echo "file not found: $env_file" >&2; exit 2; }
[[ -z "$workerd" || -f "$workerd" ]] || { echo "file not found: $workerd" >&2; exit 2; }
for command_name in curl sha256sum; do
  command -v "$command_name" >/dev/null || {
    echo "required command not found: $command_name" >&2
    exit 1
  }
done

release_dir=$(mktemp -d "${TMPDIR:-/tmp}/rf-release-install.XXXXXXXX")
cleanup() {
  rm -rf -- "$release_dir"
}
trap cleanup EXIT

release_base="https://github.com/$repo/releases/download/$version"
source_base="https://raw.githubusercontent.com/$repo/$version/infra"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$release_dir/rf-linux-x86_64" \
  "$release_base/rf-linux-x86_64"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$release_dir/rf-linux-x86_64.sha256" \
  "$release_base/rf-linux-x86_64.sha256"
for file in install.sh fetch-workerd.sh rf.service rf-bwrap.apparmor; do
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$release_dir/$file" "$source_base/$file"
done

read -r expected_sha checksum_name checksum_extra < "$release_dir/rf-linux-x86_64.sha256"
[[ "$expected_sha" =~ ^[0-9a-fA-F]{64}$ && "$checksum_name" == "rf-linux-x86_64" && -z "$checksum_extra" ]] || {
  echo "release checksum sidecar has an unexpected format" >&2
  exit 1
}
actual_sha=$(sha256sum "$release_dir/rf-linux-x86_64")
actual_sha=${actual_sha%% *}
[[ "${actual_sha,,}" == "${expected_sha,,}" ]] || {
  echo "release binary checksum mismatch" >&2
  exit 1
}
echo "rf-linux-x86_64: OK"
chmod 0755 "$release_dir/rf-linux-x86_64"
reported_version=$("$release_dir/rf-linux-x86_64" --version)
[[ "$reported_version" == "rf ${version#v}" ]] || {
  echo "release binary version mismatch: expected rf ${version#v}, got $reported_version" >&2
  exit 1
}

install_args=(
  --binary "$release_dir/rf-linux-x86_64"
  --apparmor "$release_dir/rf-bwrap.apparmor"
  --health-node "$health_node"
)
[[ -z "$config" ]] || install_args+=(--config "$config")
[[ -z "$env_file" ]] || install_args+=(--env "$env_file")
[[ -z "$workerd" ]] || install_args+=(--workerd "$workerd")
[[ $skip_workerd -eq 0 ]] || install_args+=(--skip-workerd)
[[ $no_start -eq 0 ]] || install_args+=(--no-start)

bash "$release_dir/install.sh" "${install_args[@]}"
