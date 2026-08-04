#!/usr/bin/env bash
set -Eeuo pipefail

# Official workerd prebuilt packages are published through npm. Keep this
# version pinned to the one exercised by RandallFlare's real-runtime tests.
readonly WORKERD_PACKAGE_VERSION="1.20260804.1"
readonly WORKERD_VERSION="workerd 2026-08-04"
readonly TARBALL_SHA256="5c09c977db0ddae38bcb3f0c6075334467ce699f9b5f1a5fe790dda0e225c823"
readonly BINARY_SHA256="d1709383b9827e8003ed1b2a08f9fe2d12dd9c66b386a0907e428b7995e52f48"
readonly PACKAGE_URL="https://registry.npmjs.org/@cloudflare/workerd-linux-64/-/workerd-linux-64-${WORKERD_PACKAGE_VERSION}.tgz"

usage() {
  cat <<'EOF'
Usage: infra/fetch-workerd.sh --output PATH [--force]

Downloads the pinned official Linux x86_64 workerd package, verifies both
the package and extracted binary, and installs the executable at PATH.
EOF
}

output=""
force=0
while (($#)); do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || { echo "--output requires a path" >&2; exit 2; }
      output=$2
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$output" ]] || { usage >&2; exit 2; }
[[ "$(uname -m)" == "x86_64" ]] || {
  echo "the pinned package supports x86_64 only (found $(uname -m))" >&2
  exit 1
}
for command_name in curl tar sha256sum install mktemp awk; do
  command -v "$command_name" >/dev/null || {
    echo "required command not found: $command_name" >&2
    exit 1
  }
done
if [[ -e "$output" && $force -ne 1 ]]; then
  echo "refusing to overwrite existing output: $output (pass --force)" >&2
  exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/rf-workerd.XXXXXXXX")
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

archive="$work_dir/workerd.tgz"
curl --fail --location --silent --show-error --retry 3 \
  --output "$archive" "$PACKAGE_URL"
actual_archive_sha=$(sha256sum "$archive" | awk '{print $1}')
[[ "$actual_archive_sha" == "$TARBALL_SHA256" ]] || {
  echo "workerd package checksum mismatch" >&2
  exit 1
}

tar -xzf "$archive" -C "$work_dir"
extracted="$work_dir/package/bin/workerd"
[[ -f "$extracted" ]] || { echo "workerd binary missing from package" >&2; exit 1; }
actual_binary_sha=$(sha256sum "$extracted" | awk '{print $1}')
[[ "$actual_binary_sha" == "$BINARY_SHA256" ]] || {
  echo "workerd binary checksum mismatch" >&2
  exit 1
}

install -D -m 0755 "$extracted" "$output"
actual_version=$("$output" --version 2>&1) || {
  echo "workerd cannot run; Linux x86_64 with glibc 2.35+ is required" >&2
  exit 1
}
[[ "$actual_version" == "$WORKERD_VERSION" ]] || {
  echo "unexpected workerd version: $actual_version" >&2
  exit 1
}
echo "installed $actual_version at $output"
