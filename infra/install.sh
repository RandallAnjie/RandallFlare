#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo infra/install.sh --binary PATH [options]

Options:
  --config PATH       Install this node config. Required on first install.
  --env PATH          Install an EnvironmentFile (for CF_API_TOKEN, etc.).
  --workerd PATH      Install an already-downloaded workerd executable.
  --apparmor PATH     Ubuntu AppArmor profile for bubblewrap builds.
  --skip-workerd      Do not download workerd when it is not installed.
  --health-node ADDR  Peer API health address (default 127.0.0.1:7382).
  --no-start          Install and validate, but do not enable/start systemd.
  -h, --help          Show this help.

Set DESTDIR to stage the filesystem layout without touching systemd. The
hardened service expects data_dir = "/var/lib/rf".
EOF
}

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
binary_source=""
config_source=""
env_source=""
workerd_source=""
apparmor_source=""
health_node="127.0.0.1:7382"
skip_workerd=0
no_start=0

while (($#)); do
  case "$1" in
    --binary|--config|--env|--workerd|--apparmor|--health-node)
      [[ $# -ge 2 ]] || { echo "$1 requires a value" >&2; exit 2; }
      case "$1" in
        --binary) binary_source=$2 ;;
        --config) config_source=$2 ;;
        --env) env_source=$2 ;;
        --workerd) workerd_source=$2 ;;
        --apparmor) apparmor_source=$2 ;;
        --health-node) health_node=$2 ;;
      esac
      shift 2
      ;;
    --skip-workerd)
      skip_workerd=1
      shift
      ;;
    --no-start)
      no_start=1
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

[[ -n "$binary_source" && -f "$binary_source" ]] || {
  echo "--binary must point to the rf release binary" >&2
  exit 2
}
[[ -z "$config_source" || -f "$config_source" ]] || {
  echo "config file not found: $config_source" >&2
  exit 2
}
[[ -z "$env_source" || -f "$env_source" ]] || {
  echo "environment file not found: $env_source" >&2
  exit 2
}
[[ -z "$workerd_source" || -f "$workerd_source" ]] || {
  echo "workerd file not found: $workerd_source" >&2
  exit 2
}
[[ -z "$apparmor_source" || -f "$apparmor_source" ]] || {
  echo "AppArmor profile not found: $apparmor_source" >&2
  exit 2
}

destdir=${DESTDIR:-}
if [[ "$destdir" == "/" ]]; then
  destdir=""
elif [[ -n "$destdir" && "$destdir" != /* ]]; then
  echo "DESTDIR must be an absolute path" >&2
  exit 2
fi
if [[ -z "$destdir" && $EUID -ne 0 ]]; then
  echo "live installation must run as root" >&2
  exit 1
fi

path_in_root() {
  printf '%s%s' "$destdir" "$1"
}

rf_bin=$(path_in_root /usr/local/bin/rf)
workerd_bin=$(path_in_root /usr/local/bin/workerd)
config_target=$(path_in_root /etc/rf.toml)
env_target=$(path_in_root /etc/rf.env)
service_target=$(path_in_root /etc/systemd/system/rf.service)
apparmor_target=$(path_in_root /etc/apparmor.d/rf-bwrap)
state_dir=$(path_in_root /var/lib/rf)
rf_candidate="${rf_bin}.install.$$"
workerd_candidate="${workerd_bin}.install.$$"
downloaded_workerd=""

cleanup() {
  if [[ -n "$downloaded_workerd" ]]; then
    rm -f -- "$downloaded_workerd"
  fi
  rm -f -- "$rf_candidate" "$workerd_candidate"
}
trap cleanup EXIT

if [[ -z "$config_source" && ! -f "$config_target" ]]; then
  echo "--config is required because $config_target does not exist" >&2
  exit 2
fi

if [[ -z "$destdir" ]]; then
  command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
  if ! getent group rf >/dev/null; then
    groupadd --system rf
  fi
  if ! id rf >/dev/null 2>&1; then
    nologin_shell=$(command -v nologin || printf '/usr/sbin/nologin')
    useradd --system --gid rf --home-dir /var/lib/rf --shell "$nologin_shell" rf
  fi
fi

install -d -m 0755 "$(dirname -- "$rf_bin")" "$(dirname -- "$service_target")"
install -d -m 0700 "$state_dir"

install -m 0755 "$binary_source" "$rf_candidate"
"$rf_candidate" --version >/dev/null

if [[ -z "$workerd_source" && ! -f "$workerd_bin" && $skip_workerd -ne 1 ]]; then
  downloaded_workerd=$(mktemp "${TMPDIR:-/tmp}/rf-workerd-install.XXXXXXXX")
  bash "$script_dir/fetch-workerd.sh" --output "$downloaded_workerd" --force
  workerd_source=$downloaded_workerd
fi
if [[ -n "$workerd_source" ]]; then
  install -m 0755 "$workerd_source" "$workerd_candidate"
  "$workerd_candidate" --version >/dev/null
  if [[ -f "$workerd_bin" ]]; then
    install -m 0755 "$workerd_bin" "${workerd_bin}.previous"
  fi
  mv -f -- "$workerd_candidate" "$workerd_bin"
fi

validation_config=${config_source:-$config_target}
if ! sed -nE 's/^[[:space:]]*data_dir[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
  "$validation_config" | head -n1 | grep -Fxq '/var/lib/rf'; then
  echo "the hardened service requires data_dir = \"/var/lib/rf\"" >&2
  exit 1
fi
if [[ -z "$destdir" ]]; then
  "$rf_candidate" doctor --config "$validation_config"
fi

if [[ -f "$rf_bin" ]]; then
  install -m 0755 "$rf_bin" "${rf_bin}.previous"
fi
mv -f -- "$rf_candidate" "$rf_bin"

if [[ -n "$config_source" && "$config_source" != "$config_target" ]]; then
  if [[ -f "$config_target" ]]; then
    install -m 0640 "$config_target" "${config_target}.previous"
  fi
  install -m 0640 "$config_source" "$config_target"
fi
if [[ -n "$env_source" && "$env_source" != "$env_target" ]]; then
  if [[ -f "$env_target" ]]; then
    install -m 0640 "$env_target" "${env_target}.previous"
  fi
  install -m 0640 "$env_source" "$env_target"
elif [[ ! -e "$env_target" ]]; then
  install -m 0640 /dev/null "$env_target"
fi
install -m 0644 "$script_dir/rf.service" "$service_target"

# Ubuntu 24.04's AppArmor user-namespace restriction otherwise sends bwrap to
# the generic unprivileged_userns profile, which cannot populate uid_map. Load
# a path-scoped bwrap profile instead of disabling the host-wide restriction.
if [[ -n "$apparmor_source" ]]; then
  apparmor_restriction=$(path_in_root /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
  if [[ -f "$apparmor_restriction" && "$(cat "$apparmor_restriction")" == "1" ]]; then
    command -v apparmor_parser >/dev/null || {
      echo "AppArmor restricts user namespaces but apparmor_parser is unavailable" >&2
      exit 1
    }
    install -d -m 0755 "$(dirname -- "$apparmor_target")"
    install -m 0644 "$apparmor_source" "$apparmor_target"
    apparmor_parser -r "$apparmor_target"
  fi
fi

if [[ -z "$destdir" ]]; then
  chown root:rf "$config_target" "$env_target"
  [[ ! -f "${config_target}.previous" ]] || chown root:rf "${config_target}.previous"
  [[ ! -f "${env_target}.previous" ]] || chown root:rf "${env_target}.previous"
  chown -R -- rf:rf "$state_dir"
  chmod 0640 "$config_target" "$env_target"
  chmod 0700 "$state_dir"

  if command -v runuser >/dev/null; then
    (
      cd "$state_dir"
      runuser -u rf -- "$rf_bin" doctor --config "$config_target"
    )
  else
    (
      cd "$state_dir"
      sudo -u rf -- "$rf_bin" doctor --config "$config_target"
    )
  fi

  systemctl daemon-reload
  if [[ $no_start -eq 1 ]]; then
    echo "installed rf; service was not started (--no-start)"
    exit 0
  fi

  systemctl enable rf.service >/dev/null
  systemctl restart rf.service
  for attempt in $(seq 1 30); do
    if "$rf_bin" health --node "$health_node" >/dev/null 2>&1; then
      "$rf_bin" health --node "$health_node"
      echo "rf installation complete"
      exit 0
    fi
    sleep 1
  done
  echo "rf did not become healthy within 30 seconds" >&2
  systemctl --no-pager --full status rf.service >&2 || true
  journalctl -u rf.service -n 100 --no-pager >&2 || true
  exit 1
fi

echo "staged RandallFlare filesystem at $destdir"
