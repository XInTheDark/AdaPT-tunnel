#!/usr/bin/env bash
set -euo pipefail

DEFAULT_BIN_DIR="/usr/local/bin"
DEFAULT_SHARE_DIR="/usr/local/share/adapt"
DEFAULT_INSTALLER_NAME="adapt-install"
DEFAULT_UNINSTALLER_NAME="adapt-uninstall"
DEFAULT_CONFIG_DIR="/etc/adapt"
DEFAULT_STATE_DIR="/var/lib/adapt"
DEFAULT_SYSTEMD_SERVICE_NAME="apt-edge.service"
DEFAULT_SYSTEMD_SERVICE_PATH="/etc/systemd/system/${DEFAULT_SYSTEMD_SERVICE_NAME}"

script_name="$(basename "$0")"
script_dir="$(cd "$(dirname "$0")" && pwd)"
if [[ "$(basename "$script_dir")" == "scripts" ]]; then
  inferred_bin_dir="$DEFAULT_BIN_DIR"
else
  inferred_bin_dir="$script_dir"
fi

bin_dir="${ADAPT_BIN_DIR:-$inferred_bin_dir}"
share_dir="${ADAPT_SHARE_DIR:-$DEFAULT_SHARE_DIR}"
installer_name="${ADAPT_INSTALLER_NAME:-$DEFAULT_INSTALLER_NAME}"
uninstaller_name="${ADAPT_UNINSTALLER_NAME:-$DEFAULT_UNINSTALLER_NAME}"
config_dir="${ADAPT_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
state_dir="${ADAPT_STATE_DIR:-$DEFAULT_STATE_DIR}"
systemd_service_name="${ADAPT_SYSTEMD_SERVICE_NAME:-$DEFAULT_SYSTEMD_SERVICE_NAME}"
systemd_service_path="${ADAPT_SYSTEMD_SERVICE_PATH:-$DEFAULT_SYSTEMD_SERVICE_PATH}"

bin_dir_override=0
share_dir_override=0
installer_name_override=0
uninstaller_name_override=0
config_dir_override=0
state_dir_override=0
systemd_service_name_override=0
systemd_service_path_override=0
purge_config=0
purge_state=0
dry_run=0

[[ -n "${ADAPT_BIN_DIR:-}" ]] && bin_dir_override=1
[[ -n "${ADAPT_SHARE_DIR:-}" ]] && share_dir_override=1
[[ -n "${ADAPT_INSTALLER_NAME:-}" ]] && installer_name_override=1
[[ -n "${ADAPT_UNINSTALLER_NAME:-}" ]] && uninstaller_name_override=1
[[ -n "${ADAPT_CONFIG_DIR:-}" ]] && config_dir_override=1
[[ -n "${ADAPT_STATE_DIR:-}" ]] && state_dir_override=1
[[ -n "${ADAPT_SYSTEMD_SERVICE_NAME:-}" ]] && systemd_service_name_override=1
[[ -n "${ADAPT_SYSTEMD_SERVICE_PATH:-}" ]] && systemd_service_path_override=1

usage() {
  cat <<USAGE
Usage:
  ${script_name} [options]

Uninstalls AdaPT Tunnel binaries and shared docs that were installed by the release installer.

Default behavior removes installed binaries and release docs, while preserving runtime config/state.

Options:
  --bin-dir DIR           Installed binary directory (default: ${bin_dir})
  --share-dir DIR         Installed docs/metadata directory (default: ${share_dir})
  --installer-name NAME   Installed updater command name (default: ${installer_name})
  --uninstaller-name NAME Installed uninstall command name (default: ${uninstaller_name})
  --config-dir DIR        Runtime config directory to optionally purge (default: ${config_dir})
  --state-dir DIR         Runtime state directory to optionally purge (default: ${state_dir})
  --systemd-service NAME  Startup service name to remove if present (default: ${systemd_service_name})
  --systemd-unit-path PATH
                         Startup unit path to remove if present (default: ${systemd_service_path})
  --purge-config          Also remove ${config_dir}
  --purge-state           Also remove ${state_dir}
  --purge-all             Remove both config and state directories
  --dry-run               Print planned removals without deleting anything
  -h, --help              Show this help text

Environment overrides:
  ADAPT_BIN_DIR
  ADAPT_SHARE_DIR
  ADAPT_INSTALLER_NAME
  ADAPT_UNINSTALLER_NAME
  ADAPT_CONFIG_DIR
  ADAPT_STATE_DIR
  ADAPT_SYSTEMD_SERVICE_NAME
  ADAPT_SYSTEMD_SERVICE_PATH

Examples:
  sudo ${script_name}
  sudo ${script_name} --purge-config
  sudo ${script_name} --purge-all
USAGE
}

log() {
  printf '==> %s\n' "$*" >&2
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

read_installed_value() {
  local key="$1"
  local meta_path="$2"
  [[ -f "$meta_path" ]] || return 0
  sed -n "s/^${key}=//p" "$meta_path" | tail -n 1
}

find_meta_path() {
  local -a candidates=()
  local candidate=""

  candidates+=("${share_dir}/.install-meta")
  candidate="$(cd "${script_dir}/.." && pwd)/share/adapt/.install-meta"
  if [[ "$candidate" != "${share_dir}/.install-meta" ]]; then
    candidates+=("$candidate")
  fi
  if [[ "${DEFAULT_SHARE_DIR}/.install-meta" != "${share_dir}/.install-meta" && "${DEFAULT_SHARE_DIR}/.install-meta" != "$candidate" ]]; then
    candidates+=("${DEFAULT_SHARE_DIR}/.install-meta")
  fi

  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      [[ $# -ge 2 ]] || die "missing value for --bin-dir"
      bin_dir="$2"
      bin_dir_override=1
      shift 2
      ;;
    --share-dir)
      [[ $# -ge 2 ]] || die "missing value for --share-dir"
      share_dir="$2"
      share_dir_override=1
      shift 2
      ;;
    --installer-name)
      [[ $# -ge 2 ]] || die "missing value for --installer-name"
      installer_name="$2"
      installer_name_override=1
      shift 2
      ;;
    --uninstaller-name)
      [[ $# -ge 2 ]] || die "missing value for --uninstaller-name"
      uninstaller_name="$2"
      uninstaller_name_override=1
      shift 2
      ;;
    --config-dir)
      [[ $# -ge 2 ]] || die "missing value for --config-dir"
      config_dir="$2"
      config_dir_override=1
      shift 2
      ;;
    --state-dir)
      [[ $# -ge 2 ]] || die "missing value for --state-dir"
      state_dir="$2"
      state_dir_override=1
      shift 2
      ;;
    --systemd-service)
      [[ $# -ge 2 ]] || die "missing value for --systemd-service"
      systemd_service_name="$2"
      systemd_service_name_override=1
      shift 2
      ;;
    --systemd-unit-path)
      [[ $# -ge 2 ]] || die "missing value for --systemd-unit-path"
      systemd_service_path="$2"
      systemd_service_path_override=1
      shift 2
      ;;
    --purge-config)
      purge_config=1
      shift
      ;;
    --purge-state)
      purge_state=1
      shift
      ;;
    --purge-all)
      purge_config=1
      purge_state=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

meta_path="${share_dir}/.install-meta"
if existing_meta_path="$(find_meta_path)"; then
  meta_path="$existing_meta_path"
  if [[ "$bin_dir_override" -eq 0 ]]; then
    existing_bin_dir="$(read_installed_value bin_dir "$meta_path")"
    [[ -n "$existing_bin_dir" ]] && bin_dir="$existing_bin_dir"
  fi
  if [[ "$share_dir_override" -eq 0 ]]; then
    existing_share_dir="$(read_installed_value share_dir "$meta_path")"
    [[ -n "$existing_share_dir" ]] && share_dir="$existing_share_dir"
  fi
  if [[ "$installer_name_override" -eq 0 ]]; then
    existing_installer_name="$(read_installed_value installer_name "$meta_path")"
    [[ -n "$existing_installer_name" ]] && installer_name="$existing_installer_name"
  fi
  if [[ "$uninstaller_name_override" -eq 0 ]]; then
    existing_uninstaller_name="$(read_installed_value uninstaller_name "$meta_path")"
    [[ -n "$existing_uninstaller_name" ]] && uninstaller_name="$existing_uninstaller_name"
  fi
fi
meta_path="${share_dir}/.install-meta"

removed=()
skipped=()

maybe_remove() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    if [[ "$dry_run" -eq 1 ]]; then
      removed+=("$path")
      return 0
    fi
    rm -rf "$path"
    removed+=("$path")
  else
    skipped+=("$path")
  fi
}

log "Using bin dir: ${bin_dir}"
log "Using share dir: ${share_dir}"

disable_systemd_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found; skipping disable/stop for ${systemd_service_name}"
    return 0
  fi

  systemctl disable --now "${systemd_service_name}" >/dev/null 2>&1 || \
    warn "could not disable/stop ${systemd_service_name}; continuing"
}

reload_systemd() {
  if [[ "$dry_run" -eq 1 ]]; then
    return 0
  fi
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl daemon-reload >/dev/null 2>&1 || \
    warn "could not reload systemd after removing ${systemd_service_path}"
}

if [[ -e "${systemd_service_path}" || -L "${systemd_service_path}" ]]; then
  disable_systemd_service
  maybe_remove "${systemd_service_path}"
  reload_systemd
else
  skipped+=("${systemd_service_path}")
fi

maybe_remove "${bin_dir}/apt-edge"
maybe_remove "${bin_dir}/apt-client"
maybe_remove "${bin_dir}/apt-clientd"
maybe_remove "${bin_dir}/apt-tunneld"
maybe_remove "${bin_dir}/${installer_name}"
maybe_remove "${bin_dir}/${uninstaller_name}"

maybe_remove "${share_dir}/README.md"
maybe_remove "${share_dir}/SPEC_v1.md"
maybe_remove "${share_dir}/guides"
maybe_remove "${share_dir}/install.sh"
maybe_remove "${share_dir}/uninstall.sh"
maybe_remove "$meta_path"

if [[ "$purge_config" -eq 1 ]]; then
  maybe_remove "$config_dir"
fi
if [[ "$purge_state" -eq 1 ]]; then
  maybe_remove "$state_dir"
fi

if [[ "$dry_run" -eq 0 ]]; then
  rmdir "$share_dir" 2>/dev/null || true
fi

cat <<SUMMARY
AdaPT Tunnel uninstall summary
  bin dir: ${bin_dir}
  share dir: ${share_dir}
  purge config: ${purge_config}
  purge state: ${purge_state}
SUMMARY

if [[ ${#removed[@]} -gt 0 ]]; then
  printf 'Removed paths:\n'
  printf '  %s\n' "${removed[@]}"
else
  printf 'Removed paths:\n'
  printf '  (none)\n'
fi

if [[ "$purge_config" -eq 0 ]]; then
  printf 'Config kept: %s\n' "$config_dir"
fi
if [[ "$purge_state" -eq 0 ]]; then
  printf 'State kept: %s\n' "$state_dir"
fi
if [[ ${#skipped[@]} -gt 0 ]]; then
  printf 'Not present:\n'
  printf '  %s\n' "${skipped[@]}"
fi
