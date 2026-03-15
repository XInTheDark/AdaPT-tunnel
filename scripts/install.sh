#!/usr/bin/env bash
set -euo pipefail

DEFAULT_GITHUB_REPO="XInTheDark/AdaPT-tunnel"
DEFAULT_GITHUB_API_BASE="https://api.github.com"
DEFAULT_GITHUB_WEB_BASE="https://github.com"
DEFAULT_BIN_DIR="/usr/local/bin"
DEFAULT_SHARE_DIR="/usr/local/share/adapt"
DEFAULT_INSTALLER_NAME="adapt-install"
DEFAULT_UNINSTALLER_NAME="adapt-uninstall"

script_name="$(basename "$0")"
script_dir="$(cd "$(dirname "$0")" && pwd)"
action="install"
repo="${ADAPT_GITHUB_REPO:-$DEFAULT_GITHUB_REPO}"
api_base="${ADAPT_GITHUB_API_BASE:-$DEFAULT_GITHUB_API_BASE}"
web_base="${ADAPT_GITHUB_WEB_BASE:-$DEFAULT_GITHUB_WEB_BASE}"
bin_dir="${ADAPT_BIN_DIR:-$DEFAULT_BIN_DIR}"
share_dir="${ADAPT_SHARE_DIR:-$DEFAULT_SHARE_DIR}"
installer_name="${ADAPT_INSTALLER_NAME:-$DEFAULT_INSTALLER_NAME}"
uninstaller_name="${ADAPT_UNINSTALLER_NAME:-$DEFAULT_UNINSTALLER_NAME}"
repo_override=0
api_base_override=0
web_base_override=0
bin_dir_override=0
share_dir_override=0
installer_name_override=0
uninstaller_name_override=0
tag=""
target=""
force=0
dry_run=0

[[ -n "${ADAPT_GITHUB_REPO:-}" ]] && repo_override=1
[[ -n "${ADAPT_GITHUB_API_BASE:-}" ]] && api_base_override=1
[[ -n "${ADAPT_GITHUB_WEB_BASE:-}" ]] && web_base_override=1
[[ -n "${ADAPT_BIN_DIR:-}" ]] && bin_dir_override=1
[[ -n "${ADAPT_SHARE_DIR:-}" ]] && share_dir_override=1
[[ -n "${ADAPT_INSTALLER_NAME:-}" ]] && installer_name_override=1
[[ -n "${ADAPT_UNINSTALLER_NAME:-}" ]] && uninstaller_name_override=1

usage() {
  cat <<USAGE
Usage:
  ${script_name} [install|update] [options]

Downloads the matching AdaPT Tunnel release bundle from GitHub and installs:
  - apt-edge
  - apt-client
  - apt-clientd
  - apt-tunneld
  - ${installer_name} (this installer script for later updates)
  - ${uninstaller_name} (an uninstall helper)

Default repository:
  ${DEFAULT_GITHUB_REPO}

Commands:
  install    Install the latest release (default)
  update     Update an existing install to the latest release

Options:
  --repo OWNER/REPO     Override the GitHub repository (default: ${repo})
  --api-base URL        Override the GitHub API base (default: ${api_base})
  --web-base URL        Override the GitHub web base (default: ${web_base})
  --tag TAG             Install a specific release tag instead of the latest release
  --target TARGET       Override the auto-detected release target triple
  --bin-dir DIR         Install binaries into DIR (default: ${bin_dir})
  --share-dir DIR       Install docs/metadata into DIR (default: ${share_dir})
  --installer-name NAME Name of the installed updater command (default: ${installer_name})
  --uninstaller-name NAME
                        Name of the installed uninstall command (default: ${uninstaller_name})
  --force               Reinstall even if the same tag is already installed
  --dry-run             Print the chosen release/asset and exit without downloading
  -h, --help            Show this help text

Environment overrides:
  ADAPT_GITHUB_REPO
  ADAPT_GITHUB_API_BASE
  ADAPT_GITHUB_WEB_BASE
  ADAPT_BIN_DIR
  ADAPT_SHARE_DIR
  ADAPT_INSTALLER_NAME
  ADAPT_UNINSTALLER_NAME
  GH_TOKEN / GITHUB_TOKEN   Optional token for higher GitHub API limits or private repos

Examples:
  sudo ${script_name}
  sudo ${script_name} update
  sudo ${script_name} --repo your-org/AdaPT-tunnel
  sudo ${script_name} --target x86_64-unknown-linux-gnu
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

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: ${command_name}"
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

download_file() {
  local url="$1"
  local output="$2"
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

  if command -v curl >/dev/null 2>&1; then
    local -a args=(-fsSL -o "$output")
    if [[ -n "$token" ]]; then
      args+=(-H "Authorization: Bearer ${token}")
    fi
    if [[ "$url" == "${api_base%/}/"* ]]; then
      args+=(-H "Accept: application/vnd.github+json")
    elif [[ "$url" == *"/releases/assets/"* ]]; then
      args+=(-H "Accept: application/octet-stream")
    fi
    curl "${args[@]}" "$url"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    local -a args=(-q -O "$output")
    if [[ -n "$token" ]]; then
      args+=(--header "Authorization: Bearer ${token}")
    fi
    if [[ "$url" == "${api_base%/}/"* ]]; then
      args+=(--header "Accept: application/vnd.github+json")
    elif [[ "$url" == *"/releases/assets/"* ]]; then
      args+=(--header "Accept: application/octet-stream")
    fi
    wget "${args[@]}" "$url"
    return
  fi

  die "either curl or wget is required for downloads"
}

infer_target() {
  local os
  local arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)
      case "$arch" in
        x86_64|amd64)
          printf 'x86_64-unknown-linux-musl\n'
          ;;
        *)
          die "no published Linux release asset for architecture: ${arch}"
          ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64|amd64)
          printf 'x86_64-apple-darwin\n'
          ;;
        arm64|aarch64)
          printf 'aarch64-apple-darwin\n'
          ;;
        *)
          die "no published macOS release asset for architecture: ${arch}"
          ;;
      esac
      ;;
    *)
      die "unsupported operating system: ${os}"
      ;;
  esac
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

if [[ $# -gt 0 ]]; then
  case "$1" in
    install|update)
      action="$1"
      shift
      ;;
    help|-h|--help)
      usage
      exit 0
      ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -ge 2 ]] || die "missing value for --repo"
      repo="$2"
      repo_override=1
      shift 2
      ;;
    --api-base)
      [[ $# -ge 2 ]] || die "missing value for --api-base"
      api_base="$2"
      api_base_override=1
      shift 2
      ;;
    --web-base)
      [[ $# -ge 2 ]] || die "missing value for --web-base"
      web_base="$2"
      web_base_override=1
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || die "missing value for --tag"
      tag="$2"
      shift 2
      ;;
    --target)
      [[ $# -ge 2 ]] || die "missing value for --target"
      target="$2"
      shift 2
      ;;
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
    --force)
      force=1
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

require_command python3
require_command tar
require_command install
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  die "either sha256sum or shasum is required for checksum verification"
fi

target="${target:-$(infer_target)}"

case "$target" in
  x86_64-unknown-linux-musl|x86_64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin)
    ;;
  *)
    warn "target ${target} is not in the standard supported set; continuing anyway"
    ;;
esac

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
  if [[ "$repo_override" -eq 0 ]]; then
    existing_repo="$(read_installed_value repo "$meta_path")"
    [[ -n "$existing_repo" ]] && repo="$existing_repo"
  fi
  if [[ "$api_base_override" -eq 0 ]]; then
    existing_api_base="$(read_installed_value api_base "$meta_path")"
    [[ -n "$existing_api_base" ]] && api_base="$existing_api_base"
  fi
  if [[ "$web_base_override" -eq 0 ]]; then
    existing_web_base="$(read_installed_value web_base "$meta_path")"
    [[ -n "$existing_web_base" ]] && web_base="$existing_web_base"
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

tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t adapt-install)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

metadata_path="$tmpdir/release.json"
if [[ -n "${ADAPT_RELEASE_METADATA_FILE:-}" ]]; then
  cp "$ADAPT_RELEASE_METADATA_FILE" "$metadata_path"
else
  if [[ -n "$tag" ]]; then
    release_url="${api_base%/}/repos/${repo}/releases/tags/${tag}"
  else
    release_url="${api_base%/}/repos/${repo}/releases/latest"
  fi
  log "Fetching release metadata from ${release_url}"
  if ! download_file "$release_url" "$metadata_path"; then
    die "failed to fetch release metadata from ${release_url}"
  fi
fi

mapfile -t release_info < <(TARGET="$target" python3 - "$metadata_path" <<'PY'
import json
import os
import sys

path = sys.argv[1]
target = os.environ["TARGET"]
with open(path, "r", encoding="utf-8") as handle:
    release = json.load(handle)

if "tag_name" not in release:
    print("release metadata does not include tag_name", file=sys.stderr)
    sys.exit(1)

bundle_name = f"adapt-tunnel-{target}.tar.gz"
checksum_name = f"adapt-tunnel-{target}.sha256"
assets = {asset.get("name"): asset for asset in release.get("assets", []) if asset.get("name")}

def asset_url(name):
    asset = assets.get(name)
    if asset is None:
        return None
    return asset.get("browser_download_url") or asset.get("url")

bundle_asset = assets.get(bundle_name)
checksum_asset = assets.get(checksum_name)
if bundle_asset is None or checksum_asset is None:
    print(
        f"release {release['tag_name']} does not contain the expected assets: {bundle_name} and {checksum_name}",
        file=sys.stderr,
    )
    sys.exit(2)

print(release["tag_name"])
print(bundle_name)
print(asset_url(bundle_name) or "")
print(asset_url(checksum_name) or "")
PY
)

[[ ${#release_info[@]} -eq 4 ]] || die "failed to parse release metadata"
release_tag="${release_info[0]}"
asset_name="${release_info[1]}"
asset_url="${release_info[2]}"
checksum_url="${release_info[3]}"
checksum_name="${asset_name%.tar.gz}.sha256"

if [[ -z "$asset_url" ]]; then
  asset_url="${web_base%/}/${repo}/releases/download/${release_tag}/${asset_name}"
fi
if [[ -z "$checksum_url" ]]; then
  checksum_url="${web_base%/}/${repo}/releases/download/${release_tag}/${checksum_name}"
fi

installed_tag="$(read_installed_value tag "$meta_path")"
installed_target="$(read_installed_value target "$meta_path")"

if [[ "$dry_run" -eq 1 ]]; then
  cat <<DRYRUN
repo=${repo}
api_base=${api_base}
web_base=${web_base}
action=${action}
release_tag=${release_tag}
target=${target}
asset_name=${asset_name}
asset_url=${asset_url}
checksum_url=${checksum_url}
bin_dir=${bin_dir}
share_dir=${share_dir}
installer_name=${installer_name}
uninstaller_name=${uninstaller_name}
installed_tag=${installed_tag}
installed_target=${installed_target}
DRYRUN
  exit 0
fi

if [[ -n "$installed_tag" && "$installed_tag" == "$release_tag" && "$installed_target" == "$target" && "$force" -eq 0 ]]; then
  if [[ "$action" == "update" ]]; then
    log "AdaPT Tunnel is already up to date at ${release_tag} (${target})"
  else
    log "AdaPT Tunnel ${release_tag} (${target}) is already installed; use --force to reinstall"
  fi
  exit 0
fi

archive_path="$tmpdir/$asset_name"
checksum_path="$tmpdir/$checksum_name"
extract_dir="$tmpdir/extract"

log "Downloading ${asset_name}"
download_file "$asset_url" "$archive_path"
log "Downloading ${checksum_name}"
download_file "$checksum_url" "$checksum_path"

expected_checksum="$(awk 'NF { print $1; exit }' "$checksum_path")"
[[ -n "$expected_checksum" ]] || die "failed to read checksum from ${checksum_name}"
actual_checksum="$(sha256_file "$archive_path")"
[[ "$actual_checksum" == "$expected_checksum" ]] || die "checksum mismatch for ${asset_name}"

mkdir -p "$extract_dir"
log "Extracting ${asset_name}"
tar -xzf "$archive_path" -C "$extract_dir"

stage_dir="$extract_dir/adapt-tunnel-${target}"
[[ -d "$stage_dir" ]] || die "release archive did not unpack as expected"
[[ -f "$stage_dir/bin/apt-edge" ]] || die "release archive is missing apt-edge"
[[ -f "$stage_dir/bin/apt-client" ]] || die "release archive is missing apt-client"
[[ -f "$stage_dir/bin/apt-clientd" ]] || die "release archive is missing apt-clientd"
[[ -f "$stage_dir/bin/apt-tunneld" ]] || die "release archive is missing apt-tunneld"
[[ -f "$stage_dir/install.sh" ]] || die "release archive is missing install.sh"
[[ -f "$stage_dir/uninstall.sh" ]] || die "release archive is missing uninstall.sh"

log "Installing binaries into ${bin_dir}"
mkdir -p "$bin_dir"
install -m 0755 "$stage_dir/bin/apt-edge" "$bin_dir/apt-edge"
install -m 0755 "$stage_dir/bin/apt-client" "$bin_dir/apt-client"
install -m 0755 "$stage_dir/bin/apt-clientd" "$bin_dir/apt-clientd"
install -m 0755 "$stage_dir/bin/apt-tunneld" "$bin_dir/apt-tunneld"
install -m 0755 "$stage_dir/install.sh" "$bin_dir/$installer_name"
install -m 0755 "$stage_dir/uninstall.sh" "$bin_dir/$uninstaller_name"

log "Installing docs and metadata into ${share_dir}"
mkdir -p "$share_dir"
rm -rf "$share_dir/guides"
install -m 0644 "$stage_dir/README.md" "$share_dir/README.md"
install -m 0644 "$stage_dir/SPEC_v1.md" "$share_dir/SPEC_v1.md"
cp -R "$stage_dir/guides" "$share_dir/guides"
install -m 0755 "$stage_dir/install.sh" "$share_dir/install.sh"
install -m 0755 "$stage_dir/uninstall.sh" "$share_dir/uninstall.sh"

cat > "$meta_path" <<METADATA
bin_dir=${bin_dir}
share_dir=${share_dir}
repo=${repo}
api_base=${api_base}
web_base=${web_base}
tag=${release_tag}
target=${target}
installer_name=${installer_name}
uninstaller_name=${uninstaller_name}
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
METADATA

if [[ ":${PATH}:" != *":${bin_dir}:"* ]]; then
  warn "${bin_dir} is not currently in PATH"
fi

cat <<SUMMARY
Installed AdaPT Tunnel ${release_tag}
  target: ${target}
  repo: ${repo}
  binaries: ${bin_dir}
  updater: ${bin_dir}/${installer_name}
  uninstaller: ${bin_dir}/${uninstaller_name}
  docs: ${share_dir}

Next steps:
  sudo apt-edge init
  sudo apt-edge start
  sudo ${installer_name} update
  sudo ${uninstaller_name}
SUMMARY
