#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <rust-target-triple>" >&2
  exit 1
fi

target="$1"
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
dist_dir="$root_dir/dist"
asset_basename="adapt-tunnel-${target}"
stage_dir="$dist_dir/$asset_basename"
archive_path="$dist_dir/${asset_basename}.tar.gz"
checksum_path="$dist_dir/${asset_basename}.sha256"

rm -rf "$stage_dir" "$archive_path" "$checksum_path"
mkdir -p "$stage_dir/bin" "$stage_dir/guides/examples"

cp "$root_dir/target/$target/release/apt-edge" "$stage_dir/bin/"
cp "$root_dir/target/$target/release/apt-client" "$stage_dir/bin/"
cp "$root_dir/target/$target/release/apt-clientd" "$stage_dir/bin/"
cp "$root_dir/target/$target/release/apt-tunneld" "$stage_dir/bin/"
chmod 755 "$stage_dir/bin/apt-edge" "$stage_dir/bin/apt-client" "$stage_dir/bin/apt-clientd" "$stage_dir/bin/apt-tunneld"

cp "$root_dir/README.md" "$stage_dir/"
cp "$root_dir/SPEC_v1.md" "$stage_dir/"
cp "$root_dir/scripts/install.sh" "$stage_dir/install.sh"
cp "$root_dir/scripts/uninstall.sh" "$stage_dir/uninstall.sh"
chmod 755 "$stage_dir/install.sh"
chmod 755 "$stage_dir/uninstall.sh"
cp "$root_dir/guides/DEPLOYMENT.md" "$stage_dir/guides/"
cp "$root_dir/guides/MANUAL-CONFIG-SETUP.md" "$stage_dir/guides/"
cp "$root_dir/guides/MANUAL-TESTING.md" "$stage_dir/guides/"
cp "$root_dir/guides/examples/server.toml" "$stage_dir/guides/examples/"
cp "$root_dir/guides/examples/client.toml" "$stage_dir/guides/examples/"

mkdir -p "$dist_dir"
tar -C "$dist_dir" -czf "$archive_path" "$asset_basename"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$archive_path" > "$checksum_path"
else
  shasum -a 256 "$archive_path" > "$checksum_path"
fi

echo "Created:"
echo "  $archive_path"
echo "  $checksum_path"
