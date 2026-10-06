#!/usr/bin/env bash
# Usage: package-release.sh <version> <target-triple> <binary> <output-dir>
# Builds op-secretd_<version>_linux_<arch>.tar.gz deterministically and prints its path.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <version> <target-triple> <binary> <output-dir>" >&2
  exit 2
fi
version=$1
target=$2
binary=$3
output=$4

case "$target" in
  x86_64-unknown-linux-musl) arch=x86_64 ;;
  aarch64-unknown-linux-musl) arch=aarch64 ;;
  *)
    echo "unsupported target: $target" >&2
    exit 1
    ;;
esac

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
name="op-secretd_${version}_linux_${arch}"
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
stage="$temp/$name"

install -d "$stage/share/op-secretd"
install -m 0755 "$binary" "$stage/op-secretd"
install -m 0644 "$repo/packaging/op-secretd.service" "$stage/share/op-secretd/op-secretd.service"
install -m 0644 "$repo/packaging/org.freedesktop.secrets.service" \
  "$stage/share/op-secretd/org.freedesktop.secrets.service"
# The binary is the single source of truth for the example configuration.
"$stage/op-secretd" --config "$stage/share/op-secretd/config.example.toml" config init >/dev/null
chmod 0644 "$stage/share/op-secretd/config.example.toml"
install -m 0644 "$repo/LICENSE" "$stage/LICENSE"
install -m 0644 "$repo/README.md" "$stage/README.md"

# A stable timestamp keeps the archive reproducible for a given commit.
: "${SOURCE_DATE_EPOCH:=$(git -C "$repo" log -1 --format=%ct)}"
mkdir -p "$output"
archive="$output/$name.tar.gz"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
  --format=posix --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' \
  -C "$temp" -cf - "$name" | gzip -n -9 >"$archive"
printf '%s\n' "$archive"
