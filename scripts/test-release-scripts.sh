#!/usr/bin/env bash
# Tests for the release helper scripts; needs only bash, git, tar and gzip.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# --- validate-release-version.sh
printf '[package]\nname = "x"\nversion = "1.2.3"\n' >"$temp/Cargo.toml"
[[ $("$repo/scripts/validate-release-version.sh" v1.2.3 "$temp/Cargo.toml") == 1.2.3 ]] || fail "version output"
"$repo/scripts/validate-release-version.sh" v1.2.4 "$temp/Cargo.toml" 2>/dev/null && fail "mismatched tag accepted"
"$repo/scripts/validate-release-version.sh" 1.2.3 "$temp/Cargo.toml" 2>/dev/null && fail "tag without v accepted"
"$repo/scripts/validate-release-version.sh" v1.2.3-rc1 "$temp/Cargo.toml" 2>/dev/null && fail "pre-release tag accepted"

# --- package-release.sh with a stand-in binary
cat >"$temp/op-secretd" <<'SCRIPT'
#!/bin/sh
# Stand-in for `op-secretd --config <path> config init`.
[ "$3" = config ] && [ "$4" = init ] && printf 'vault = "x"\n' >"$2"
SCRIPT
chmod 0755 "$temp/op-secretd"
export SOURCE_DATE_EPOCH=1700000000
first=$("$repo/scripts/package-release.sh" 1.2.3 x86_64-unknown-linux-musl "$temp/op-secretd" "$temp/out1")
second=$("$repo/scripts/package-release.sh" 1.2.3 x86_64-unknown-linux-musl "$temp/op-secretd" "$temp/out2")
[[ $(basename "$first") == op-secretd_1.2.3_linux_x86_64.tar.gz ]] || fail "archive name: $first"
cmp "$first" "$second" || fail "archives are not reproducible"

listing=$(tar -tzf "$first")
for expected in \
  op-secretd_1.2.3_linux_x86_64/op-secretd \
  op-secretd_1.2.3_linux_x86_64/LICENSE \
  op-secretd_1.2.3_linux_x86_64/README.md \
  op-secretd_1.2.3_linux_x86_64/share/op-secretd/op-secretd.service \
  op-secretd_1.2.3_linux_x86_64/share/op-secretd/org.freedesktop.secrets.service \
  op-secretd_1.2.3_linux_x86_64/share/op-secretd/config.example.toml; do
  grep -Fxq "$expected" <<<"$listing" || fail "missing $expected"
done
verbose=$(tar -tvzf "$first")
grep -q 'rwxr-xr-x 0/0 .* op-secretd_1.2.3_linux_x86_64/op-secretd$' <<<"$verbose" || fail "binary mode or owner"
grep -q '2023-11-14' <<<"$verbose" || fail "timestamps are not pinned"

"$repo/scripts/package-release.sh" 1.2.3 riscv64-unknown-linux-musl "$temp/op-secretd" "$temp/out3" 2>/dev/null &&
  fail "unsupported target accepted"
aarch=$("$repo/scripts/package-release.sh" 1.2.3 aarch64-unknown-linux-musl "$temp/op-secretd" "$temp/out4")
[[ $(basename "$aarch") == op-secretd_1.2.3_linux_aarch64.tar.gz ]] || fail "aarch64 name"

# --- check-conventional-commits.sh in a scratch repository
git init -q "$temp/repo"
git -C "$temp/repo" config user.email t@example.invalid
git -C "$temp/repo" config user.name T
git -C "$temp/repo" commit -q --allow-empty -m "chore: start"
git -C "$temp/repo" commit -q --allow-empty -m "feat(dbus)!: breaking change"
(cd "$temp/repo" && "$repo/scripts/check-conventional-commits.sh" HEAD) || fail "valid subjects rejected"
git -C "$temp/repo" commit -q --allow-empty -m "Fix the thing"
(cd "$temp/repo" && "$repo/scripts/check-conventional-commits.sh" HEAD 2>/dev/null) && fail "invalid subject accepted"

echo "release script tests passed"
