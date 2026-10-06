#!/usr/bin/env bash
# Usage: validate-release-version.sh <tag> <Cargo.toml>
# Checks that a vX.Y.Z tag matches the crate version and prints the version.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <Cargo.toml>" >&2
  exit 2
fi
tag=$1
manifest=$2

if [[ ! $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  echo "tag '$tag' is not of the form vX.Y.Z" >&2
  exit 1
fi
version=${BASH_REMATCH[1]}

crate_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$manifest" | head -n1)
if [[ "$crate_version" != "$version" ]]; then
  echo "tag $tag does not match the crate version '$crate_version' in $manifest" >&2
  exit 1
fi
printf '%s\n' "$version"
