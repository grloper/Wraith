#!/usr/bin/env bash
# Produce a sensor-only binary archive; no network publication or tagging.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'Packaging requires Linux x86-64.' >&2; exit 2;
}
cargo build --release --locked
root=target/dist
mkdir -p "$root"
temporary=$(mktemp -d "$root/.release.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
stage="$temporary/wraith-linux-x86_64"
mkdir -p "$stage"
cp target/release/wraith LICENSE README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md "$stage/"
cp -R docs "$stage/"
tar -C "$temporary" -czf "$root/wraith-linux-x86_64.tar.gz" wraith-linux-x86_64
(cd "$root" && sha256sum wraith-linux-x86_64.tar.gz > SHA256SUMS && sha256sum -c SHA256SUMS)
printf 'Created %s/wraith-linux-x86_64.tar.gz and SHA256SUMS\n' "$root"
