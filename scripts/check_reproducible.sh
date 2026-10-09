#!/usr/bin/env bash
# Build the sensor twice from scratch in separate target directories and compare
# SHA-256. Proves reproducibility on THIS toolchain/host only.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
for n in 1 2; do
  CARGO_TARGET_DIR="$tmp/target$n" cargo build --release --locked --bin wraith
  sha256sum "$tmp/target$n/release/wraith" | tee "$tmp/sum$n.txt"
done
a=$(cut -d' ' -f1 "$tmp/sum1.txt"); b=$(cut -d' ' -f1 "$tmp/sum2.txt")
if [[ "$a" != "$b" ]]; then
  echo "NOT REPRODUCIBLE: $a != $b" >&2; exit 1
fi
echo "REPRODUCIBLE: $a"
