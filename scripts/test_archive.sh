#!/usr/bin/env bash
# A same-version stale default binary must never replace Cargo's selected artifact.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Archive verification requires Linux x86-64.' >&2; exit 2; }
root=$PWD
temporary=$(mktemp -d)
default="$root/target/release/wraith"
existed=0
if [[ -f "$default" ]]; then
  existed=1
  cp -p "$default" "$temporary/original"
fi
restore() {
  if [[ $existed == 1 ]]; then cp -p "$temporary/original" "$default"; else rm -f "$default"; fi
  rm -rf "$temporary"
}
trap restore EXIT
export CARGO_TARGET_DIR="$temporary/cargo-target"
cargo build --release --locked --bin wraith --message-format=json > "$temporary/build.jsonl"
actual=$(python3 - "$temporary/build.jsonl" <<'PY'
import json, pathlib, sys
paths = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    row = json.loads(line)
    if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'wraith' and 'bin' in row['target'].get('kind', []) and row.get('executable'):
        paths.append(row['executable'])
if len(paths) != 1:
    raise SystemExit('Expected one actual Cargo sensor executable')
print(paths[0])
PY
)
mkdir -p "$(dirname "$default")"
cp "$actual" "$default"
printf '\nWRAITH_ARCHIVE_STALE_CANARY\n' >> "$default"
"$default" --version
bash scripts/package_release.sh
tar -xzf target/dist/wraith-linux-x86_64.tar.gz -C "$temporary"
python3 - "$actual" "$temporary/wraith-linux-x86_64/wraith" "$default" <<'PY'
import hashlib, pathlib, sys
hashes = [hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() for path in sys.argv[1:]]
assert hashes[0] != hashes[2], 'same-version canary did not differ from fresh output'
assert hashes[0] == hashes[1], 'archive packaged a stale default binary instead of the actual Cargo artifact'
print('PASS: archive contains the actual Cargo artifact, not a same-version stale default')
PY
