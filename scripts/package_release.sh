#!/usr/bin/env bash
# Produce a sensor-only binary archive; no network publication or tagging.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'Packaging requires Linux x86-64.' >&2; exit 2;
}
root=target/dist
mkdir -p "$root"
temporary=$(mktemp -d "$root/.release.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
# Cargo may use CARGO_TARGET_DIR or a configured target triple. Select its actual
# fresh artifact instead of silently copying a same-version stale default file.
cargo build --release --locked --bin wraith --message-format=json > "$temporary/build.jsonl"
binary=$(python3 - "$temporary/build.jsonl" <<'PY'
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
"$binary" --version
stage="$temporary/wraith-linux-x86_64"
mkdir -p "$stage"
cp "$binary" "$stage/wraith"
cmp "$binary" "$stage/wraith"
cp LICENSE README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md "$stage/"
cp -R docs "$stage/"
tar -C "$temporary" -czf "$root/wraith-linux-x86_64.tar.gz" wraith-linux-x86_64
(cd "$root" && sha256sum wraith-linux-x86_64.tar.gz > SHA256SUMS && sha256sum -c SHA256SUMS)
printf 'Created %s/wraith-linux-x86_64.tar.gz and SHA256SUMS\n' "$root"
