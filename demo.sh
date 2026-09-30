#!/usr/bin/env bash
# Local fixtures only. Fail if a verdict or enforcement behavior regresses.
set -euo pipefail
cd "$(dirname "$0")"
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'Wraith demos require x86-64 Linux.' >&2
  exit 2
fi
cargo build --release --locked --quiet
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
wraith=./target/release/wraith
run_case() {
  local label=$1 expected=$2 target=$3 mode=${4:-}
  local code=0
  echo
  printf '==> %s (expected sensor exit %s)\n' "$label" "$expected"
  local flags=()
  [[ -z $mode ]] || flags+=("$mode")
  "$wraith" run "${flags[@]}" --json "$out/$label.jsonl" -- "./target/release/$target" >"$out/$label.stdout" 2>"$out/$label.stderr" || code=$?
  cat "$out/$label.stdout" "$out/$label.stderr"
  if [[ $code != "$expected" ]]; then
    printf 'FAIL: %s exited %s, expected %s\n' "$label" "$code" "$expected" >&2
    exit 1
  fi
}
run_case benign 0 benign
run_case benign-threads 0 benign-threads
run_case injected 3 shellcode-sim
run_case injected-worker 3 mt-shellcode-sim
run_case block 3 shellcode-sim --block
run_case kill 3 shellcode-sim --kill
python3 - "$out" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for name in ('benign', 'benign-threads'):
    assert not (root / f'{name}.jsonl').read_text(), f'{name}: unexpected detections'
for name in ('injected', 'injected-worker', 'block', 'kill'):
    events = [json.loads(line) for line in (root / f'{name}.jsonl').read_text().splitlines()]
    assert any(e['kind'] == 'foreign_origin_syscall' and e['severity'] == 'CRITICAL' for e in events), name
    assert any(e['kind'] == 'exploitation_chain' for e in events), name
blocked = (root / 'block.stdout').read_text()
assert 'socket() -> -38' in blocked, 'blocked syscall did not return ENOSYS'
assert 'shellcode-sim: done' in blocked, 'block must let fixture finish'
assert any(json.loads(line)['kind'] == 'blocked' for line in (root / 'block.jsonl').read_text().splitlines())
assert any(json.loads(line)['kind'] == 'killed' for line in (root / 'kill.jsonl').read_text().splitlines())
assert 'payload ran' not in (root / 'kill.stdout').read_text(), 'killed payload executed'
print('\nPASS: both controls clean; main/worker injection detected; block and kill verified.')
PY
