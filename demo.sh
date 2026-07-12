#!/usr/bin/env bash
# Side-by-side demonstration: Wraith stays silent on a benign program and
# catches the payload simulator executing a syscall from injected memory.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> building (release)"
cargo build --release --quiet

WRAITH=./target/release/wraith
BENIGN=./target/release/benign
SIM=./target/release/shellcode-sim

echo
echo "============================================================"
echo " 1/2  BENIGN target — expect: clean, exit 0"
echo "============================================================"
set +e
"$WRAITH" run --min info -- "$BENIGN"
echo "   -> wraith exit code: $?"
set -e

echo
echo "============================================================"
echo " 2/2  SHELLCODE-SIM target — expect: EXPLOITATION DETECTED, exit 3"
echo "============================================================"
set +e
"$WRAITH" run -- "$SIM"
code=$?
echo "   -> wraith exit code: $code"
set -e

echo
if [ "$code" -eq 3 ]; then
  echo "Demo OK: benign was clean; injected-code execution was detected and correlated."
else
  echo "Demo WARNING: expected exit 3 from the simulator run (got $code)."
fi
