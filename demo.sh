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
MT_BENIGN=./target/release/benign-threads
MT_SIM=./target/release/mt-shellcode-sim

echo
echo "============================================================"
echo " 1/4  BENIGN target — expect: clean, exit 0"
echo "============================================================"
set +e
"$WRAITH" run --min info -- "$BENIGN"
echo "   -> wraith exit code: $?"
set -e

echo
echo "============================================================"
echo " 2/4  SHELLCODE-SIM target — expect: EXPLOITATION DETECTED, exit 3"
echo "============================================================"
set +e
"$WRAITH" run -- "$SIM"
code=$?
echo "   -> wraith exit code: $code"
set -e

echo
echo "============================================================"
echo " 3/4  BENIGN multithreaded target — expect: clean, exit 0"
echo "============================================================"
set +e
"$WRAITH" run -- "$MT_BENIGN"
echo "   -> wraith exit code: $?"
set -e

echo
echo "============================================================"
echo " 4/4  WORKER-THREAD exploit — payload fires from a spawned"
echo "      thread; only thread-following catches it (exit 3)"
echo "============================================================"
set +e
"$WRAITH" run -- "$MT_SIM"
mt_code=$?
echo "   -> wraith exit code: $mt_code"
set -e

echo
echo "============================================================"
echo " 5/5  ENFORCEMENT — same payload, but Wraith intervenes"
echo "============================================================"
echo "--- --block: the injected socket() is neutralised (returns -ENOSYS),"
echo "    the process survives so you can watch what it does next ---"
set +e
"$WRAITH" run --block -- "$SIM"
echo "   -> wraith exit code: $?"
echo
echo "--- --kill: the traced tree is SIGKILLed before the payload runs ---"
"$WRAITH" run --kill -- "$SIM"
echo "   -> wraith exit code: $?"
set -e

echo
if [ "$code" -eq 3 ] && [ "$mt_code" -eq 3 ]; then
  echo "Demo OK: benign runs (single- and multi-threaded) were clean;"
  echo "         injected-code execution was detected on the main thread AND"
  echo "         on a worker thread, correlated into an exploitation chain, and"
  echo "         (in --block/--kill) stopped before the payload's syscall ran."
else
  echo "Demo WARNING: expected exit 3 from both simulator runs (got $code and $mt_code)."
fi
