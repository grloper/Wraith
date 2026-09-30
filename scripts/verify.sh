#!/usr/bin/env bash
# Release gate: unavailable tracing is a failure, not hidden test coverage.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'Verification requires Linux x86-64.' >&2; exit 2;
}
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
WRAITH_REQUIRE_PTRACE=1 timeout 180 cargo test --all-targets --locked
cargo build --release --locked
python3 scripts/check_docs.py
bash -n demo.sh scripts/verify.sh scripts/package_release.sh .githooks/pre-commit
printf '\nPASS: formatting, Clippy, strict tests, release build and documentation gates.\n'
