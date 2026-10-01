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
python3 scripts/check_brand.py
python3 scripts/test_brand.py
python3 scripts/test_report.py
python3 scripts/test_workloads.py
bash -n demo.sh scripts/verify.sh scripts/package_release.sh scripts/package_deb.sh scripts/test_deb.sh scripts/test_archive.sh .githooks/pre-commit
# These artifact freshness tests temporarily replace/restore a default binary;
# keep them sequential and never overlap them with performance measurements.
bash scripts/test_deb.sh
bash scripts/test_archive.sh
printf '\nPASS: formatting, Clippy, strict tests, release build, bounded investigation workflows, package and documentation gates.\n'
