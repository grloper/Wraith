# Changelog

## Unreleased

### Maintained investigation foundations

- Make required-map coverage failures visible, discard stale decision caches and
  return operational code 2 even after recovery or output filtering.
- Correlate actual successful protection/positive-input exits with bounded,
  expiring address-span evidence; keep invalidating maps after partial failures.
- Enroll successfully observed native per-thread signal stacks for placement only;
  preserve executable-origin checks and conservative unknown/inherited cases.
- Bound retired process rows, retain live rows/aggregate counters and reset reused IDs.
- Isolate waits across creator OS threads with real concurrent/unrelated-child controls.
- Add owned-child `doctor` preflight, configurable evidence/history bounds and
  schema-2 event metadata with terminal-safe explanations.
- Distinguish handled signal-delivery stops from confirmed fatal termination;
  do not report ordinary JVM signal handling as HIGH crash evidence.
- Create new JSONL evidence files owner-only without altering existing log permissions.
- Add strict bounded JSONL triage, real HTTP/SQLite timing and legal-runtime controls.
- Build actual amd64 `.deb` artifacts without privilege/service activation; select
  Cargo's real executable paths, reject stale same-version canaries, and verify
  extraction, dependencies, permissions, manifests and fixed-input reproducibility.
- Publish primary-source Linux/Kali comparisons and explicit deployment/pilot gates.

These are development capabilities, not a finalized endpoint product or a
population-wide detection/performance guarantee. Event-schema revisions do not
rename the project.

### Detection accuracy and safety

- Classify named anonymous mappings as anonymous instead of trusting square brackets.
- Apply executable/write checks before accepting known kernel code mappings.
- Require full-span trust for protection requests; do not trust an mmap address hint.
- Keep default anonymous RX sensitive execution and W→X transitions at WARN;
  explicit no-JIT policy can elevate them. Prevent old foreign evidence from escalating trusted code.
- Treat missing/NX map origins as uncertainty rather than enforcement proof.
- Inspect writable intersections across protection spans.
- Invalidate maps across completed memory operations and reset state on exec.

### Tracing and telemetry

- Classify actual syscall entry/exit stops and reject unsupported x32 ABI calls.
- Handle leader/nonleader exec and attach all preexisting sibling threads.
- Add construction/drop cleanup and retry interrupted waits.
- Fail closed on enforcement errors rather than logging false success.
- Keep launched target stdout out of JSON stdout, report target outcomes, and
  return an operational error on evidence-sink failure.
- Reject conflicting enforcement modes and fail explicitly on unsupported launched
  group stops instead of silently bypassing SIGSTOP.

### Verification and community

- Assert benign, main-thread, worker-thread, block and kill demo outcomes.
- Add actual reproducible terminal SVG/asciicast capture and workload benchmark scripts.
- Document the threat model, Linux research, operations, contribution workflow and launch kit.
- Add strict Linux quality gates, MSRV CI matrix, package checks and sensor-only
  release artifacts with checksums. No automatic public publishing.

Pre-1.0 APIs and severity policy may change. Review the threat model before upgrading
an enforcement deployment; a clean verdict is not proof of absence of exploitation.
