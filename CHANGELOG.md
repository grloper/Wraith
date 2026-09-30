# Changelog

## Unreleased

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
