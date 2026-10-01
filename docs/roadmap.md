# Scoped roadmap

The roadmap is a contribution backlog, not a list of shipped features.

## Reliability before new backends

- Preserve job-control stops and validate SIGSTOP/SIGCONT across run/attach modes.
- Extend beyond tested OS-thread wait isolation: arbitrary untraced children created
  by the same tracer thread still require a dedicated-process boundary.
- Stress the implemented retired-history cap under longer-lived native workloads
  without evicting live targets or losing aggregate counters.
- Validate teardown/error paths across multiple kernels and namespace configurations.

Each item needs a real-process reproducer, a regression that fails before the
fix, and evidence that borrowed tracees remain alive where appropriate.

## Accuracy

- Refine the shipped successful, expiring address-span correlation with allocation
  generations, reuse/concurrent-mutation tests and causal limitations.
- Expand observed per-thread alternate-stack enrollment to preexisting/inherited
  configurations and coroutines; JIT attestation remains separate from broad trust.
- Assess modified file-backed code and dual mappings without hashing every syscall.
- Expand benign controls across actual runtimes and publish their configurations.

Acceptance requires both positive injection controls and legitimate negative controls.
Do not claim a false-positive rate from only synthetic fixtures.

## Performance

- Publish native-Linux service workloads with raw baseline/traced samples.
- Reduce repeated event construction where policy permits without hiding evidence.
- Design an eBPF observation backend with explicit dropped-event accounting and
  map-provenance synchronization; enforcement must be designed separately.

No near-zero-overhead claim is accepted without a reproducible measurement.
