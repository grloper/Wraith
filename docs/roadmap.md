# Scoped roadmap

The roadmap is a contribution backlog, not a list of shipped features.

## Reliability before new backends

- Preserve job-control stops and validate SIGSTOP/SIGCONT across run/attach modes.
- Isolate waits when embedding multiple tracers/unrelated children in one process.
- Bound historical dashboard process rows for fork-heavy long-lived targets.
- Validate teardown/error paths across multiple kernels and namespace configurations.

Each item needs a real-process reproducer, a regression that fails before the
fix, and evidence that borrowed tracees remain alive where appropriate.

## Accuracy

- Correlate successful syscall returns with concrete executable allocations;
  expire evidence rather than accumulating unrelated process-lifetime milestones.
- Enroll legitimate alternate stacks/JIT arenas without trusting broad address ranges.
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
