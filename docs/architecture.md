# Architecture

```text
CLI → Tracer (Linux transport) → Engine (per-address-space state)
                                  ├─ MemoryMap → binary-search interval lookup
                                  ├─ Detector → origin / permissions / stack / chain
                                  └─ Reporter → text, JSONL, terminal dashboard
```

| Module | Responsibility |
|---|---|
| `src/maps.rs` | Parse procfs mappings into sorted typed intervals |
| `src/provenance.rs` | Classify syscall and stack addresses |
| `src/syscalls.rs` | x86-64 syscall names and policy categories |
| `src/detect.rs` | Rules, trust ranges, severity and chain state |
| `src/engine.rs` | Shared map cache, counters, lifecycle and action policy |
| `src/tracer.rs` | Spawn/attach, ptrace stops, threads, signals and enforcement |
| `src/event.rs` | Event schema, terminal-safe text and JSON escaping |
| `src/ui.rs` | Bounded event feed and ANSI dashboard |
| `src/bin/wraith.rs` | CLI selection, output routing and sensor exit status |

The `Backend` trait decouples register transport from rules; only ptrace is
implemented. Reuse of the rules by another backend does not automatically make
its sampling, event-loss or enforcement semantics equivalent.

## State and hot path

Threads normally share a thread-group key, cached map and chain. A memory-management
operation invalidates map state; exec starts a new provenance lifecycle while
preserving run counters. Maps are refreshed when invalidated and on unknown/NX
instruction addresses. Binary search avoids scanning all mappings for each pointer.

The ptrace context-switch tax remains dominant for syscall-heavy workloads. There
is no whole-host overhead target. Benchmarks must include the selected workload,
kernel, raw samples and baseline; see `scripts/benchmark.py`.

## Deliberate constraints

- Linux x86-64 syscall ABI only; no compatibility/x32 or native ARM support claim.
- Only `nix` and `libc` as direct dependencies.
- Hand-written JSON preserves a small dependency surface; parser tests and actual
  demo JSON validation guard serialization.
- Correlation currently accumulates coarse milestones, not causal taint flow.
- The public tracer library should be driven in a dedicated process. Global waits
  and signal ownership need care when embedding with unrelated child processes.

See the [threat model](threat-model.md) for the boundaries that matter operationally.
