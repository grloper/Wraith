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

Threads normally share a thread-group key, cached map and correlation context.
Each TID holds at most one pending syscall entry; actual kernel exits commit only
successful protection/positive-input milestones. Protection evidence carries an
address span, and context expires by syscall budget and monotonic time. Failed
memory calls still invalidate maps because partial effects are possible. Successful
native alternate-stack registrations affect per-thread placement, not code trust.

Exec/retirement reset provenance state while aggregate run counters survive. Map
refresh failures discard the decision cache, record coverage gaps and cannot
produce stale-map intervention. Retired process rows are capped separately from
live targets; PID reuse resets the visible lifecycle. Maps refresh when invalidated
and on unknown/NX sites; binary search avoids linear mapping scans per pointer.

The ptrace context-switch tax remains dominant for syscall-heavy workloads. There
is no whole-host overhead target. Benchmarks must include the selected workload,
kernel, raw samples and baseline; see `scripts/benchmark.py`.

## Deliberate constraints

- Linux x86-64 syscall ABI only; no compatibility/x32 or native ARM support claim.
- Only `nix` and `libc` as direct dependencies.
- Hand-written JSON preserves a small dependency surface; parser tests and actual
  demo JSON validation guard serialization.
- Correlation uses completed, expiring, address-span context, not causal taint flow
  or a complete allocation-generation graph.
- The library should be driven in a dedicated process/creator OS thread.
  `__WNOTHREAD` isolates other threads' children, but arbitrary untraced children
  on that same thread and moving active tracers across threads remain unsupported.

See the [threat model](threat-model.md) for the boundaries that matter operationally.
