# Threat model

## What Wraith observes

A selected Linux x86-64 process tree, at syscall stops, with register snapshots
and a cached view of its virtual mappings. It classifies mapping permissions and
labels; it does not attest code bytes or determine whether a file is trustworthy.

The supported transport is `ptrace`. No eBPF backend, kernel module, universal
exploit detector, or full endpoint product is present.

## Intended detections

- Sensitive syscalls issued directly from suspicious executable memory.
- Requests for RWX pages and writable-to-executable transitions.
- Heap/file stack-pointer placement as an optional heuristic.
- Combinations of these signals within an address space.

Staging checks happen at entry: a failed `mmap`/`mprotect` request may still produce
an event. Correlation is process-lifetime evidence, not a proof of causality or
an allocation-by-allocation provenance graph. `exec` must reset that evidence.

## Legitimate behavior that resembles an attack

JIT engines, emulators, runtime-generated syscall stubs, instrumentation and custom
stacks can violate the same assumptions. W→X is a normal way to implement W^X in a
JIT, not a violation of simultaneous write/execute permissions. Anonymous RX
execution and W→X transitions are WARN by default, even for sensitive anonymous
RX calls; the explicit no-JIT policy can elevate them. RWX execution remains a strong policy signal, but some
legacy runtimes also use RWX. Crashes alone do not prove exploitation.

Trust ranges are an operator-created exclusion. They are not learned or signed;
trusted code can still be compromised. Full-span protection exemptions prevent a
trusted starting address from exempting untrusted pages beyond the range.

## Blind spots

- ROP/JOP or syscall gadgets executing entirely in accepted file-backed code.
- Data-only attacks and operations requiring no newly suspicious syscall origin.
- Modified private file-backed pages, malicious shared libraries, file replacement,
  dual-mapped JIT aliases and memfd-backed executable images.
- Pivots into anonymous writable memory (also used for ordinary worker stacks).
- Changes by unrelated processes sharing an mm through unusual clone configurations;
  external writers and tracing-incompatible security software.
- Time-of-check/map races: cache invalidation and miss retries reduce uncertainty,
  but do not serialize every thread's address-space mutation.
- Group-stop/job-control and library embedding limitations documented in
  [operations](operations.md). Do not hide these behind a production-ready label.

Missing/NX mappings are uncertainty, not evidence sufficient for CRITICAL
blocking. Register/map failures or attach skips must be treated as coverage gaps.

## Trust boundaries and deployment

The tracer needs access to procfs and ptrace permissions. The monitored process
can supply hostile mapping labels and output; terminal rendering sanitizes control
characters, but event metadata should still be handled as untrusted input.
Do not interpret JSON event strings as commands or render them as HTML.

Observe mode does not rewrite target registers, but tracing changes timing and
signal interactions. Launch mode uses EXITKILL: if the tracer dies unexpectedly,
its launched tracees are killed. Attached/scan targets are borrowed and must not
use EXITKILL. Enforcement is opt-in and may cause availability loss.

Use an isolated test VM, least privilege, restricted log permissions and a
rollback plan. A clean result means no configured signal was observed—not that
an exploit is absent. No empirical population-wide false-positive rate has been established.
