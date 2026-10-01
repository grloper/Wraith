# Evidence-first design notes

This review focused on Linux behavior that can invalidate attractive detection
claims. Sources below are primary kernel/man-page documentation, not benchmarks
or marketing comparisons. Repository regressions establish Wraith behavior; the
sources establish the OS semantics behind the design.

## 1. Mapping names are untrusted labels

Linux permits anonymous mapping names through
[`PR_SET_VMA_ANON_NAME`](https://man7.org/linux/man-pages/man2/pr_set_vma.2const.html).
[`/proc/pid/maps`](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
can expose `[anon:name]` and `[anon_shmem:name]`. Square brackets therefore do not
mean kernel executable code. Accepting every bracketed mapping as vDSO makes a
label-based provenance bypass possible.

**Decision:** classify named anonymous mappings as anonymous. Only known kernel
executable labels belong in the vDSO category, and permission checks still apply.
No label is code-content attestation.

## 2. Syscall stops have a real phase

[`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html) documents syscall
entry/exit stops, exec events, per-thread attachment and `PTRACE_GET_SYSCALL_INFO`
(available since Linux 5.3). Attaching mid-syscall does not establish an alternating
entry-first sequence. An entry/exit toggle can inspect the wrong stop and apply
blocking after the syscall has already run.

**Decision:** use kernel-reported stop type and explicit exec lifecycle handling.
Map changes also require exit-side invalidation because another thread may have
consumed entry-side invalidation before the change completes.

## 3. W→X is not inherently malicious

[`mprotect(2)`](https://man7.org/linux/man-pages/man2/mprotect.2.html) changes page
permissions. JITs can write a page, remove write permission, then execute it.
That is different from simultaneous W+X. A sensitive syscall from anonymous RX
memory is not alone proof of exploitation.

**Decision:** default anonymous RX observations remain WARN, with an explicit
no-JIT policy for elevation. Protection-request exclusions must cover the entire
span; an `mmap` address hint is not the kernel's actual chosen mapping address.

## Completed evidence and partial failure

A syscall entry describes a request, not its result. Correlation now consumes
actual exit outcomes: positive input only, successful protection candidates and
actual mmap return addresses. Evidence is address-span-bound and expires; it is
not a causal input-to-code graph.

A controlled three-page WSL reproduction unmapped the middle page and requested
RX protection for the whole span. `mprotect` returned `ENOMEM`, yet the first page
had become RX. Failure must **not** imply no mapping change. The corresponding
live fixture and exit-side invalidation preserve that distinction; the
[Linux mprotect implementation](https://github.com/torvalds/linux/blob/v5.15/mm/mprotect.c)
also provides the relevant VMA-by-VMA context. This observed kernel behavior is not
an assertion that every failure changes pages on every kernel.

A failed required map refresh cannot justify using an old RWX snapshot for a new
intervention. The engine invalidates decision state, surfaces a coverage notice
and retains the run's failed-decision count after recovery. Output filters do not
turn that incomplete run into a clean result.

## 4. Heap stacks can be legitimate

[`sigaltstack(2)`](https://man7.org/linux/man-pages/man2/sigaltstack.2.html) supports
alternate signal stacks. The [TLPI example](https://www.man7.org/tlpi/code/online/book/signals/t_sigaltstack.c.html)
allocates one with `malloc`. User-space coroutine stacks can also differ from a
conventional main-thread stack.

**Decision:** retain stack placement only as a documented optional heuristic,
not an invariant. Successfully observed native `sigaltstack` registrations enroll
only that thread's stack extent after the kernel accepts the request. This changes
stack-placement interpretation, not executable-memory or syscall-origin trust.
Registrations predating attachment, fork-inherited configurations and general
coroutine stacks still need separate treatment; do not trust all heap memory.

## 5. eBPF observation is not ptrace enforcement

The kernel's [BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html)
describes programs attached at security hooks. A syscall tracepoint is a telemetry
point, not a general interface for synchronously denying any arbitrary syscall.
An asynchronous observer can also lose events or see maps at a different time.

**Decision:** no claim of a finished or near-zero-overhead eBPF backend. Future
work needs an explicit ABI, map consistency model, event-loss accounting,
benchmark, privilege model and hook-specific enforcement design.

## What still needs research

1. Finer allocation identity/address-reuse and concurrent-map causality beyond the
   implemented successful, expiring address-span context.
2. Runtime-owned JIT attestation and preexisting/inherited/coroutine stack awareness
   beyond observed per-thread signal-stack registration.
3. File-backed page integrity and dual-mapping attacks without per-syscall hashing.
4. Real-service overhead, false positives and job-control behavior on supported kernels.
5. Address spaces shared outside conventional thread groups.

These are open engineering questions, not implemented roadmap promises. A finite
fixture suite cannot establish a population-wide zero-false-positive rate.
