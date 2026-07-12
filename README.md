# Wraith

**Signature-free runtime exploitation detection via syscall provenance verification.**

Wraith is a low-level Rust security sensor that answers a question most tools
can't: *is this process being exploited right now?* — without knowing the
vulnerability or the payload in advance. That makes it effective against
**zero-days and n-days alike**, because it keys on the *behaviour of
exploitation*, not the *identity of the bug*.

> Built as the runtime-defence companion to [`ghost`](https://github.com/pandaadir05/ghost).
> `ghost` finds weaknesses; `wraith` catches them being used.

---

## The idea

Defensive tooling usually answers one of two questions:

| Question | Needs to know | Blind to |
|---|---|---|
| *Does this code contain a known bug?* (SAST/scanners) | the vulnerability | zero-days |
| *Do these bytes match known-bad?* (AV/YARA) | the payload | novel payloads |

Wraith answers a **third** question — *is this process executing in a state
that only exploitation produces?* — and it needs to know neither the bug nor
the payload.

The observation behind it: **every** memory-corruption exploit, no matter the
root cause (stack overflow, UAF, type confusion, an unknown zero-day),
eventually converges on the same visible act. To accomplish anything — spawn a
shell, open a socket, read a secret — the attacker must issue **system calls**.
And at the instant those syscalls happen, the process is in a state that
legitimate execution *never* produces.

Wraith attaches to a process with `ptrace`, stops at the entry of every
syscall, and checks a handful of invariants that hold for all benign programs:

1. **Provenance** — a `syscall` instruction only ever runs from a *file-backed
   executable page* (the program's own `.text`, a shared library, or the kernel
   vDSO). Shellcode injected into the heap, stack, or an anonymous page
   **breaks this**.
2. **W^X** — no benign program needs a page that is writable *and* executable,
   nor to flip a writable page to executable. Payload staging **breaks this**.
3. **Stack integrity** — at syscall time the stack pointer lives inside a real
   stack, never the heap or a file image. A ROP stack pivot **breaks this**.

Because these are invariants of *legitimate behaviour* rather than signatures
of *specific attacks*, any violation is evidence of exploitation regardless of
how the attacker got there.

---

## Quickstart

```bash
cargo build --release

# Monitor a program you launch:
./target/release/wraith run -- /usr/bin/some-service --flags

# Monitor a process that's already running:
sudo ./target/release/wraith attach 4242

# Emit machine-readable events for your SIEM/pipeline:
./target/release/wraith run --json events.jsonl -- ./target
```

Wraith exits `0` when clean, `1` on suspicious (HIGH) activity, and `3` when it
detects exploitation (CRITICAL) — so it drops straight into CI and fuzzing
harnesses as a behavioural oracle.

### See it work

The repo ships two self-contained targets (no real exploit required):

```console
$ wraith run --min info -- ./target/release/benign
wraith: monitoring `./target/release/benign` (provenance mode)
benign: ... normal work ...
wraith: 81 syscalls, 0 event(s); verdict: clean          # <- false-positive control

$ wraith run -- ./target/release/shellcode-sim
    HIGH pid=6586 wx_violation           mmap   @ 0x7fa8ad52534a  `mmap` requests writable+executable memory — classic shellcode staging
CRITICAL pid=6586 foreign_origin_syscall socket @ 0x7fa8ad696011 [anon]  sensitive syscall `socket` issued from wx-violation memory — injected code is now acting
CRITICAL pid=6586 exploitation_chain     socket @ 0x7fa8ad696011 [correlated]  EXPLOITATION CHAIN: executable payload staged (W^X) -> sensitive syscall from injected code
wraith: 69 syscalls, 3 event(s); verdict: EXPLOITATION DETECTED
```

`shellcode-sim` stages an RWX page, writes a payload into it, and issues a
syscall from that page — the exact tail end of a real exploit — and Wraith
catches every stage and correlates them into one verdict.

---

## What it detects

| Event | Severity | Meaning |
|---|---|---|
| `foreign_origin_syscall` | HIGH / CRITICAL | A syscall issued from non-code memory (heap/stack/anon/RWX). CRITICAL when the syscall is *sensitive* (execve, connect, ptrace, …). |
| `wx_violation` | HIGH | `mmap`/`mprotect` requesting writable **and** executable memory. |
| `wx_transition` | HIGH | A writable page being flipped to executable — payload staging. |
| `stack_pivot` | HIGH | Stack pointer sitting in the heap or a file image at syscall time — a ROP indicator. |
| `crash` | HIGH | Target took SIGSEGV/SIGILL/SIGBUS/SIGABRT — often a *failed* exploit worth investigating. |
| `exploitation_chain` | CRITICAL | Multiple primitives correlated into a single high-confidence verdict. |
| `sensitive_call` | INFO | Audit breadcrumb (with `--audit-sensitive`): a sensitive syscall from legitimate code. |

Tuning:

```
--jit-critical      treat anonymous-exec pages as HIGH (targets that never JIT)
--no-stack-pivot    disable the ROP stack-pivot heuristic
--audit-sensitive   log sensitive syscalls from legitimate code too
--min <sev>         floor: info|warn|high|critical (default warn)
```

---

## Architecture

Small, auditable, and dependency-light on purpose — a sensor others run should
carry the smallest supply chain you can manage. The engine links only `nix` and
`libc`; JSON is emitted by hand.

```
  src/
   ├─ maps.rs        parse /proc/<pid>/maps into typed regions
   ├─ provenance.rs  classify an instruction/stack pointer against the map
   ├─ syscalls.rs    the syscall table Wraith cares about
   ├─ detect.rs      the invariants + the exploitation-chain correlator
   ├─ event.rs       detection events + their JSONL form
   ├─ tracer.rs      the ptrace engine (spawn/attach, thread-following loop)
   └─ bin/
       ├─ wraith.rs           the CLI sensor
       ├─ benign.rs           false-positive control target
       ├─ benign_threads.rs   multithreaded false-positive control
       ├─ shellcode_sim.rs    exploitation-behaviour simulator
       └─ mt_shellcode_sim.rs exploitation from a worker thread
```

The tracer adds no syscall of its own on the hot path beyond the unavoidable
`getregs`, and re-reads `/proc/<pid>/maps` only when a memory operation could
have changed it.

**Thread-following.** Real targets — network daemons, request handlers, fuzz
harnesses — are multithreaded, and an exploit can fire from any thread. Wraith
follows every `clone`/`fork`/`vfork` the target makes and inspects syscalls
from *all* of them. Threads that share an address space share one cached memory
map and one exploitation-chain accumulator, so a payload staged on one thread
and fired from another is still correlated into a single verdict — while
separate processes keep separate state.

---

## Limitations & roadmap

Wraith is an honest research prototype with a clear production path; it does not
claim to be a finished EDR.

- **`ptrace` overhead.** Two stops per syscall suits high-value targets
  (network daemons, parsers, fuzz targets), not the whole system. The
  production path is the same logic on **eBPF** (`tracepoint/raw_syscalls` +
  a page-provenance map) for near-zero overhead — the detection model is
  transport-agnostic by design.
- **Attach vs. pre-existing threads.** `wraith run` and `wraith attach` follow
  every thread and child the target spawns *after* tracing begins (via
  `PTRACE_O_TRACECLONE`/`FORK`/`VFORK`). When attaching to an already-running
  multithreaded process, only the threads that clone after attach are picked
  up automatically; seizing every pre-existing sibling thread is a small
  follow-up.
- **Pure-ROP that never leaves legit code.** An attacker who only reuses
  existing `.text` and never stages new executable memory won't trip the
  provenance rule — that's what the stack-pivot heuristic is for, and why
  return-address validation and a shadow stack are on the roadmap.
- **Legitimate JIT** (browsers, JVMs, .NET) runs code from anonymous
  executable pages; hence `AnonExec` is WARN by default and configurable.

Roadmap: eBPF backend · return-address/shadow-stack checks · ROP-chain length
heuristics · per-thread stack tracking · seizing pre-existing threads on attach
· per-process behavioural baselining · a policy DSL for allow-listing
legitimate JIT regions.

---

## Building & testing

```bash
cargo build --release
cargo test          # 28 unit + 6 end-to-end tests
cargo clippy --all-targets
./demo.sh           # side-by-side benign vs. exploitation run
```

The end-to-end tests drive the real ptrace engine over the `benign`,
`benign-threads`, `shellcode-sim`, and `mt-shellcode-sim` binaries — including
an exploit fired from a worker thread to exercise thread-following. They
self-skip where `ptrace` is unavailable.

## License

MIT — see [LICENSE](LICENSE).
