//! # Wraith
//!
//! Signature-free runtime exploitation detection via **syscall provenance
//! verification**.
//!
//! Most defensive tooling answers one of two questions: *does this program
//! contain a known vulnerability?* (needs the bug) or *does this file match
//! known-bad bytes?* (needs the payload). Wraith answers a third, harder one:
//! *is this process being exploited right now?* — without knowing the bug or
//! the payload in advance.
//!
//! The insight is that every memory-corruption exploit, whatever the root
//! cause, converges on the same observable behaviour: to accomplish anything
//! the attacker must eventually issue system calls, and at that moment the
//! process is in a state legitimate execution never produces. Wraith attaches
//! to a process with `ptrace`, stops at the entry of every syscall, and checks
//! a handful of invariants that hold for all benign programs:
//!
//! 1. **Provenance** — a syscall instruction only ever executes from a
//!    file-backed executable page (the program's own code, a shared library,
//!    or the kernel vDSO). Injected shellcode in the heap, stack, or an
//!    anonymous page breaks this. See [`provenance`].
//! 2. **W^X** — no benign program needs a page that is writable *and*
//!    executable, nor to flip a writable page to executable. Payload staging
//!    breaks this. See [`detect`].
//! 3. **Stack integrity** — at syscall time the stack pointer is inside a real
//!    stack, never the heap or a file image. ROP stack pivots break this.
//!
//! Because these are invariants of *legitimate behaviour* rather than
//! signatures of *specific attacks*, a violation is evidence of exploitation
//! regardless of which vulnerability (zero-day or n-day) was used to get
//! there.
//!
//! ## Layout
//! - [`maps`] — parse `/proc/<pid>/maps`.
//! - [`provenance`] — classify an instruction/stack pointer against the map.
//! - [`syscalls`] — the syscall table Wraith cares about.
//! - [`detect`] — the rules and the exploitation-chain correlator.
//! - [`event`] — detection events and their JSON form.
//! - [`engine`] — the transport-agnostic detection core ([`Backend`], [`Engine`]).
//! - [`tracer`] — the `ptrace` [`Backend`] that drives a target.
//! - [`ui`] — the live terminal dashboard (`--ui`).

pub mod detect;
pub mod engine;
pub mod event;
pub mod maps;
pub mod provenance;
pub mod syscalls;
pub mod tracer;
pub mod ui;

pub use detect::{Config, Detector, Enforcement, SyscallCtx};
pub use engine::{Backend, Engine, ProcStat, Reporter, Summary};
pub use event::{Event, Kind, Severity};
pub use tracer::Tracer;
pub use ui::{Dashboard, TerminalGuard};
