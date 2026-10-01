//! # Wraith
//!
//! Signature-free runtime exploitation detection via **syscall provenance
//! verification**.
//!
//! Wraith inspects syscall instruction origins, executable-memory protection
//! requests and stack placement for a selected Linux process tree. Its rules
//! are behavioral heuristics, not payload signatures or proof of malicious intent.
//!
//! Anonymous RX code can be legitimate JIT code, W->X transitions can enforce
//! W^X, and alternate stacks can live on the heap. The default policy accounts
//! for anonymous RX origins; operators must baseline other workload-specific
//! behavior before enabling enforcement. ROP in accepted code, data-only attacks
//! and modified file-backed executable pages can evade provenance checks.
//!
//! See the repository threat model for coverage and deployment limits.
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

// Wraith decodes syscall arguments straight out of the x86-64 `user_regs_struct`
// (`orig_rax`, `rip`, `rsp`, `rdi`…) and keys off x86-64 syscall numbers. Those
// are architecture-specific, so refuse to build anywhere else with a clear
// message rather than failing deep inside the tracer with a missing-field error.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!(
    "Wraith currently supports x86-64 Linux only: its syscall table and register \
     decoding are x86-64-specific. Build on an x86-64 host."
);

pub mod detect;
pub mod doctor;
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
