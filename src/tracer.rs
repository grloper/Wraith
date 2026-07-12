//! The ptrace engine.
//!
//! Wraith drives a target with `PTRACE_SYSCALL`, stopping at the entry to every
//! system call. At each stop it reads the tracee's registers, refreshes the
//! memory map when a prior memory operation could have changed it, and hands
//! the snapshot to the [`Detector`]. The design goal is to add no syscall of
//! our own on the hot path beyond the unavoidable `getregs`, and to re-read
//! `/proc/<pid>/maps` only when it can have changed.

use std::ffi::CString;
use std::io;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};

use crate::detect::{Config, Detector, SyscallCtx};
use crate::event::{Event, Kind, Severity};
use crate::maps::MemoryMap;
use crate::syscalls;

/// Outcome of a completed trace.
#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub exit_code: Option<i32>,
    pub term_signal: Option<i32>,
    pub syscalls_seen: u64,
    pub events: u64,
    pub max_severity: Option<Severity>,
}

impl Summary {
    fn record(&mut self, ev: &Event) {
        self.events += 1;
        self.max_severity = Some(match self.max_severity {
            Some(cur) => cur.max(ev.severity),
            None => ev.severity,
        });
    }
}

/// How the tracee was obtained, so `run` knows how to resume it.
enum Target {
    /// We forked and exec'd it; it is stopped at the post-exec SIGTRAP.
    Spawned(Pid),
    /// We attached to an already-running process.
    Attached(Pid),
}

pub struct Tracer {
    target: Target,
    detector: Detector,
}

impl Tracer {
    /// Fork, `PTRACE_TRACEME`, and exec `argv`. Returns with the child stopped
    /// at its first instruction, ready for [`Tracer::run`].
    pub fn spawn(argv: &[String], cfg: Config) -> io::Result<Self> {
        if argv.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command"));
        }
        // Build C strings in the parent; between fork and exec we must touch
        // only async-signal-safe operations.
        let cargs: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<Result<_, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains NUL"))?;

        match unsafe { fork() }.map_err(nix_err)? {
            ForkResult::Child => {
                // If any of this fails we cannot safely return; die immediately.
                if ptrace::traceme().is_err() {
                    unsafe { libc::_exit(126) };
                }
                let _ = execvp(&cargs[0], &cargs);
                // execvp only returns on failure.
                unsafe { libc::_exit(127) };
            }
            ForkResult::Parent { child } => {
                // Consume the automatic stop that the exec delivers.
                match waitpid(child, None).map_err(nix_err)? {
                    WaitStatus::Exited(_, code) => {
                        return Err(io::Error::other(format!(
                            "target exited before trace could begin (code {code}) — command not found?"
                        )));
                    }
                    WaitStatus::Stopped(_, _) => {}
                    other => {
                        return Err(io::Error::other(format!(
                            "unexpected initial wait status: {other:?}"
                        )));
                    }
                }
                set_options(child)?;
                Ok(Tracer {
                    target: Target::Spawned(child),
                    detector: Detector::new(cfg),
                })
            }
        }
    }

    /// Attach to a running process by PID.
    pub fn attach(pid: i32, cfg: Config) -> io::Result<Self> {
        let child = Pid::from_raw(pid);
        ptrace::attach(child).map_err(nix_err)?;
        // Attach delivers a SIGSTOP; wait for it.
        match waitpid(child, None).map_err(nix_err)? {
            WaitStatus::Stopped(_, _) => {}
            other => {
                return Err(io::Error::other(format!(
                    "unexpected status after attach: {other:?}"
                )));
            }
        }
        set_options(child)?;
        Ok(Tracer {
            target: Target::Attached(child),
            detector: Detector::new(cfg),
        })
    }

    fn pid(&self) -> Pid {
        match self.target {
            Target::Spawned(p) => p,
            Target::Attached(p) => p,
        }
    }

    /// Run the trace to completion (or until the attached process detaches),
    /// invoking `on_event` for every detection.
    pub fn run<F>(mut self, mut on_event: F) -> io::Result<Summary>
    where
        F: FnMut(&Event),
    {
        let pid = self.pid();
        let mut summary = Summary::default();

        // Cached map plus a "may be stale" flag set after memory operations.
        let mut map: Option<MemoryMap> = None;
        let mut map_dirty = true;
        // PTRACE_SYSCALL stops at both entry and exit; we only inspect entries.
        let mut at_entry = true;

        // Kick the tracee toward its first syscall stop.
        ptrace::syscall(pid, None).map_err(nix_err)?;

        loop {
            let status = waitpid(pid, None).map_err(nix_err)?;
            match status {
                WaitStatus::Exited(_, code) => {
                    summary.exit_code = Some(code);
                    break;
                }
                WaitStatus::Signaled(_, sig, _) => {
                    summary.term_signal = Some(sig as i32);
                    break;
                }
                WaitStatus::PtraceSyscall(_) => {
                    if at_entry {
                        summary.syscalls_seen += 1;
                        if let Some(nr) = self.inspect(pid, &mut map, &mut map_dirty, &mut summary, &mut on_event) {
                            // The memory map may change as a result of this
                            // call; force a refresh before the next inspection.
                            if syscalls::is_memory_op(nr) {
                                map_dirty = true;
                            }
                        }
                    }
                    at_entry = !at_entry;
                    ptrace::syscall(pid, None).map_err(nix_err)?;
                }
                WaitStatus::Stopped(_, sig) => {
                    // A real signal was delivered to the tracee (not a syscall
                    // stop). Fatal memory-safety signals are worth surfacing as
                    // a possible failed exploit, then we forward the signal.
                    self.on_signal(pid, sig, &mut summary, &mut on_event);
                    ptrace::syscall(pid, Some(sig)).map_err(nix_err)?;
                }
                WaitStatus::PtraceEvent(_, _, _) => {
                    ptrace::syscall(pid, None).map_err(nix_err)?;
                }
                WaitStatus::Continued(_) => {}
                WaitStatus::StillAlive => {}
            }
        }
        Ok(summary)
    }

    /// Inspect a single syscall-entry stop. Returns the syscall number, or
    /// `None` if registers could not be read.
    fn inspect<F>(
        &mut self,
        pid: Pid,
        map: &mut Option<MemoryMap>,
        map_dirty: &mut bool,
        summary: &mut Summary,
        on_event: &mut F,
    ) -> Option<u64>
    where
        F: FnMut(&Event),
    {
        let regs = ptrace::getregs(pid).ok()?;
        let nr = regs.orig_rax;

        // Refresh the memory map if stale or unset.
        if *map_dirty || map.is_none() {
            if let Ok(fresh) = MemoryMap::read(pid.as_raw()) {
                *map = Some(fresh);
                *map_dirty = false;
            }
        }
        let current = map.as_ref()?;

        // The `syscall` instruction is two bytes; RIP already points past it.
        let site = regs.rip.wrapping_sub(2);
        let ctx = SyscallCtx {
            pid: pid.as_raw(),
            nr,
            rip: site,
            rsp: regs.rsp,
            args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
        };

        for ev in self.detector.on_syscall(&ctx, current) {
            summary.record(&ev);
            on_event(&ev);
        }
        Some(nr)
    }

    fn on_signal<F>(&self, pid: Pid, sig: Signal, summary: &mut Summary, on_event: &mut F)
    where
        F: FnMut(&Event),
    {
        let fatal = matches!(
            sig,
            Signal::SIGSEGV | Signal::SIGILL | Signal::SIGBUS | Signal::SIGABRT
        );
        if !fatal {
            return;
        }
        let (rip, rsp) = ptrace::getregs(pid)
            .map(|r| (r.rip, r.rsp))
            .unwrap_or((0, 0));
        let ev = Event::now(
            pid.as_raw(),
            Severity::High,
            Kind::Crash,
            format!("signal:{sig:?}"),
            rip,
            rsp,
            "fault",
            format!(
                "target received {sig:?} — memory-corruption fault; possible failed exploitation attempt"
            ),
        );
        summary.record(&ev);
        on_event(&ev);
    }
}

fn set_options(pid: Pid) -> io::Result<()> {
    use ptrace::Options;
    // TRACESYSGOOD lets us tell syscall stops apart from signal stops.
    // EXITKILL guarantees the tracee dies with us instead of being left
    // orphaned and stopped if the tracer crashes.
    ptrace::setoptions(pid, Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_EXITKILL)
        .map_err(nix_err)
}

fn nix_err(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}
