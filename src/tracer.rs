//! The ptrace engine.
//!
//! Wraith drives a target with `PTRACE_SYSCALL`, stopping at the entry to every
//! system call. At each stop it reads the tracee's registers, refreshes the
//! memory map when a prior memory operation could have changed it, and hands
//! the snapshot to the [`Detector`]. The design goal is to add no syscall of
//! our own on the hot path beyond the unavoidable `getregs`, and to re-read
//! `/proc/<pid>/maps` only when it can have changed.
//!
//! ## Thread-following
//!
//! Real targets — network daemons, parsers, fuzz harnesses — spawn threads, so
//! an exploit can fire from any of them. The engine follows every `clone`,
//! `fork`, and `vfork` (via `PTRACE_O_TRACE{CLONE,FORK,VFORK}`) and reaps *all*
//! tracees with `waitpid(-1)`. Each thread keeps its own syscall entry/exit
//! phase, while threads that share an address space (same thread-group id)
//! share one cached memory map and one exploitation-chain accumulator — so a
//! payload staged in one thread and fired from another is still one verdict.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;

use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};

use crate::detect::{Config, Detector, Enforcement, SyscallCtx};
use crate::event::{Event, Kind, Severity};
use crate::maps::MemoryMap;
use crate::syscalls;

/// A cached memory map for one address space (one thread-group), plus a flag
/// set whenever any thread in the group runs a memory-management syscall that
/// could have changed it. Threads share memory, so one thread's `mmap`
/// invalidates the whole group's view.
struct AddrSpace {
    map: Option<MemoryMap>,
    dirty: bool,
}

impl AddrSpace {
    fn new() -> Self {
        AddrSpace { map: None, dirty: true }
    }
}

/// Per-thread bookkeeping. `PTRACE_SYSCALL` stops at both entry and exit; each
/// thread toggles its own phase independently since their stops interleave.
struct ThreadState {
    at_entry: bool,
    tgid: i32,
}

/// What one syscall-entry inspection produced, so the run loop can decide
/// whether to enforce.
struct Inspection {
    /// The syscall number, or `None` if registers could not be read.
    nr: Option<u64>,
    /// The highest severity among the events this syscall raised, if any.
    max_severity: Option<Severity>,
}

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

/// How the tracee(s) were obtained, so `run` knows how to seed and resume them.
enum Target {
    /// We forked and exec'd it; it is stopped at the post-exec SIGTRAP. We own
    /// it, so it is killed with us on exit.
    Spawned(Pid),
    /// We attached to one already-running process. We do not own it, so it is
    /// left running if we exit.
    Attached(Pid),
    /// We attached to a whole set of already-running processes (`scan` mode).
    /// Peers with no distinguished root; all left running if we exit.
    ScanAttached(Vec<Pid>),
}

pub struct Tracer {
    target: Target,
    detector: Detector,
    /// What to do on confirmed exploitation. Kept on the tracer (not just the
    /// detector) because acting on the tracee — cancelling a syscall, killing
    /// the tree — is a ptrace operation the engine owns.
    enforcement: Enforcement,
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
                // We own this child, so tie its life to ours.
                set_options(child, true)?;
                let enforcement = cfg.enforcement;
                Ok(Tracer {
                    target: Target::Spawned(child),
                    detector: Detector::new(cfg),
                    enforcement,
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
        // Observing someone else's process: leave it running if we stop.
        set_options(child, false)?;
        let enforcement = cfg.enforcement;
        Ok(Tracer {
            target: Target::Attached(child),
            detector: Detector::new(cfg),
            enforcement,
        })
    }

    /// Attach to a whole set of already-running processes at once (`scan`
    /// mode). Each pid is attached, waited for its stop, and configured
    /// independently; a pid we cannot attach to (permission, or it exited
    /// between enumeration and attach) is skipped rather than failing the
    /// whole scan. Errors only if *nothing* could be attached.
    pub fn attach_many(pids: &[i32], cfg: Config) -> io::Result<Self> {
        let mut attached = Vec::new();
        for &pid in pids {
            let child = Pid::from_raw(pid);
            if ptrace::attach(child).is_err() {
                continue; // not ours / gone / already traced
            }
            match waitpid(child, None) {
                Ok(WaitStatus::Stopped(_, _)) => {}
                _ => {
                    let _ = ptrace::detach(child, None);
                    continue;
                }
            }
            // Never kill-on-exit under scan: stopping the monitor must not take
            // down every process it was watching.
            if set_options(child, false).is_err() {
                let _ = ptrace::detach(child, None);
                continue;
            }
            attached.push(child);
        }
        if attached.is_empty() {
            return Err(io::Error::other(
                "could not attach to any matching process (need CAP_SYS_PTRACE / ownership?)",
            ));
        }
        let enforcement = cfg.enforcement;
        Ok(Tracer {
            target: Target::ScanAttached(attached),
            detector: Detector::new(cfg),
            enforcement,
        })
    }

    /// Run the trace to completion — following every thread and child the
    /// target(s) spawn — invoking `on_event` for every detection. The trace
    /// ends once the last tracee has exited.
    pub fn run<F>(mut self, mut on_event: F) -> io::Result<Summary>
    where
        F: FnMut(&Event),
    {
        let mut summary = Summary::default();

        // The tracee(s) to seed, and — for a single spawned/attached target —
        // the one pid whose exit status the summary records. A `scan` has many
        // peers and no distinguished root.
        let (initial, root_pid): (Vec<Pid>, Option<i32>) = match &self.target {
            Target::Spawned(p) | Target::Attached(p) => (vec![*p], Some(p.as_raw())),
            Target::ScanAttached(pids) => (pids.clone(), None),
        };

        // Per-thread phase, and per-address-space (tgid) cached maps. Threads
        // that share memory share an `AddrSpace` entry.
        let mut threads: HashMap<i32, ThreadState> = HashMap::new();
        let mut spaces: HashMap<i32, AddrSpace> = HashMap::new();

        // Seed every initial tracee and kick each toward its first syscall stop.
        for p in &initial {
            let raw = p.as_raw();
            let tgid = read_tgid(raw);
            threads.insert(raw, ThreadState { at_entry: true, tgid });
            spaces.entry(tgid).or_insert_with(AddrSpace::new);
            ptrace::syscall(*p, None).map_err(nix_err)?;
        }

        loop {
            // Reap any tracee. `ECHILD` means every thread and child has gone.
            let status = match waitpid(Pid::from_raw(-1), None) {
                Ok(s) => s,
                Err(nix::errno::Errno::ECHILD) => break,
                Err(e) => return Err(nix_err(e)),
            };

            let Some(who) = status_pid(&status) else { continue };
            let raw = who.as_raw();

            // First sighting of a tid: a freshly-cloned thread or child, still
            // stopped at its creation stop with our trace options inherited.
            // Registering lazily on first sight (rather than parsing the parent
            // clone event) sidesteps the parent/child wait-ordering race.
            if let Entry::Vacant(slot) = threads.entry(raw) {
                let tgid = read_tgid(raw);
                slot.insert(ThreadState { at_entry: true, tgid });
                spaces.entry(tgid).or_insert_with(AddrSpace::new);
                // Consume this initial stop and let the new tracee run; the
                // creation SIGSTOP must not be forwarded.
                let _ = ptrace::syscall(who, None);
                continue;
            }

            match status {
                WaitStatus::Exited(_, code) => {
                    threads.remove(&raw);
                    if Some(raw) == root_pid {
                        summary.exit_code = Some(code);
                    }
                    if threads.is_empty() {
                        break;
                    }
                }
                WaitStatus::Signaled(_, sig, _) => {
                    threads.remove(&raw);
                    if Some(raw) == root_pid {
                        summary.term_signal = Some(sig as i32);
                    }
                    if threads.is_empty() {
                        break;
                    }
                }
                WaitStatus::PtraceSyscall(_) => {
                    let tgid = threads[&raw].tgid;
                    let mut killed = false;
                    if threads[&raw].at_entry {
                        summary.syscalls_seen += 1;
                        let space = spaces.entry(tgid).or_insert_with(AddrSpace::new);
                        let step = self.inspect(who, tgid, space, &mut summary, &mut on_event);
                        if let Some(nr) = step.nr {
                            // A memory op by any thread can change the shared
                            // address space; invalidate the whole group's map.
                            if syscalls::is_memory_op(nr) {
                                spaces.get_mut(&tgid).unwrap().dirty = true;
                            }
                        }
                        // Enforce only on a confirmed exploitation (CRITICAL),
                        // and only at the syscall's entry stop — the one moment
                        // the offending syscall has not yet run.
                        if self.enforcement != Enforcement::Observe
                            && step.max_severity == Some(Severity::Critical)
                        {
                            match self.enforcement {
                                Enforcement::Block => {
                                    self.block_syscall(who, &mut summary, &mut on_event)
                                }
                                Enforcement::Kill => {
                                    self.kill_tree(who, &threads, &mut summary, &mut on_event);
                                    killed = true;
                                }
                                Enforcement::Observe => {}
                            }
                        }
                    }
                    let ts = threads.get_mut(&raw).unwrap();
                    ts.at_entry = !ts.at_entry;
                    // Resume. After a kill the tracee is stopped with a pending
                    // SIGKILL; restarting it lets the kernel deliver it, and the
                    // call racing with the process's death is expected, so a
                    // failure here is not fatal to the trace.
                    if killed {
                        let _ = ptrace::syscall(who, None);
                    } else {
                        ptrace::syscall(who, None).map_err(nix_err)?;
                    }
                }
                WaitStatus::Stopped(_, sig) => {
                    // A real signal was delivered to the tracee (not a syscall
                    // stop). Fatal memory-safety signals are worth surfacing as
                    // a possible failed exploit, then we forward the signal.
                    self.on_signal(who, sig, &mut summary, &mut on_event);
                    ptrace::syscall(who, Some(sig)).map_err(nix_err)?;
                }
                WaitStatus::PtraceEvent(_, _, _) => {
                    // Clone/fork/exec notification for a tracee we already know;
                    // the new child is handled on its own first sighting above.
                    ptrace::syscall(who, None).map_err(nix_err)?;
                }
                WaitStatus::Continued(_) => {}
                WaitStatus::StillAlive => {}
            }
        }
        Ok(summary)
    }

    /// Inspect a single syscall-entry stop for thread `who` in address space
    /// `space`, reporting the syscall number and the highest severity it
    /// raised so the caller can decide whether to enforce.
    fn inspect<F>(
        &mut self,
        who: Pid,
        tgid: i32,
        space: &mut AddrSpace,
        summary: &mut Summary,
        on_event: &mut F,
    ) -> Inspection
    where
        F: FnMut(&Event),
    {
        let Ok(regs) = ptrace::getregs(who) else {
            return Inspection { nr: None, max_severity: None };
        };
        let nr = regs.orig_rax;

        // Refresh the shared map if stale or unset. Reading `/proc/<tid>/maps`
        // for any thread yields the whole group's address space.
        if space.dirty || space.map.is_none() {
            if let Ok(fresh) = MemoryMap::read(who.as_raw()) {
                space.map = Some(fresh);
                space.dirty = false;
            }
        }
        let Some(current) = space.map.as_ref() else {
            return Inspection { nr: Some(nr), max_severity: None };
        };

        // The `syscall` instruction is two bytes; RIP already points past it.
        let site = regs.rip.wrapping_sub(2);
        let ctx = SyscallCtx {
            pid: who.as_raw(),
            nr,
            rip: site,
            rsp: regs.rsp,
            args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
        };

        let mut max_severity = None;
        for ev in self.detector.on_syscall(tgid, &ctx, current) {
            max_severity = Some(max_severity.map_or(ev.severity, |cur: Severity| cur.max(ev.severity)));
            summary.record(&ev);
            on_event(&ev);
        }
        Inspection { nr: Some(nr), max_severity }
    }

    /// Neutralise the syscall the tracee is stopped at by overwriting its
    /// syscall number with an invalid value: the kernel then skips the call and
    /// returns `-ENOSYS`, so the injected code's action never takes effect. The
    /// tracee lives on, which is what `--block` is for.
    fn block_syscall<F>(&self, who: Pid, summary: &mut Summary, on_event: &mut F)
    where
        F: FnMut(&Event),
    {
        let Ok(mut regs) = ptrace::getregs(who) else { return };
        let syscall = syscalls::name(regs.orig_rax);
        let rip = regs.rip.wrapping_sub(2);
        let rsp = regs.rsp;
        // -1 is not a valid syscall number; the kernel rejects it without
        // running anything and reports -ENOSYS to the tracee.
        regs.orig_rax = u64::MAX;
        if ptrace::setregs(who, regs).is_err() {
            return;
        }
        let ev = Event::now(
            who.as_raw(),
            Severity::Critical,
            Kind::Blocked,
            syscall.clone(),
            rip,
            rsp,
            "enforced",
            format!("neutralised `{syscall}` from injected code before it executed (--block)"),
        );
        summary.record(&ev);
        on_event(&ev);
    }

    /// `SIGKILL` every thread-group under trace. Sending the signal to a group
    /// leader (a tgid) tears down all of its threads at once, so the offending
    /// process — and every sibling we are following — dies before the syscall
    /// we stopped at can run.
    fn kill_tree<F>(
        &self,
        who: Pid,
        threads: &HashMap<i32, ThreadState>,
        summary: &mut Summary,
        on_event: &mut F,
    ) where
        F: FnMut(&Event),
    {
        let (syscall, rip, rsp) = ptrace::getregs(who)
            .map(|r| (syscalls::name(r.orig_rax), r.rip.wrapping_sub(2), r.rsp))
            .unwrap_or_else(|_| ("?".to_string(), 0, 0));

        // One SIGKILL per distinct thread-group is enough to take down all of
        // its threads; de-duplicating avoids redundant signals.
        let mut killed_groups = std::collections::HashSet::new();
        for ts in threads.values() {
            if killed_groups.insert(ts.tgid) {
                let _ = kill(Pid::from_raw(ts.tgid), Signal::SIGKILL);
            }
        }

        let ev = Event::now(
            who.as_raw(),
            Severity::Critical,
            Kind::Killed,
            syscall.clone(),
            rip,
            rsp,
            "enforced",
            format!("killed traced process tree on `{syscall}` from injected code (--kill)"),
        );
        summary.record(&ev);
        on_event(&ev);
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

fn set_options(pid: Pid, kill_on_exit: bool) -> io::Result<()> {
    use ptrace::Options;
    // TRACESYSGOOD lets us tell syscall stops apart from signal stops.
    // TRACE{CLONE,FORK,VFORK} make every thread and child the target spawns a
    // tracee too, and are inherited by those descendants — so following the
    // whole process tree needs setting them only on the root.
    let mut opts = Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK;
    // EXITKILL ties the tracee's life to ours — right for a process we spawned
    // and own, but wrong when merely observing someone else's process (attach /
    // scan): stopping the monitor must not kill what it was watching.
    if kill_on_exit {
        opts |= Options::PTRACE_O_EXITKILL;
    }
    ptrace::setoptions(pid, opts).map_err(nix_err)
}

/// The pid a [`WaitStatus`] refers to, if it carries one.
fn status_pid(status: &WaitStatus) -> Option<Pid> {
    match status {
        WaitStatus::Exited(p, _)
        | WaitStatus::Signaled(p, _, _)
        | WaitStatus::Stopped(p, _)
        | WaitStatus::PtraceEvent(p, _, _)
        | WaitStatus::PtraceSyscall(p)
        | WaitStatus::Continued(p) => Some(*p),
        WaitStatus::StillAlive => None,
    }
}

/// The thread-group id of a thread, read once from `/proc/<tid>/status`.
/// Threads of a process share a tgid (and their address space); a `fork`ed
/// child gets its own. Falls back to the tid itself if status is unreadable.
fn read_tgid(tid: i32) -> i32 {
    if let Ok(status) = fs::read_to_string(format!("/proc/{tid}/status")) {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Tgid:") {
                if let Ok(v) = rest.trim().parse::<i32>() {
                    return v;
                }
            }
        }
    }
    tid
}

fn nix_err(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}
