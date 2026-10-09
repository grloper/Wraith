//! The ptrace engine — Wraith's first [`Backend`].
//!
//! Wraith drives a target with `PTRACE_SYSCALL`, stopping at the entry to every
//! system call. At each stop it reads the tracee's registers into a
//! [`SyscallEntry`] and hands it to the [`Engine`], which refreshes the memory
//! map when a prior operation could have changed it and runs the detector. The
//! design goal is to add no syscall of our own on the hot path beyond the
//! unavoidable `getregs`, and to re-read `/proc/<pid>/maps` only when it can
//! have changed (the engine's job).
//!
//! This module owns only what is specific to the `ptrace` *transport*: how a
//! syscall stop is obtained (the `waitpid` reap loop), how registers are read,
//! and how enforcement is *carried out* (rewriting the syscall number, killing
//! the tree). The transport-agnostic detection core lives in [`Engine`]; an
//! eBPF backend would reuse it unchanged.
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
use std::io;
use std::time::Instant;

use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};

use crate::detect::Config;
use crate::engine::{read_tgid, Action, Backend, Engine, SyscallEntry};
use crate::event::{Event, Kind, Severity};
use crate::syscalls;

// Re-export the transport-agnostic detection types from their new home so the
// long-standing `wraith::tracer::{Reporter, Summary, ProcStat}` paths — used by
// the UI, the binary, and the test-suite — keep resolving unchanged.
pub use crate::engine::{ProcStat, Reporter, Summary};

/// The kernel identifies entry/exit stops; only in-flight map changes are local.
struct ThreadState {
    /// Exactly one original entry per active TID. An unmatched initial attach
    /// exit is ignored rather than inventing a completion candidate.
    pending: Option<PendingSyscall>,
    tgid: i32,
    last_signal: Option<(Signal, u64, u64)>,
    /// Deduplication is carried only by this group's remaining live threads.
    fatal_reported: bool,
}

struct PendingSyscall {
    entry: SyscallEntry,
    altstack: Option<AltStack>,
}

struct AltStack {
    start: u64,
    size: u64,
    flags: u64,
}

fn capture_altstack(pid: Pid, address: u64) -> Option<AltStack> {
    if address == 0 {
        return None;
    }
    // Native x86-64 stack_t is pointer, int flags + padding, size_t (24 bytes).
    // The tracee is stopped; no arbitrary host dereference is performed.
    let start = ptrace::read(pid, address as ptrace::AddressType).ok()? as u64;
    let flags = ptrace::read(pid, address.checked_add(8)? as ptrace::AddressType).ok()? as u64
        & 0xffff_ffff;
    let size = ptrace::read(pid, address.checked_add(16)? as ptrace::AddressType).ok()? as u64;
    Some(AltStack { start, size, flags })
}

/// Linux's ptrace_syscall_info ABI (including the largest, seccomp union arm).
#[repr(C)]
#[derive(Default)]
struct SyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    ip: u64,
    sp: u64,
    data: [u64; 8],
}

enum SyscallStop {
    Entry(SyscallEntry),
    Exit { result: i64, is_error: bool },
}

/// `PTRACE_GET_SYSCALL_INFO` request number (Linux >= 5.3, `<linux/ptrace.h>`).
const PTRACE_GET_SYSCALL_INFO: u32 = 0x420e;

fn syscall_stop(pid: Pid) -> io::Result<SyscallStop> {
    let mut info = SyscallInfo::default();
    // GET_SYSCALL_INFO requires Linux >= 5.3. Never guess phase on older kernels:
    // an attached task's first stop may be an exit, where enforcement is unsafe.
    let size = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO as _,
            pid.as_raw(),
            std::mem::size_of::<SyscallInfo>(),
            &mut info as *mut SyscallInfo,
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    decode_syscall_info(&info, size as i64)
}

fn decode_syscall_info(info: &SyscallInfo, size: i64) -> io::Result<SyscallStop> {
    if info.arch != 0xc000003e {
        return Err(io::Error::other("ptrace requires native x86-64 syscalls"));
    }
    if info.op == 1 && info.data[0] & 0x40000000 != 0 {
        return Err(io::Error::other(
            "x32 syscalls are unsupported by the native x86-64 detector",
        ));
    }
    match info.op {
        1 if size >= 80 => Ok(SyscallStop::Entry(SyscallEntry {
            nr: info.data[0],
            rip: info.ip,
            rsp: info.sp,
            args: info.data[1..7].try_into().expect("six syscall arguments"),
        })),
        2 if size >= 33 => Ok(SyscallStop::Exit {
            result: info.data[0] as i64,
            is_error: info.data[1] & 0xff != 0,
        }),
        _ => Err(io::Error::other(
            "kernel did not identify the syscall entry/exit stop",
        )),
    }
}

/// Adapts a plain `FnMut(&Event)` closure into a [`Reporter`], so the common
/// "just hand me events" callers keep working unchanged through [`Tracer::run`].
struct FnReporter<F>(F);

impl<F: FnMut(&Event)> Reporter for FnReporter<F> {
    fn event(&mut self, ev: &Event) {
        (self.0)(ev)
    }
}

/// How the tracee(s) were obtained, so `drive` knows how to seed and resume them.
enum Target {
    /// We forked and exec'd it; it is stopped at the post-exec SIGTRAP. We own
    /// it, so it is killed with us on exit.
    Spawned(Pid),
    /// We attached to one already-running process. We do not own it, so it is
    /// left running if we exit.
    Attached { root: Pid, threads: Vec<Pid> },
    /// We attached to a whole set of already-running processes (`scan` mode).
    /// Peers with no distinguished root; all left running if we exit.
    ScanAttached(Vec<Pid>),
}

pub struct Tracer {
    target: Target,
    /// The detection configuration; an [`Engine`] is built from it per run.
    cfg: Config,
    started: bool,
}

impl Tracer {
    /// Fork, `PTRACE_TRACEME`, and exec `argv`. Returns with the child stopped
    /// at its first instruction, ready for [`Tracer::run`].
    pub fn spawn(argv: &[String], cfg: Config) -> io::Result<Self> {
        Self::spawn_with_output(argv, cfg, false)
    }

    /// Reserve stdout for machine-readable reports by sending target output to stderr.
    pub fn spawn_with_output(
        argv: &[String],
        cfg: Config,
        redirect_stdout: bool,
    ) -> io::Result<Self> {
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
                if redirect_stdout
                    && unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } < 0
                {
                    unsafe { libc::_exit(126) };
                }
                if ptrace::traceme().is_err() {
                    unsafe { libc::_exit(126) };
                }
                let _ = execvp(&cargs[0], &cargs);
                // execvp only returns on failure.
                unsafe { libc::_exit(127) };
            }
            ForkResult::Parent { child } => {
                // Consume the automatic stop that the exec delivers.
                match wait_tracee(child) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        return Err(io::Error::other(format!(
                            "target exited before trace could begin (code {code}) — command not found?"
                        )));
                    }
                    Ok(WaitStatus::Stopped(_, _)) => {}
                    other => {
                        let _ = kill(child, Signal::SIGKILL);
                        let _ = ptrace::cont(child, None);
                        let _ = wait_tracee(child);
                        return Err(io::Error::other(format!(
                            "unexpected initial wait status: {other:?}"
                        )));
                    }
                }
                // We own this child, so tie its life to ours.
                if let Err(e) = set_options(child, true) {
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = ptrace::cont(child, None);
                    let _ = wait_tracee(child);
                    return Err(e);
                }
                Ok(Tracer {
                    target: Target::Spawned(child),
                    cfg,
                    started: false,
                })
            }
        }
    }

    /// Attach to a running process by PID.
    pub fn attach(pid: i32, cfg: Config) -> io::Result<Self> {
        let threads = attach_group(pid)?;
        Ok(Tracer {
            target: Target::Attached {
                root: Pid::from_raw(read_tgid(pid)),
                threads,
            },
            cfg,
            started: false,
        })
    }

    /// Attach to a whole set of already-running processes at once (`scan`
    /// mode). Each pid is attached, waited for its stop, and configured
    /// independently; a pid we cannot attach to (permission, or it exited
    /// between enumeration and attach) is skipped rather than failing the
    /// whole scan. Errors only if *nothing* could be attached.
    pub fn attach_many(pids: &[i32], cfg: Config) -> io::Result<Self> {
        let mut attached = Vec::new();
        let mut groups = std::collections::HashSet::new();
        for &pid in pids {
            if groups.insert(read_tgid(pid)) {
                if let Ok(group) = attach_group(pid) {
                    attached.extend(group);
                }
            }
        }
        if attached.is_empty() {
            return Err(io::Error::other(
                "could not attach to any matching process (need CAP_SYS_PTRACE / ownership?)",
            ));
        }
        Ok(Tracer {
            target: Target::ScanAttached(attached),
            cfg,
            started: false,
        })
    }

    /// Run the trace to completion — following every thread and child the
    /// target(s) spawn — invoking `on_event` for every detection. The trace
    /// ends once the last tracee has exited. This is the plain, event-only
    /// entry point; for a live progress UI, see [`Tracer::run_with`].
    pub fn run<F>(self, on_event: F) -> io::Result<Summary>
    where
        F: FnMut(&Event),
    {
        self.run_with(FnReporter(on_event))
    }

    /// Run the trace to completion, driving an arbitrary [`Reporter`]. The
    /// engine feeds it every detection and — when it asks via
    /// [`Reporter::wants_refresh`] — periodic per-process snapshots for a live
    /// display. The trace ends once the last tracee has exited.
    pub fn run_with<R>(self, mut reporter: R) -> io::Result<Summary>
    where
        R: Reporter,
    {
        Box::new(self).drive(&mut reporter)
    }

    /// Neutralise the syscall the tracee is stopped at by overwriting its
    /// syscall number with an invalid value: the kernel then skips the call and
    /// returns `-ENOSYS`, so the injected code's action never takes effect. The
    /// tracee lives on, which is what `--block` is for. Records the enforcement
    /// event through the engine on success.
    fn block_syscall(
        &self,
        who: Pid,
        tgid: i32,
        engine: &mut Engine,
        reporter: &mut dyn Reporter,
    ) -> io::Result<()> {
        let mut regs = ptrace::getregs(who).map_err(nix_err)?;
        let syscall = syscalls::name(regs.orig_rax);
        let rip = regs.rip.wrapping_sub(2);
        let rsp = regs.rsp;
        // -1 is not a valid syscall number; the kernel rejects it without
        // running anything and reports -ENOSYS to the tracee.
        regs.orig_rax = u64::MAX;
        ptrace::setregs(who, regs).map_err(nix_err)?;
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
        engine.record_event(tgid, &ev, reporter);
        Ok(())
    }

    /// `SIGKILL` every thread-group under trace. Sending the signal to a group
    /// leader (a tgid) tears down all of its threads at once, so the offending
    /// process — and every sibling we are following — dies before the syscall
    /// we stopped at can run.
    fn kill_tree(
        &self,
        who: Pid,
        tgid: i32,
        threads: &HashMap<i32, ThreadState>,
        engine: &mut Engine,
        reporter: &mut dyn Reporter,
    ) -> io::Result<()> {
        let (syscall, rip, rsp) = ptrace::getregs(who)
            .map(|r| (syscalls::name(r.orig_rax), r.rip.wrapping_sub(2), r.rsp))
            .unwrap_or_else(|_| (std::borrow::Cow::Borrowed("?"), 0, 0));

        // One SIGKILL per distinct thread-group is enough to take down all of
        // its threads; de-duplicating avoids redundant signals.
        let mut killed_groups = std::collections::HashSet::new();
        for ts in threads.values() {
            if killed_groups.insert(ts.tgid) {
                match kill(Pid::from_raw(ts.tgid), Signal::SIGKILL) {
                    Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                    Err(e) => return Err(nix_err(e)),
                }
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
        engine.record_event(tgid, &ev, reporter);
        Ok(())
    }

    /// A delivery stop does not establish termination: handlers and runtimes
    /// may intentionally catch these signals. Return bounded advisory context.
    fn on_signal(
        &self,
        pid: Pid,
        tgid: i32,
        sig: Signal,
        engine: &mut Engine,
        reporter: &mut dyn Reporter,
    ) -> Option<(u64, u64)> {
        if !diagnostic_signal(sig) {
            return None;
        }
        let (rip, rsp) = ptrace::getregs(pid)
            .map(|r| (r.rip, r.rsp))
            .unwrap_or((0, 0));
        let ev = Event::now(
            pid.as_raw(),
            Severity::Info,
            Kind::SignalDelivery,
            format!("signal:{sig:?}"),
            rip,
            rsp,
            "signal-delivery",
            format!("{sig:?} delivery observed; handler and termination outcome are unknown"),
        );
        engine.record_event(tgid, &ev, reporter);
        Some((rip, rsp))
    }
}

fn diagnostic_signal(sig: Signal) -> bool {
    matches!(
        sig,
        Signal::SIGSEGV | Signal::SIGILL | Signal::SIGBUS | Signal::SIGABRT | Signal::SIGFPE
    )
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if self.started {
            return;
        }
        match &self.target {
            Target::Spawned(pid) => {
                let _ = kill(*pid, Signal::SIGKILL);
                let _ = ptrace::cont(*pid, None);
                let _ = wait_tracee(*pid);
            }
            Target::Attached { threads, .. } | Target::ScanAttached(threads) => {
                for &pid in threads {
                    release_attached(pid);
                }
            }
        }
    }
}

/// Own every traced tid, including descendants, until its final wait is reaped.
struct TraceCleanup {
    tids: std::collections::HashSet<Pid>,
    owned: bool,
    enforcement_failed: bool,
}

impl Drop for TraceCleanup {
    fn drop(&mut self) {
        for &pid in &self.tids {
            if self.owned || self.enforcement_failed {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = ptrace::cont(pid, None);
                let _ = wait_tracee(pid);
            } else {
                release_attached(pid);
            }
        }
    }
}

impl Backend for Tracer {
    fn drive(mut self: Box<Self>, reporter: &mut dyn Reporter) -> io::Result<Summary> {
        let mut engine = Engine::new(self.cfg.clone());

        // The tracee(s) to seed, and — for a single spawned/attached target —
        // the one pid whose exit status the summary records. A `scan` has many
        // peers and no distinguished root.
        let (initial, root_pid): (Vec<Pid>, Option<i32>) = match &self.target {
            Target::Spawned(p) => (vec![*p], Some(p.as_raw())),
            Target::Attached { root, threads } => (threads.clone(), Some(root.as_raw())),
            Target::ScanAttached(pids) => (pids.clone(), None),
        };

        let mut cleanup = TraceCleanup {
            tids: initial.iter().copied().collect(),
            owned: matches!(self.target, Target::Spawned(_)),
            enforcement_failed: false,
        };
        self.started = true;

        // Per-thread entry/exit phase, tracked here because it is a `ptrace`
        // artifact; the shared maps and stats live in the engine.
        let mut threads: HashMap<i32, ThreadState> = HashMap::new();
        let mut last_refresh = Instant::now();
        // Only a successfully enforced tree kill permits ESRCH while draining.
        // Queued stops can outlive the task after SIGKILL, including other tids.
        let mut kill_pending = false;

        // Seed every initial tracee and kick each toward its first syscall stop.
        for p in &initial {
            let raw = p.as_raw();
            let tgid = read_tgid(raw);
            threads.insert(
                raw,
                ThreadState {
                    pending: None,
                    last_signal: None,
                    fatal_reported: false,
                    tgid,
                },
            );
            engine.register_space(tgid);
            ptrace::syscall(*p, None).map_err(nix_err)?;
        }
        engine.refresh(reporter, &mut last_refresh, true);

        loop {
            // Reap any tracee. `ECHILD` means every thread and child has gone.
            let status = match wait_tracee(Pid::from_raw(-1)) {
                Ok(s) => s,
                Err(e) if e.raw_os_error() == Some(libc::ECHILD) => break,
                Err(e) => return Err(e),
            };

            let Some(who) = status_pid(&status) else {
                continue;
            };
            let raw = who.as_raw();

            if kill_pending
                && !matches!(
                    status,
                    WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)
                )
            {
                // A clone may have been created before enforcement but first
                // reported afterwards. Kill late tracees as well as known tids.
                if cleanup.tids.insert(who) {
                    match kill(who, Signal::SIGKILL) {
                        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                        Err(e) => return Err(nix_err(e)),
                    }
                }
                match ptrace::cont(who, None) {
                    Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                    Err(e) => return Err(nix_err(e)),
                }
                continue;
            }

            // First sighting of a tid: a freshly-cloned thread or child, still
            // stopped at its creation stop with our trace options inherited.
            // Registering lazily on first sight (rather than parsing the parent
            // clone event) sidesteps the parent/child wait-ordering race.
            if let Entry::Vacant(slot) = threads.entry(raw) {
                if matches!(
                    status,
                    WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)
                ) {
                    cleanup.tids.remove(&who);
                    continue;
                }
                cleanup.tids.insert(who);
                let tgid = read_tgid(raw);
                slot.insert(ThreadState {
                    pending: None,
                    last_signal: None,
                    fatal_reported: false,
                    tgid,
                });
                engine.register_space(tgid);
                // Consume this initial stop and let the new tracee run; the
                // creation SIGSTOP must not be forwarded.
                let _ = ptrace::syscall(who, None);
                engine.refresh(reporter, &mut last_refresh, true);
                continue;
            }

            match status {
                WaitStatus::Exited(_, code) => {
                    let tgid = threads.get(&raw).map(|t| t.tgid);
                    threads.remove(&raw);
                    cleanup.tids.remove(&who);
                    engine.on_thread_exit(raw);
                    if Some(raw) == root_pid {
                        engine.set_exit_code(code);
                    }
                    mark_dead_if_last(&mut engine, &threads, tgid);
                    engine.refresh(reporter, &mut last_refresh, true);
                    if threads.is_empty() && !kill_pending {
                        break;
                    }
                }
                WaitStatus::Signaled(_, sig, _) => {
                    let thread = threads.remove(&raw);
                    let tgid = thread.as_ref().map(|state| state.tgid);
                    if diagnostic_signal(sig)
                        && thread.as_ref().is_some_and(|state| !state.fatal_reported)
                    {
                        let group = tgid.unwrap_or(raw);
                        let context = thread
                            .as_ref()
                            .and_then(|state| state.last_signal)
                            .filter(|(delivered, _, _)| *delivered == sig);
                        let (rip, rsp) = context.map(|(_, rip, rsp)| (rip, rsp)).unwrap_or((0, 0));
                        let detail = if context.is_some() {
                            format!("target terminated by {sig:?}; cause unknown; registers are cached delivery context, not a proven fault origin")
                        } else {
                            format!("target terminated by {sig:?}; cause unknown; register context unavailable")
                        };
                        let event = Event::now(
                            raw,
                            Severity::High,
                            Kind::Crash,
                            format!("signal:{sig:?}"),
                            rip,
                            rsp,
                            "terminal-signal",
                            detail,
                        );
                        engine.record_event(group, &event, reporter);
                        for state in threads.values_mut().filter(|state| state.tgid == group) {
                            state.fatal_reported = true;
                        }
                    }
                    cleanup.tids.remove(&who);
                    engine.on_thread_exit(raw);
                    if Some(raw) == root_pid {
                        engine.set_term_signal(sig as i32);
                    }
                    mark_dead_if_last(&mut engine, &threads, tgid);
                    engine.refresh(reporter, &mut last_refresh, true);
                    if threads.is_empty() && !kill_pending {
                        break;
                    }
                }
                WaitStatus::PtraceSyscall(_) => {
                    // The vacant-entry check above guarantees `raw` is known here;
                    // still, read it fallibly rather than index-and-panic, so a
                    // phantom stop from a kernel/wait race can never crash the
                    // sensor. An unattributable stop is simply resumed.
                    let tgid = match threads.get(&raw) {
                        Some(ts) => ts.tgid,
                        None => {
                            let _ = ptrace::syscall(who, None);
                            continue;
                        }
                    };
                    let mut killed = false;
                    let mut event_fired = false;
                    match syscall_stop(who)? {
                        SyscallStop::Entry(entry) => {
                            engine.count_syscall(tgid);
                            if let Some(ts) = threads.get_mut(&raw) {
                                let altstack = if entry.nr == 131 && entry.args[0] != 0 {
                                    capture_altstack(who, entry.args[0])
                                } else {
                                    None
                                };
                                ts.pending = Some(PendingSyscall { entry, altstack });
                            }
                            let step = engine.inspect(raw, tgid, &entry, reporter);
                            event_fired = step.event_fired;
                            // Enforce at the entry stop — the one moment the
                            // offending syscall has not yet run. The mechanism is
                            // ours; the engine already decided the policy.
                            match step.action {
                                Action::Block => {
                                    if let Err(e) =
                                        self.block_syscall(who, tgid, &mut engine, reporter)
                                    {
                                        cleanup.enforcement_failed = true;
                                        return Err(e);
                                    }
                                }
                                Action::Kill => {
                                    if let Err(e) =
                                        self.kill_tree(who, tgid, &threads, &mut engine, reporter)
                                    {
                                        cleanup.enforcement_failed = true;
                                        return Err(e);
                                    }
                                    killed = true;
                                    kill_pending = true;
                                }
                                Action::Proceed => {}
                            }
                        }
                        SyscallStop::Exit { result, is_error } => {
                            if let Some(pending) =
                                threads.get_mut(&raw).and_then(|ts| ts.pending.take())
                            {
                                if is_error && result >= 0 {
                                    return Err(io::Error::other(
                                        "inconsistent kernel syscall exit result",
                                    ));
                                }
                                engine.on_syscall_exit(raw, tgid, &pending.entry, result);
                                if pending.entry.nr == 131
                                    && pending.entry.args[0] != 0
                                    && !is_error
                                    && result == 0
                                {
                                    let registration = pending.altstack.ok_or_else(|| io::Error::other(
                                        "successful sigaltstack metadata unavailable; stack-policy coverage incomplete"))?;
                                    engine.register_altstack(
                                        raw,
                                        tgid,
                                        registration.start,
                                        registration.size,
                                        registration.flags,
                                    );
                                }
                            }
                        }
                    }
                    // Resume. After a kill the tracee is stopped with a pending
                    // SIGKILL; restarting it lets the kernel deliver it, and the
                    // call racing with the process's death is expected, so a
                    // failure here is not fatal to the trace.
                    if killed {
                        let _ = ptrace::syscall(who, None);
                    } else {
                        ptrace::syscall(who, None).map_err(nix_err)?;
                    }
                    // Repaint immediately on a detection, else at a throttled rate.
                    engine.refresh(reporter, &mut last_refresh, event_fired);
                }
                WaitStatus::Stopped(_, sig) => {
                    // Legacy TRACEME cannot LISTEN without restarting a group
                    // stop. Refuse this unsupported path rather than silently
                    // letting the target run without SIGCONT. Owned cleanup
                    // terminates/reaps the child on the operational error.
                    if cleanup.owned
                        && matches!(
                            sig,
                            Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                        )
                        && matches!(ptrace::getsiginfo(who), Err(nix::errno::Errno::EINVAL))
                    {
                        return Err(io::Error::other(
                            "job-control group stops are unsupported for launched targets; use a validated attach workflow",
                        ));
                    }
                    // Delivery is advisory, not a proven crash. Forward it so
                    // the target's handler/default disposition decides outcome.
                    let Some(tgid) = threads.get(&raw).map(|t| t.tgid) else {
                        ptrace::syscall(who, Some(sig)).map_err(nix_err)?;
                        continue;
                    };
                    engine.register_space(tgid);
                    let context = self.on_signal(who, tgid, sig, &mut engine, reporter);
                    if let Some((rip, rsp)) = context {
                        if let Some(state) = threads.get_mut(&raw) {
                            state.last_signal = Some((sig, rip, rsp));
                        }
                    }
                    ptrace::syscall(who, Some(sig)).map_err(nix_err)?;
                    engine.refresh(reporter, &mut last_refresh, context.is_some());
                }
                WaitStatus::PtraceEvent(_, sig, event) => {
                    if !cleanup.owned
                        && event == libc::PTRACE_EVENT_STOP
                        && matches!(
                            sig,
                            Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                        )
                    {
                        let result = unsafe { libc::ptrace(libc::PTRACE_LISTEN, raw, 0, 0) };
                        if result < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        continue;
                    }
                    if event == libc::PTRACE_EVENT_EXEC {
                        // Non-leader exec changes its tid to the group leader's;
                        // the former tid and all sibling threads cease to exist.
                        let former = ptrace::getevent(who).map_err(nix_err)? as i32;
                        let tgid = read_tgid(raw);
                        threads.remove(&former);
                        threads.retain(|tid, ts| *tid == raw || ts.tgid != tgid);
                        cleanup
                            .tids
                            .retain(|pid| threads.contains_key(&pid.as_raw()));
                        cleanup.tids.insert(who);
                        threads.insert(
                            raw,
                            ThreadState {
                                pending: None,
                                last_signal: None,
                                fatal_reported: false,
                                tgid,
                            },
                        );
                        engine.on_exec(tgid);
                    }
                    ptrace::syscall(who, None).map_err(nix_err)?;
                }
                WaitStatus::Continued(_) => {}
                WaitStatus::StillAlive => {}
            }
        }
        // A final frame so the last state is on screen before we return.
        engine.refresh(reporter, &mut last_refresh, true);
        Ok(engine.into_summary())
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
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACEEXEC;
    // EXITKILL ties the tracee's life to ours — right for a process we spawned
    // and own, but wrong when merely observing someone else's process (attach /
    // scan): stopping the monitor must not kill what it was watching.
    if kill_on_exit {
        opts |= Options::PTRACE_O_EXITKILL;
    }
    ptrace::setoptions(pid, opts).map_err(nix_err)
}

/// Freeze an entire existing thread group before enabling clone following.
/// Once all enumerated tids are stopped, a stable pass closes the creation race.
fn attach_group(pid: i32) -> io::Result<Vec<Pid>> {
    let tgid = read_tgid(pid);
    let mut attached = Vec::new();
    let result = (|| {
        for _ in 0..8 {
            let mut added = false;
            for entry in std::fs::read_dir(format!("/proc/{tgid}/task"))? {
                let tid: i32 = entry?
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| io::Error::other("invalid task id"))?;
                let task = Pid::from_raw(tid);
                if attached.contains(&task) {
                    continue;
                }
                if attached.len() >= 4096 {
                    return Err(io::Error::other(
                        "thread group exceeds attachment limit (4096)",
                    ));
                }
                match ptrace::seize(task, ptrace::Options::empty()) {
                    Ok(()) => {}
                    Err(nix::errno::Errno::ESRCH) => continue,
                    Err(e) => return Err(nix_err(e)),
                }
                attached.push(task);
                ptrace::interrupt(task).map_err(nix_err)?;
                match wait_tracee(task)? {
                    WaitStatus::PtraceEvent(_, _, _) | WaitStatus::Stopped(_, _) => {}
                    WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                        attached.pop();
                        continue;
                    }
                    status => {
                        return Err(io::Error::other(format!(
                            "unexpected attach stop: {status:?}"
                        )))
                    }
                }
                added = true;
            }
            if !added {
                if attached.is_empty() {
                    return Err(io::Error::other("thread group exited during attach"));
                }
                for &task in &attached {
                    set_options(task, false)?;
                }
                return Ok(());
            }
        }
        Err(io::Error::other(
            "thread group did not stabilize within 8 attachment passes",
        ))
    })();
    if let Err(e) = result {
        for task in &attached {
            release_attached(*task);
        }
        return Err(e);
    }
    Ok(attached)
}

fn wait_tracee(pid: Pid) -> io::Result<WaitStatus> {
    loop {
        // ptrace ownership is per OS thread. __WALL includes cloned tracees;
        // __WNOTHREAD prevents consuming a sibling thread's unrelated child or
        // another independent tracer's status. Spawn/attach and drive on the
        // same thread; arbitrary unrelated children on that thread are not safe.
        let flags = nix::sys::wait::WaitPidFlag::__WALL | nix::sys::wait::WaitPidFlag::__WNOTHREAD;
        match waitpid(pid, Some(flags)) {
            Err(nix::errno::Errno::EINTR) => continue,
            result => return result.map_err(nix_err),
        }
    }
}

fn release_attached(pid: Pid) {
    // INTERRUPT on an already stopped task may queue a future event instead of
    // generating a waitable stop, so detach a stopped task directly first.
    if ptrace::detach(pid, None).is_ok() {
        return;
    }
    // SEIZE permits a signal-free stop for cleanup, even from LISTEN state.
    if ptrace::interrupt(pid).is_ok() {
        let _ = wait_tracee(pid);
        let _ = ptrace::detach(pid, None);
    }
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

/// Mark a process dead once its last thread has gone. `tgid` is the group the
/// just-exited thread belonged to; if no surviving thread shares it, the
/// process is finished and its row flips to "exited".
fn mark_dead_if_last(engine: &mut Engine, threads: &HashMap<i32, ThreadState>, tgid: Option<i32>) {
    if let Some(tgid) = tgid {
        if !threads.values().any(|t| t.tgid == tgid) {
            engine.mark_dead(tgid);
        }
    }
}

fn nix_err(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

#[cfg(test)]
mod tests {
    #[cfg(target_env = "gnu")]
    #[test]
    fn syscall_info_request_matches_libc() {
        assert_eq!(
            super::PTRACE_GET_SYSCALL_INFO,
            libc::PTRACE_GET_SYSCALL_INFO
        );
        assert_eq!(super::PTRACE_GET_SYSCALL_INFO, 0x420e);
    }

    use super::*;

    #[test]
    fn syscall_exit_preserves_signed_result_and_kernel_error_bit() {
        let mut info = SyscallInfo {
            op: 2,
            arch: 0xc000003e,
            ..Default::default()
        };
        info.data[0] = (-9_i64) as u64;
        info.data[1] = 1;
        assert!(matches!(
            decode_syscall_info(&info, 33),
            Ok(SyscallStop::Exit {
                result: -9,
                is_error: true
            })
        ));
        info.data[0] = 12;
        info.data[1] = 0;
        assert!(matches!(
            decode_syscall_info(&info, 33),
            Ok(SyscallStop::Exit {
                result: 12,
                is_error: false
            })
        ));
    }

    #[test]
    fn syscall_info_rejects_x32_despite_native_audit_arch() {
        let mut info = SyscallInfo {
            op: 1,
            arch: 0xc000003e,
            ..Default::default()
        };
        info.data[0] = 0x40000000 | 41;
        assert!(decode_syscall_info(&info, 80).is_err());
    }

    #[test]
    fn syscall_info_distinguishes_entry_exit_and_rejects_short_records() {
        let mut info = SyscallInfo {
            op: 1,
            arch: 0xc000003e,
            ..Default::default()
        };
        assert!(matches!(
            decode_syscall_info(&info, 80),
            Ok(SyscallStop::Entry(_))
        ));
        assert!(decode_syscall_info(&info, 79).is_err());
        info.op = 2;
        assert!(matches!(
            decode_syscall_info(&info, 33),
            Ok(SyscallStop::Exit { .. })
        ));
        assert!(decode_syscall_info(&info, 32).is_err());
        info.arch = 0x40000003;
        assert!(decode_syscall_info(&info, 33).is_err());
    }
}
