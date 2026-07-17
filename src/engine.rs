//! The transport-agnostic detection core.
//!
//! Wraith's value is in *what* it checks at each syscall — provenance, W^X,
//! stack integrity, the exploitation-chain correlator — not in *how* the
//! syscall stop is obtained. [`Engine`] owns everything on the first side of
//! that line: the [`Detector`], the per-address-space cached memory map, the
//! per-process live [`ProcStat`]s, the running [`Summary`], and the decision of
//! whether a confirmed exploitation should be enforced.
//!
//! A *transport* — the `ptrace` engine today, an eBPF backend tomorrow — is a
//! [`Backend`]. It captures a [`SyscallEntry`] however it can (a `ptrace`
//! `getregs`, an eBPF `sys_enter` tracepoint) and feeds it to
//! [`Engine::inspect`], which runs detection and hands back the enforcement
//! [`Action`] to carry out. The *mechanism* of enforcement (rewriting the
//! syscall, killing the tree) stays with the backend, because only it knows how
//! to touch its tracees; the *policy* (fire only on a CRITICAL verdict) lives
//! here so every backend shares it. Because the engine never issues a single
//! `ptrace` call itself, the same detection logic drives any transport
//! unchanged — the model is transport-agnostic by design.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::time::{Duration, Instant};

use crate::detect::{Config, Detector, Enforcement, SyscallCtx};
use crate::event::{Event, Severity};
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

/// A raw syscall-entry register snapshot, captured by whatever transport is in
/// use. `rip` points just past the two-byte `syscall` instruction (as the
/// hardware leaves it); the engine rewinds it to the instruction site itself.
#[derive(Debug, Clone, Copy)]
pub struct SyscallEntry {
    /// The syscall number (`orig_rax` on x86-64).
    pub nr: u64,
    /// The instruction pointer, pointing just past the `syscall` instruction.
    pub rip: u64,
    /// The stack pointer at the trap.
    pub rsp: u64,
    /// Syscall arguments in x86-64 ABI order: rdi, rsi, rdx, r10, r8, r9.
    pub args: [u64; 6],
}

/// The enforcement action a [`Backend`] must carry out after a syscall-entry is
/// inspected. The engine decides *whether* to act; the backend knows *how*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Let the syscall run — the default, and the only outcome under `Observe`.
    Proceed,
    /// Neutralise this syscall in place before it executes (`--block`).
    Block,
    /// Kill the whole traced tree before this syscall executes (`--kill`).
    Kill,
}

/// What one [`Engine::inspect`] produced: the enforcement action to take, and
/// whether any event fired (so the backend can force an immediate UI repaint).
#[derive(Debug, Clone, Copy)]
pub struct Step {
    pub action: Action,
    pub event_fired: bool,
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

/// Live, per-process statistics surfaced to a [`Reporter`] during a run, so a
/// UI can show what each traced process is doing in real time. Keyed by
/// thread-group id — one entry per address space, matching how detection is
/// scoped — so every thread of a process rolls up into one row.
#[derive(Debug, Clone)]
pub struct ProcStat {
    pub tgid: i32,
    pub name: String,
    pub syscalls: u64,
    pub events: u64,
    pub max_severity: Option<Severity>,
    pub alive: bool,
}

impl ProcStat {
    fn new(tgid: i32) -> Self {
        ProcStat {
            tgid,
            name: read_comm(tgid),
            syscalls: 0,
            events: 0,
            max_severity: None,
            alive: true,
        }
    }

    fn record(&mut self, ev: &Event) {
        self.events += 1;
        self.max_severity = Some(match self.max_severity {
            Some(cur) => cur.max(ev.severity),
            None => ev.severity,
        });
    }
}

/// The sink for a run's output. Detection events arrive via [`Reporter::event`];
/// an implementor that also wants live progress overrides [`Reporter::wants_refresh`]
/// to return `true` and paints in [`Reporter::refresh`]. The defaults make a
/// plain event-only consumer (a logging closure, the test harness) pay nothing
/// for progress machinery it doesn't use — the engine skips building snapshots
/// entirely when no one is watching.
pub trait Reporter {
    /// One detection fired.
    fn event(&mut self, ev: &Event);
    /// Whether this reporter wants periodic [`refresh`](Reporter::refresh)
    /// snapshots. Default `false`.
    fn wants_refresh(&self) -> bool {
        false
    }
    /// A periodic snapshot of every traced process and the running aggregate.
    /// Only called when [`wants_refresh`](Reporter::wants_refresh) is `true`.
    fn refresh(&mut self, _stats: &[ProcStat], _summary: &Summary) {}
}

/// A syscall-transport engine: it drives its tracee(s), captures each
/// syscall-entry into a [`SyscallEntry`], feeds them to an owned [`Engine`],
/// and applies the enforcement the engine asks for. The `ptrace` [`Tracer`] is
/// the first implementor; an eBPF backend would be the second, reusing the same
/// [`Engine`] unchanged.
///
/// [`Tracer`]: crate::tracer::Tracer
pub trait Backend {
    /// Run the trace to completion, feeding every detection (and, if the
    /// reporter asks, periodic progress snapshots) to `reporter`, and return
    /// the run summary once the last tracee has exited.
    fn drive(self: Box<Self>, reporter: &mut dyn Reporter) -> io::Result<Summary>;
}

/// The detection core shared by every [`Backend`]. Owns the detector, the
/// per-address-space cached maps, the per-process stats, and the run summary;
/// exposes exactly the operations a transport needs to drive detection without
/// ever issuing a syscall of its own.
pub struct Engine {
    detector: Detector,
    /// The enforcement policy — what to do on a confirmed (CRITICAL) verdict.
    enforcement: Enforcement,
    /// One cached map per address space (thread-group id). Threads that share
    /// memory share an entry; a memory op by any of them marks it dirty.
    spaces: HashMap<i32, AddrSpace>,
    /// One live-stats row per address space, surfaced to the reporter.
    stats: HashMap<i32, ProcStat>,
    summary: Summary,
}

impl Engine {
    /// Build an engine from a [`Config`]. The enforcement policy is taken from
    /// the config so the backend and the detector agree on it.
    pub fn new(cfg: Config) -> Self {
        let enforcement = cfg.enforcement;
        Engine {
            detector: Detector::new(cfg),
            enforcement,
            spaces: HashMap::new(),
            stats: HashMap::new(),
            summary: Summary::default(),
        }
    }

    /// Ensure the per-address-space map cache and the per-process stats row for
    /// `tgid` exist. A backend calls this when it first sees a thread-group, so
    /// a process shows up in the live view even before its first syscall.
    pub fn register_space(&mut self, tgid: i32) {
        self.spaces.entry(tgid).or_insert_with(AddrSpace::new);
        self.stats.entry(tgid).or_insert_with(|| ProcStat::new(tgid));
    }

    /// Count one syscall for `tgid` against the summary and its stats row. Kept
    /// separate from [`inspect`](Engine::inspect) so a syscall still counts even
    /// when the backend cannot read its registers (a lost stop is still work the
    /// tracee did).
    pub fn count_syscall(&mut self, tgid: i32) {
        self.summary.syscalls_seen += 1;
        self.stats
            .entry(tgid)
            .or_insert_with(|| ProcStat::new(tgid))
            .syscalls += 1;
    }

    /// Inspect one syscall-entry: refresh the shared map if a prior memory op
    /// could have changed it, run the detector, record every event it fires,
    /// mark the map stale if this call is itself a memory op, and return the
    /// enforcement [`Action`] the backend should carry out.
    pub fn inspect(
        &mut self,
        pid: i32,
        tgid: i32,
        entry: &SyscallEntry,
        reporter: &mut dyn Reporter,
    ) -> Step {
        let nr = entry.nr;

        // Refresh the shared map if stale or unset. Reading `/proc/<tid>/maps`
        // for any thread yields the whole group's address space. Scoped so the
        // &mut to `spaces` is released before detection re-borrows it read-only.
        {
            let space = self.spaces.entry(tgid).or_insert_with(AddrSpace::new);
            if space.dirty || space.map.is_none() {
                if let Ok(fresh) = MemoryMap::read(pid) {
                    space.map = Some(fresh);
                    space.dirty = false;
                }
            }
        }

        // Run detection against the current map, if we have one. `detector`,
        // `summary` and `stats` are disjoint fields from `spaces`, so the
        // read-only map borrow coexists with recording events.
        let mut max_severity = None;
        if let Some(current) = self.spaces.get(&tgid).and_then(|s| s.map.as_ref()) {
            // The `syscall` instruction is two bytes; rip already points past it.
            let ctx = SyscallCtx {
                pid,
                nr,
                rip: entry.rip.wrapping_sub(2),
                rsp: entry.rsp,
                args: entry.args,
            };
            let stat = self.stats.entry(tgid).or_insert_with(|| ProcStat::new(tgid));
            for ev in self.detector.on_syscall(tgid, &ctx, current) {
                max_severity =
                    Some(max_severity.map_or(ev.severity, |cur: Severity| cur.max(ev.severity)));
                self.summary.record(&ev);
                stat.record(&ev);
                reporter.event(&ev);
            }
        }

        // A memory op by any thread can change the shared address space;
        // invalidate the whole group's map so the next inspection re-reads it.
        if syscalls::is_memory_op(nr) {
            if let Some(space) = self.spaces.get_mut(&tgid) {
                space.dirty = true;
            }
        }

        // Enforce only on a confirmed exploitation (CRITICAL). The backend acts
        // at the syscall's entry stop — the one moment it has not yet run.
        let critical = max_severity == Some(Severity::Critical);
        let action = if critical {
            match self.enforcement {
                Enforcement::Block => Action::Block,
                Enforcement::Kill => Action::Kill,
                Enforcement::Observe => Action::Proceed,
            }
        } else {
            Action::Proceed
        };

        Step { action, event_fired: max_severity.is_some() }
    }

    /// Record a backend-originated event (an enforcement action, a fatal-fault
    /// crash) against the summary, the `tgid`'s stats row, and the reporter.
    /// Detection events go through [`inspect`](Engine::inspect); this is the
    /// shared sink for events the transport raises itself.
    pub fn record_event(&mut self, tgid: i32, ev: &Event, reporter: &mut dyn Reporter) {
        self.summary.record(ev);
        if let Some(stat) = self.stats.get_mut(&tgid) {
            stat.record(ev);
        }
        reporter.event(ev);
    }

    /// Record the root tracee's exit code into the summary.
    pub fn set_exit_code(&mut self, code: i32) {
        self.summary.exit_code = Some(code);
    }

    /// Record the root tracee's terminating signal into the summary.
    pub fn set_term_signal(&mut self, sig: i32) {
        self.summary.term_signal = Some(sig);
    }

    /// Flip a process's live-stats row to "exited" and release the state that is
    /// no longer needed now that its last thread is gone. A backend calls this
    /// once the last thread of `tgid` has exited.
    ///
    /// The cached memory map (by far the largest per-process allocation — a
    /// `Vec` of every mapped region, each with its path) and the detector's
    /// per-process chain accumulator are dropped, so tracing a long-lived target
    /// that spawns many short-lived children no longer leaks memory without
    /// bound. The lightweight stats row is deliberately kept (only flipped to
    /// "exited") so the UI can still show the process that just finished.
    pub fn mark_dead(&mut self, tgid: i32) {
        if let Some(s) = self.stats.get_mut(&tgid) {
            s.alive = false;
        }
        self.spaces.remove(&tgid);
        self.detector.retire(tgid);
    }

    /// Push a live snapshot to the reporter. When `force` is false the paint is
    /// throttled to ~20 fps so a syscall-heavy target doesn't spend its time
    /// redrawing; `force` (a detection, a process lifecycle change, the final
    /// frame) always paints. Skipped entirely — no snapshot built — when the
    /// reporter doesn't want progress, so the plain event path costs nothing.
    pub fn refresh(&self, reporter: &mut dyn Reporter, last: &mut Instant, force: bool) {
        if !reporter.wants_refresh() {
            return;
        }
        let now = Instant::now();
        if !force && now.duration_since(*last) < Duration::from_millis(50) {
            return;
        }
        *last = now;
        let mut snap: Vec<ProcStat> = self.stats.values().cloned().collect();
        snap.sort_by_key(|s| s.tgid);
        reporter.refresh(&snap, &self.summary);
    }

    /// Consume the engine and return the accumulated summary.
    pub fn into_summary(self) -> Summary {
        self.summary
    }
}

/// The thread-group id of a thread, read once from `/proc/<tid>/status`.
/// Threads of a process share a tgid (and their address space); a `fork`ed
/// child gets its own. Falls back to the tid itself if status is unreadable.
pub fn read_tgid(tid: i32) -> i32 {
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

/// The short `comm` name of a process (e.g. `nginx`), read once. Falls back to
/// the pid rendered as a string when `/proc/<pid>/comm` is unreadable.
fn read_comm(pid: i32) -> String {
    match fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => pid.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Config;

    #[test]
    fn dead_process_frees_space_but_keeps_stats_row() {
        let mut e = Engine::new(Config::default());
        e.register_space(4242);
        assert!(e.spaces.contains_key(&4242));
        assert!(e.stats.contains_key(&4242));

        e.mark_dead(4242);

        // The stats row survives (flipped to exited) so the UI can show it...
        assert_eq!(e.stats.get(&4242).map(|s| s.alive), Some(false));
        // ...but the heavy cached map is released, bounding memory on long traces.
        assert!(!e.spaces.contains_key(&4242), "dead space must be freed");
    }
}
