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

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::time::{Duration, Instant};

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
    /// One warning per consecutive refresh-loss streak; every failed decision
    /// still increments the summary's coverage counter.
    lost: bool,
}

impl AddrSpace {
    fn new() -> Self {
        AddrSpace {
            map: None,
            dirty: true,
            lost: false,
        }
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
    /// Inspections whose current memory map was unavailable; recovery does not
    /// turn an incomplete run into a clean fully-covered result.
    pub coverage_gaps: u64,
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
    retired: VecDeque<i32>,
    max_retired_processes: usize,
    /// Private function-pointer seam: deterministic coverage-loss tests without
    /// introducing a public reader abstraction or remote dependencies.
    map_reader: fn(i32) -> io::Result<MemoryMap>,
}

impl Engine {
    /// Build an engine from a [`Config`]. The enforcement policy is taken from
    /// the config so the backend and the detector agree on it.
    pub fn new(cfg: Config) -> Self {
        let enforcement = cfg.enforcement;
        Engine {
            max_retired_processes: cfg.max_retired_processes,
            detector: Detector::new(cfg),
            enforcement,
            spaces: HashMap::new(),
            stats: HashMap::new(),
            summary: Summary::default(),
            retired: VecDeque::new(),
            map_reader: MemoryMap::read,
        }
    }

    /// Ensure the per-address-space map cache and the per-process stats row for
    /// `tgid` exist. A backend calls this when it first sees a thread-group, so
    /// a process shows up in the live view even before its first syscall.
    pub fn register_space(&mut self, tgid: i32) {
        self.spaces.entry(tgid).or_insert_with(AddrSpace::new);
        if self.stats.get(&tgid).map_or(true, |row| !row.alive) {
            self.retired.retain(|&retired| retired != tgid);
            self.stats.insert(tgid, ProcStat::new(tgid));
        }
    }

    /// Invalidate a shared snapshot after a memory operation completes. Entry
    /// invalidation alone can be consumed by another thread before it runs.
    pub fn invalidate_maps(&mut self, tgid: i32) {
        self.spaces.entry(tgid).or_insert_with(AddrSpace::new).dirty = true;
    }

    /// Successful exec replaces the address space, so old maps and correlation
    /// evidence no longer describe this program. Historical totals survive.
    pub fn on_exec(&mut self, tgid: i32) {
        self.register_space(tgid);
        self.spaces.insert(tgid, AddrSpace::new());
        self.detector.retire(tgid);
        let stat = self
            .stats
            .entry(tgid)
            .or_insert_with(|| ProcStat::new(tgid));
        stat.name = read_comm(tgid);
        stat.alive = true;
    }

    /// Count one syscall for `tgid` against the summary and its stats row. Kept
    /// separate from [`inspect`](Engine::inspect) so a syscall still counts even
    /// when the backend cannot read its registers (a lost stop is still work the
    /// tracee did).
    pub fn count_syscall(&mut self, tgid: i32) {
        self.register_space(tgid);
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

        self.register_space(tgid);
        let needs_refresh = self
            .spaces
            .get(&tgid)
            .is_some_and(|space| space.dirty || space.map.is_none());
        if needs_refresh && !self.refresh_map(pid, tgid) {
            return self.coverage_gap(pid, tgid, entry, reporter);
        }

        // A cache miss or impossible execution permission can mean another
        // thread changed mappings outside our last snapshot. Retry once, never
        // repeatedly spin on unavailable procfs or an inherently uncertain stop.
        let site = entry.rip.wrapping_sub(2);
        let retry = self
            .spaces
            .get(&tgid)
            .and_then(|s| s.map.as_ref())
            .is_some_and(|map| map.region_at(site).map_or(true, |r| !r.exec));
        if retry && !self.refresh_map(pid, tgid) {
            return self.coverage_gap(pid, tgid, entry, reporter);
        }

        if let Some(space) = self.spaces.get_mut(&tgid) {
            space.lost = false;
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
            let stat = self
                .stats
                .entry(tgid)
                .or_insert_with(|| ProcStat::new(tgid));
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

        Step {
            action,
            event_fired: max_severity.is_some(),
        }
    }

    fn refresh_map(&mut self, pid: i32, tgid: i32) -> bool {
        let outcome = (self.map_reader)(pid);
        let space = self.spaces.entry(tgid).or_insert_with(AddrSpace::new);
        match outcome {
            Ok(fresh) if !fresh.regions().is_empty() => {
                space.map = Some(fresh);
                space.dirty = false;
                true
            }
            _ => {
                // Never retain stale permissions for the current decision.
                space.map = None;
                space.dirty = true;
                false
            }
        }
    }

    fn coverage_gap(
        &mut self,
        pid: i32,
        tgid: i32,
        entry: &SyscallEntry,
        reporter: &mut dyn Reporter,
    ) -> Step {
        self.summary.coverage_gaps = self.summary.coverage_gaps.saturating_add(1);
        self.detector.clear_evidence(tgid);
        let space = self.spaces.entry(tgid).or_insert_with(AddrSpace::new);
        let first_loss = !space.lost;
        space.lost = true;
        if first_loss {
            let event = Event::now(pid, Severity::Warn, Kind::CoverageGap,
                syscalls::name(entry.nr), entry.rip.wrapping_sub(2), entry.rsp,
                "unavailable", "current memory map unavailable; provenance and enforcement skipped for this syscall");
            self.record_event(tgid, &event, reporter);
        }
        Step {
            action: Action::Proceed,
            event_fired: first_loss,
        }
    }

    /// Pair a kernel-reported exit with this TID's original entry. Map ops are
    /// invalidated regardless of return: failed mprotect can partially mutate.
    pub fn on_syscall_exit(&mut self, pid: i32, tgid: i32, entry: &SyscallEntry, result: i64) {
        let ctx = SyscallCtx {
            pid,
            nr: entry.nr,
            rip: entry.rip.wrapping_sub(2),
            rsp: entry.rsp,
            args: entry.args,
        };
        self.detector.on_syscall_exit(tgid, &ctx, result);
        if syscalls::is_memory_op(entry.nr) {
            self.invalidate_maps(tgid);
        }
    }

    /// Enroll exact RSP-only metadata after the backend observed sigaltstack
    /// succeed. Existing attachments may predate registration and are not guessed.
    pub fn register_altstack(&mut self, pid: i32, tgid: i32, start: u64, len: u64, flags: u64) {
        self.detector
            .register_altstack(pid, tgid, start, len, flags);
    }

    /// Release bounded per-thread pending state on terminal status.
    pub fn on_thread_exit(&mut self, pid: i32) {
        self.detector.retire_thread(pid);
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
    /// bound. A bounded history of lightweight exited rows remains for the UI;
    /// live rows are never evicted to satisfy the historical-row limit.
    pub fn mark_dead(&mut self, tgid: i32) {
        if let Some(row) = self.stats.get_mut(&tgid) {
            if row.alive {
                row.alive = false;
                self.retired.push_back(tgid);
            }
        }
        self.spaces.remove(&tgid);
        self.detector.retire(tgid);
        while self.retired.len() > self.max_retired_processes {
            if let Some(retired) = self.retired.pop_front() {
                if self.stats.get(&retired).is_some_and(|row| !row.alive) {
                    self.stats.remove(&retired);
                }
            }
        }
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
    use crate::event::Kind;

    #[test]
    fn coverage_counter_and_shared_json_escape_are_available() {
        assert_eq!(Summary::default().coverage_gaps, 0);
        assert_eq!(crate::event::json_escape("a\"b"), "a\\\"b");
    }

    #[test]
    fn failed_refresh_discards_stale_rwx_and_reports_loss_once() {
        struct Sink(Vec<Event>);
        impl Reporter for Sink {
            fn event(&mut self, event: &Event) {
                self.0.push(event.clone());
            }
        }
        let mut engine = Engine::new(Config {
            enforcement: Enforcement::Block,
            ..Config::default()
        });
        engine.register_space(-1);
        engine.spaces.get_mut(&-1).unwrap().map =
            Some(MemoryMap::parse("1000-2000 rwxp 0 00:00 0"));
        engine.spaces.get_mut(&-1).unwrap().dirty = true;
        let entry = SyscallEntry {
            nr: 41,
            rip: 0x1102,
            rsp: 0,
            args: [0; 6],
        };
        let mut sink = Sink(Vec::new());
        for _ in 0..4 {
            assert_eq!(
                engine.inspect(-1, -1, &entry, &mut sink).action,
                Action::Proceed,
                "a failed refresh must not enforce from a stale RWX snapshot"
            );
        }
        assert!(engine.spaces.get(&-1).unwrap().map.is_none());
        assert_eq!(
            sink.0
                .iter()
                .filter(|event| event.kind.as_str() == "coverage_gap")
                .count(),
            1
        );
    }

    #[test]
    fn real_rx_transition_cannot_enforce_from_failed_cached_rwx() {
        struct Mapping(*mut libc::c_void);
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.0, 4096);
                }
            }
        }
        fn fail(_: i32) -> io::Result<MemoryMap> {
            Err(io::Error::other("injected map refresh failure"))
        }
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        let memory = Mapping(pointer);
        let pid = std::process::id() as i32;
        let snapshot = MemoryMap::read(pid).unwrap();
        let cached = snapshot.region_at(memory.0 as u64).unwrap();
        assert!(cached.write && cached.exec);
        assert_eq!(
            unsafe { libc::mprotect(memory.0, 4096, libc::PROT_READ | libc::PROT_EXEC) },
            0
        );
        assert!(
            !MemoryMap::read(pid)
                .unwrap()
                .region_at(memory.0 as u64)
                .unwrap()
                .write
        );
        let mut engine = Engine::new(Config {
            enforcement: Enforcement::Kill,
            ..Config::default()
        });
        engine.register_space(pid);
        engine.spaces.get_mut(&pid).unwrap().map = Some(snapshot);
        engine.spaces.get_mut(&pid).unwrap().dirty = false;
        engine.invalidate_maps(pid);
        engine.map_reader = fail;
        struct Sink(Vec<Event>);
        impl Reporter for Sink {
            fn event(&mut self, event: &Event) {
                self.0.push(event.clone());
            }
        }
        let mut sink = Sink(Vec::new());
        let step = engine.inspect(
            pid,
            pid,
            &SyscallEntry {
                nr: 41,
                rip: memory.0 as u64 + 2,
                rsp: 0,
                args: [0; 6],
            },
            &mut sink,
        );
        assert_eq!(step.action, Action::Proceed);
        assert_eq!(engine.summary.coverage_gaps, 1);
        assert_eq!(sink.0.len(), 1);
        assert_eq!(sink.0[0].kind, Kind::CoverageGap);
    }

    #[test]
    fn failed_retry_stays_one_loss_streak_until_a_decision_recovers() {
        fn alternating(_: i32) -> io::Result<MemoryMap> {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static CALLS: AtomicUsize = AtomicUsize::new(0);
            if CALLS.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
                Ok(MemoryMap::parse("1000-2000 rw-p 0 00:00 0"))
            } else {
                Err(io::Error::other("injected retry failure"))
            }
        }
        struct Sink(Vec<Event>);
        impl Reporter for Sink {
            fn event(&mut self, event: &Event) {
                self.0.push(event.clone());
            }
        }
        let mut engine = Engine::new(Config::default());
        engine.map_reader = alternating;
        let entry = SyscallEntry {
            nr: 41,
            rip: 0x1102,
            rsp: 0,
            args: [0; 6],
        };
        let mut sink = Sink(Vec::new());
        for _ in 0..3 {
            assert_eq!(
                engine.inspect(-1, -1, &entry, &mut sink).action,
                Action::Proceed
            );
        }
        assert_eq!(engine.summary.coverage_gaps, 3);
        assert_eq!(
            sink.0.len(),
            1,
            "successful read followed by failed retry did not restore decision coverage"
        );
    }

    #[test]
    fn coverage_recovery_restores_detection_but_keeps_incomplete_summary() {
        fn fail(_: i32) -> io::Result<MemoryMap> {
            Err(io::Error::other("injected procfs failure"))
        }
        fn recover(_: i32) -> io::Result<MemoryMap> {
            Ok(MemoryMap::parse("1000-2000 r-xp 0 08:01 1 /app"))
        }
        struct Sink(Vec<Event>);
        impl Reporter for Sink {
            fn event(&mut self, event: &Event) {
                self.0.push(event.clone());
            }
        }
        let mut engine = Engine::new(Config {
            enforcement: Enforcement::Kill,
            ..Config::default()
        });
        engine.map_reader = fail;
        let entry = SyscallEntry {
            nr: 41,
            rip: 0x1102,
            rsp: 0,
            args: [0; 6],
        };
        let mut sink = Sink(Vec::new());
        assert_eq!(
            engine.inspect(-1, -1, &entry, &mut sink).action,
            Action::Proceed
        );
        assert_eq!(
            engine.inspect(-1, -1, &entry, &mut sink).action,
            Action::Proceed
        );
        assert_eq!(engine.summary.coverage_gaps, 2);
        assert_eq!(sink.0.len(), 1);
        engine.map_reader = recover;
        assert!(!engine.inspect(-1, -1, &entry, &mut sink).event_fired);
        assert_eq!(
            engine.summary.coverage_gaps, 2,
            "recovery cannot erase incomplete coverage"
        );
        engine.invalidate_maps(-1);
        engine.map_reader = fail;
        engine.inspect(-1, -1, &entry, &mut sink);
        assert_eq!(engine.summary.coverage_gaps, 3);
        assert_eq!(sink.0.len(), 2, "new loss streak must become visible again");
        assert!(sink
            .0
            .iter()
            .all(|event| event.kind == Kind::CoverageGap && event.severity == Severity::Warn));
    }

    #[test]
    fn reused_group_resets_retired_row_without_resetting_aggregate() {
        let mut engine = Engine::new(Config::default());
        engine.register_space(-1);
        engine.count_syscall(-1);
        engine.mark_dead(-1);
        engine.register_space(-1);
        engine.count_syscall(-1);
        let row = engine.stats.get(&-1).unwrap();
        assert!(row.alive, "reused group must become alive");
        assert_eq!(
            row.syscalls, 1,
            "new process gets a new statistics lifecycle"
        );
        assert_eq!(engine.summary.syscalls_seen, 2);
    }

    #[test]
    fn historical_rows_are_bounded_without_evicting_live_processes() {
        let mut engine = Engine::new(Config::default());
        // Negative synthetic keys cannot inspect unrelated real /proc PIDs.
        engine.register_space(-9999);
        for number in 1..=512 {
            let tgid = -number;
            engine.register_space(tgid);
            engine.count_syscall(tgid);
            engine.mark_dead(tgid);
        }
        assert!(
            engine.stats.len() <= 129,
            "unbounded retired rows: {}",
            engine.stats.len()
        );
        assert!(engine.stats.get(&-9999).unwrap().alive);
        assert_eq!(engine.summary.syscalls_seen, 512);
    }

    #[test]
    fn uncertain_map_does_not_request_enforcement() {
        struct Sink;
        impl Reporter for Sink {
            fn event(&mut self, _: &Event) {}
        }
        let mut e = Engine::new(Config {
            enforcement: Enforcement::Kill,
            ..Config::default()
        });
        // A nonexistent pid prevents refresh, leaving a deliberately stale snapshot.
        e.spaces.insert(
            -1,
            AddrSpace {
                map: Some(MemoryMap::parse("1000-2000 r-xp 0 08:01 1 /app")),
                dirty: false,
                lost: false,
            },
        );
        let step = e.inspect(
            -1,
            -1,
            &SyscallEntry {
                nr: 59,
                rip: 0x3002,
                rsp: 0,
                args: [0; 6],
            },
            &mut Sink,
        );
        assert_eq!(step.action, Action::Proceed);
    }

    #[test]
    fn cache_miss_refreshes_before_provenance_detection() {
        struct Sink;
        impl Reporter for Sink {
            fn event(&mut self, _: &Event) {}
        }
        let pid = std::process::id() as i32;
        let mut e = Engine::new(Config::default());
        e.spaces.insert(
            pid,
            AddrSpace {
                map: Some(MemoryMap::default()),
                dirty: false,
                lost: false,
            },
        );
        let rip = Engine::new as *const () as u64;
        let step = e.inspect(
            pid,
            pid,
            &SyscallEntry {
                nr: 1,
                rip: rip + 2,
                rsp: 0,
                args: [0; 6],
            },
            &mut Sink,
        );
        assert!(
            !step.event_fired,
            "a real executable site must refresh a stale empty snapshot"
        );
        assert!(e
            .spaces
            .get(&pid)
            .unwrap()
            .map
            .as_ref()
            .unwrap()
            .region_at(rip)
            .is_some());
    }

    #[test]
    fn exec_resets_space_and_evidence_preserving_totals() {
        let mut e = Engine::new(Config::default());
        e.register_space(-1);
        e.count_syscall(-1);
        e.spaces.get_mut(&-1).unwrap().map = Some(MemoryMap::parse("1000-2000 rwxp 0 00:00 0"));
        e.spaces.get_mut(&-1).unwrap().dirty = false;
        let map = e.spaces.get(&-1).unwrap().map.as_ref().unwrap().clone();
        e.detector.on_syscall(
            -1,
            &SyscallCtx {
                pid: -1,
                nr: 0,
                rip: 0x1100,
                rsp: 0,
                args: [0; 6],
            },
            &map,
        );
        e.on_exec(-1);
        let events = e.detector.on_syscall(
            -1,
            &SyscallCtx {
                pid: -1,
                nr: 41,
                rip: 0x1100,
                rsp: 0,
                args: [0; 6],
            },
            &map,
        );
        assert!(!events
            .iter()
            .any(|ev| ev.kind == crate::event::Kind::ExploitationChain));
        assert!(e.spaces.get(&-1).unwrap().map.is_none());
        assert!(e.spaces.get(&-1).unwrap().dirty);
        assert_eq!(e.stats.get(&-1).unwrap().syscalls, 1);
        assert_eq!(e.summary.syscalls_seen, 1);
    }

    #[test]
    fn memory_exit_invalidates_cached_maps() {
        let mut e = Engine::new(Config::default());
        e.register_space(-1);
        e.spaces.get_mut(&-1).unwrap().dirty = false;
        e.invalidate_maps(-1);
        assert!(e.spaces.get(&-1).unwrap().dirty);
    }

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
