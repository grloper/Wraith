//! The detection engine.
//!
//! [`Detector`] is fed one [`SyscallCtx`] per syscall-entry stop plus the
//! current [`MemoryMap`], and returns any [`Event`]s that fire. It also runs a
//! lightweight correlator: individual primitives (a W^X page, a foreign-origin
//! syscall, a stack pivot) are suspicious on their own, but seen together in
//! one process they are an exploitation chain, and Wraith says so explicitly.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::event::{Event, Kind, Severity};
use crate::maps::MemoryMap;
use crate::provenance::{classify_rip, classify_rsp, Origin, Prot, StackState};
use crate::syscalls;

/// What Wraith does when it is confident it has caught exploitation (a
/// CRITICAL event). Detection is always on; enforcement decides whether Wraith
/// also intervenes to stop the attack in its tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Enforcement {
    /// Detect and report without rewriting syscalls or deliberately killing the
    /// tracee. Ptrace observation still changes timing and execution scheduling.
    #[default]
    Observe,
    /// Neutralise the offending syscall in place: at its entry stop the syscall
    /// number is overwritten so the kernel skips it and returns an error, so
    /// the injected code's `execve`/`connect`/… never actually runs. The
    /// process keeps going, which is useful when you want it to survive (and
    /// log what it does next) rather than die.
    Block,
    /// `SIGKILL` the whole traced tree the instant exploitation is confirmed,
    /// before the offending syscall executes.
    Kill,
}

/// Tunable behaviour.
#[derive(Debug, Clone)]
pub struct Config {
    /// Strict no-JIT policy: anonymous RX origins are HIGH, or CRITICAL for
    /// sensitive syscalls. Default WARN because legitimate runtimes execute
    /// generated code there; their input and W->X activity alone proves no exploit.
    pub jit_is_critical: bool,
    /// Enable the ROP stack-pivot heuristic.
    pub detect_stack_pivot: bool,
    /// Emit INFO breadcrumbs for sensitive syscalls from legitimate origins.
    pub audit_sensitive: bool,
    /// Half-open `[start, end)` address ranges the operator vouches for as
    /// legitimate JIT / runtime-generated code. A syscall whose instruction
    /// pointer — or an `mmap`/`mprotect` whose target page — falls inside one
    /// of these is exempt from the provenance and W^X rules, so a known JIT
    /// engine can be monitored without drowning the operator in false
    /// positives. Empty by default, so it changes nothing unless asked for.
    pub trusted_regions: Vec<(u64, u64)>,
    /// Whether (and how) to actively stop confirmed exploitation. See
    /// [`Enforcement`].
    pub enforcement: Enforcement,
    /// Maximum intervening syscall entries for coarse correlation evidence.
    /// A fixed 30-second monotonic TTL also bounds idle evidence.
    pub correlation_window: u64,
    /// Retained exited process rows; live rows are never evicted to meet this cap.
    pub max_retired_processes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            jit_is_critical: false,
            detect_stack_pivot: true,
            audit_sensitive: false,
            trusted_regions: Vec::new(),
            enforcement: Enforcement::Observe,
            correlation_window: 64,
            max_retired_processes: 128,
        }
    }
}

impl Config {
    /// True when `addr` sits inside an operator-trusted JIT region.
    pub fn is_trusted(&self, addr: u64) -> bool {
        self.trusted_regions
            .iter()
            .any(|&(start, end)| addr >= start && addr < end)
    }

    /// Exempt only if the effective page-rounded span is entirely trusted.
    /// Ordinary x86-64 Linux mappings use 4096-byte base pages. This does not
    /// infer existing hugetlb mapping sizes from maps metadata. Empty requests
    /// and overflow receive no exemption; unaligned starts are rounded down.
    pub fn is_trusted_range(&self, addr: u64, len: u64) -> bool {
        const PAGE_MASK: u64 = 4095;
        if len == 0 {
            return false;
        }
        let Some(end) = addr
            .checked_add(len)
            .and_then(|end| end.checked_add(PAGE_MASK))
        else {
            return false;
        };
        let first_page = addr & !PAGE_MASK;
        let limit = end & !PAGE_MASK;
        self.trusted_regions
            .iter()
            .any(|&(start, end)| first_page >= start && limit <= end)
    }
}

/// Register/argument snapshot at a syscall-entry stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallCtx {
    pub pid: i32,
    pub nr: u64,
    pub rip: u64,
    pub rsp: u64,
    /// Syscall arguments in the x86-64 ABI order: rdi, rsi, rdx, r10, r8, r9.
    pub args: [u64; 6],
}

/// Evidence is bounded by syscall progress and monotonic time, not wall-clock
/// timestamps. It remains a coarse observation, not a causal taint graph.
#[derive(Debug, Clone, Copy)]
struct Evidence {
    sequence: u64,
    at: Instant,
}

impl Evidence {
    fn recent(self, sequence: u64, now: Instant, budget: u64) -> bool {
        sequence.saturating_sub(self.sequence) <= budget
            && now
                .checked_duration_since(self.at)
                .is_some_and(|age| age <= Duration::from_secs(30))
    }
}

#[derive(Debug, Clone, Copy)]
struct MemorySpan {
    start: u64,
    end: u64,
}

impl MemorySpan {
    fn new(start: u64, len: u64) -> Option<Self> {
        if len == 0 {
            return None;
        }
        let end = start.checked_add(len)?.checked_add(4095)? & !4095;
        Some(Self {
            start: start & !4095,
            end,
        })
    }
    fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

#[derive(Debug, Clone, Copy)]
struct MemoryEvidence {
    span: MemorySpan,
    timing: Evidence,
}

#[derive(Debug, Default, Clone)]
struct ChainState {
    sequence: u64,
    net_input: Option<Evidence>,
    wx_staged: Option<MemoryEvidence>,
    stack_pivot: Option<Evidence>,
    chain_reported: bool,
}

impl ChainState {
    fn expire(&mut self, now: Instant, budget: u64) {
        if self
            .net_input
            .is_some_and(|e| !e.recent(self.sequence, now, budget))
        {
            self.net_input = None;
        }
        if self
            .wx_staged
            .is_some_and(|e| !e.timing.recent(self.sequence, now, budget))
        {
            self.wx_staged = None;
        }
        if self
            .stack_pivot
            .is_some_and(|e| !e.recent(self.sequence, now, budget))
        {
            self.stack_pivot = None;
        }
    }
    fn staging_count(&self, origin: u64) -> u32 {
        self.net_input.is_some() as u32
            + self.wx_staged.is_some_and(|e| e.span.contains(origin)) as u32
            + self.stack_pivot.is_some() as u32
    }
}

#[derive(Debug)]
struct PendingCompletion {
    proc_key: i32,
    ctx: SyscallCtx,
    input: bool,
    wx_span: Option<MemorySpan>,
}

pub struct Detector {
    cfg: Config,
    /// One accumulating chain per traced address space (keyed by thread-group
    /// id). Threads of a process share memory, so an exploit staged in one
    /// thread and fired from another is a single chain; separate processes get
    /// separate chains so their evidence never bleeds together.
    chains: HashMap<i32, ChainState>,
    /// At most one completion candidate per active TID, removed at exit/death.
    pending: HashMap<i32, PendingCompletion>,
    /// Exact kernel-registered alternate-stack extent per observed active TID.
    alt_stacks: HashMap<i32, (i32, MemorySpan)>,
}

impl Detector {
    pub fn new(cfg: Config) -> Self {
        Detector {
            cfg,
            chains: HashMap::new(),
            pending: HashMap::new(),
            alt_stacks: HashMap::new(),
        }
    }

    /// Inspect one syscall and return any events it triggers. `proc_key`
    /// identifies the address space the syscall belongs to (the tracee's
    /// thread-group id); all threads sharing memory pass the same key so their
    /// evidence correlates into one exploitation chain.
    pub fn on_syscall(&mut self, proc_key: i32, ctx: &SyscallCtx, map: &MemoryMap) -> Vec<Event> {
        self.on_syscall_at(proc_key, ctx, map, Instant::now())
    }

    fn on_syscall_at(
        &mut self,
        proc_key: i32,
        ctx: &SyscallCtx,
        map: &MemoryMap,
        now: Instant,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        self.pending.remove(&ctx.pid);
        let mut requested_wx_span = None;
        // Resolve display names only when a rule emits an event; unknown
        // syscall names allocate, so quiet hot-path calls should not format them.
        // Disjoint field borrows: `cfg` is read-only, `chain` is the mutable
        // per-process accumulator for this address space.
        let enrolled_stack = self
            .alt_stacks
            .get(&ctx.pid)
            .is_some_and(|(group, span)| *group == proc_key && span.contains(ctx.rsp));
        let cfg = &self.cfg;
        let chain = self.chains.entry(proc_key).or_default();
        chain.sequence = chain.sequence.saturating_add(1);
        chain.expire(now, cfg.correlation_window);

        // Breadcrumb: first-stage payloads usually arrive over a read/recv.
        // A bare `read` is only interesting when it comes from stdin (fd 0);
        // reads on other fds are just the loader/program doing routine I/O.
        // `recvfrom`/`recvmsg` operate on sockets, so they always count.
        let is_external_input = syscalls::is_network_input(ctx.nr)
            && match ctx.nr {
                0 | 19 => ctx.args[0] == 0, // read/readv from stdin
                _ => true,                  // recvfrom/recvmsg
            };

        // 1. Provenance of the syscall instruction itself. A trusted JIT
        //    region is exempt: the operator has vouched that runtime-generated
        //    code lives there, so a syscall from it is not evidence of injection.
        let origin = classify_rip(map, ctx.rip);
        let confirmed_origin = origin.is_anomalous()
            && !matches!(origin, Origin::Unmapped | Origin::NonExec)
            && (origin != Origin::AnonExec || cfg.jit_is_critical);
        let trusted_origin = cfg.is_trusted(ctx.rip);
        if origin.is_anomalous() && !trusted_origin {
            let sysname = syscalls::name(ctx.nr);
            let sensitive = syscalls::is_sensitive(ctx.nr);
            let severity = foreign_severity(cfg, origin, sensitive);
            let label = map
                .region_at(ctx.rip)
                .map(|r| r.label())
                .unwrap_or_else(|| "unmapped".into());
            let detail = if matches!(origin, Origin::Unmapped | Origin::NonExec) {
                format!("syscall `{sysname}` has {} provenance — memory-map uncertainty, not confirmed injection", origin.as_str())
            } else if origin == Origin::AnonExec && !cfg.jit_is_critical {
                format!("syscall `{sysname}` issued from anonymous executable memory — JIT or injected code")
            } else if sensitive {
                format!(
                    "sensitive syscall `{sysname}` issued from {} memory — possible injected code activity",
                    origin.as_str()
                )
            } else {
                format!(
                    "syscall `{sysname}` issued from {} memory (anomalous executable origin)",
                    origin.as_str()
                )
            };
            events.push(Event::now(
                ctx.pid,
                severity,
                Kind::ForeignOriginSyscall,
                sysname.clone(),
                ctx.rip,
                ctx.rsp,
                label,
                detail,
            ));
        } else if cfg.audit_sensitive && syscalls::is_sensitive(ctx.nr) {
            let sysname = syscalls::name(ctx.nr);
            let label = map
                .region_at(ctx.rip)
                .map(|r| r.label())
                .unwrap_or_else(|| "?".into());
            events.push(Event::now(
                ctx.pid,
                Severity::Info,
                Kind::SensitiveCall,
                sysname.clone(),
                ctx.rip,
                ctx.rsp,
                label,
                format!("sensitive syscall `{sysname}` from legitimate code"),
            ));
        }

        // 2. Stack pivot: the stack pointer is somewhere no real stack lives.
        if cfg.detect_stack_pivot && !enrolled_stack {
            let ss = classify_rsp(map, ctx.rsp);
            if ss.is_anomalous() && ss != StackState::Unmapped {
                let sysname = syscalls::name(ctx.nr);
                chain.stack_pivot = Some(Evidence {
                    sequence: chain.sequence,
                    at: now,
                });
                let label = map
                    .region_at(ctx.rsp)
                    .map(|r| r.label())
                    .unwrap_or_else(|| "?".into());
                events.push(Event::now(
                    ctx.pid,
                    Severity::High,
                    Kind::StackPivot,
                    sysname.clone(),
                    ctx.rip,
                    ctx.rsp,
                    label,
                    format!(
                        "stack pointer pivoted into {} at syscall time (ROP indicator)",
                        ss.as_str()
                    ),
                ));
            }
        }

        // 3. W^X: pages requested/made writable-and-executable, or flipped
        //    from writable to executable (payload staging). A page inside a
        //    trusted JIT region is exempt — JIT engines legitimately map
        //    writable-then-executable code there.
        if syscalls::is_mmap(ctx.nr) || syscalls::is_mprotect(ctx.nr) {
            let prot = Prot::from_raw(ctx.args[2]);
            let addr = ctx.args[0];
            // A plain mmap address is merely a hint; only fixed placement
            // establishes which span the request would affect.
            // MAP_HUGETLB has a larger, possibly selected page size; without
            // that metadata a base-page trust calculation cannot exempt it.
            let fixed_target = syscalls::is_mprotect(ctx.nr)
                || (ctx.args[3] & (libc::MAP_FIXED | libc::MAP_FIXED_NOREPLACE) as u64 != 0
                    && ctx.args[3] & libc::MAP_HUGETLB as u64 == 0);
            if fixed_target && cfg.is_trusted_range(addr, ctx.args[1]) {
                // Operator-vouched JIT page; not payload staging.
            } else if prot.is_wx() {
                let sysname = syscalls::name(ctx.nr);
                requested_wx_span = MemorySpan::new(addr, ctx.args[1]);
                events.push(Event::now(
                    ctx.pid,
                    Severity::High,
                    Kind::WxViolation,
                    sysname.clone(),
                    ctx.rip,
                    ctx.rsp,
                    format!("{:#x}", addr),
                    format!("`{sysname}` requests writable+executable memory — classic shellcode staging"),
                ));
            } else if syscalls::is_mprotect(ctx.nr) && prot.exec {
                // Adding execute to a page that is currently writable is the
                // W->X flip an attacker performs after writing a payload.
                let writable = addr.checked_add(ctx.args[1]).and_then(|end| {
                    map.regions()
                        .iter()
                        .find(|r| r.write && r.start < end && r.end > addr)
                });
                if ctx.args[1] != 0 {
                    if let Some(region) = writable {
                        let sysname = syscalls::name(ctx.nr);
                        requested_wx_span = MemorySpan::new(addr, ctx.args[1]);
                        events.push(Event::now(
                            ctx.pid,
                            if cfg.jit_is_critical { Severity::High } else { Severity::Warn },
                            Kind::WxTransition,
                            sysname.clone(),
                            ctx.rip,
                            ctx.rsp,
                            region.label(),
                            "request to make writable memory executable — possible payload staging (W->X)"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // 4. Correlate. A sensitive syscall from foreign code, combined with
        //    any prior staging milestone, is an exploitation chain — one high
        //    confidence verdict rather than a scatter of primitives.
        if !chain.chain_reported
            && syscalls::is_sensitive(ctx.nr)
            && confirmed_origin
            && !trusted_origin
            && chain.staging_count(ctx.rip) >= 1
        {
            chain.chain_reported = true;
            let narrative = chain_narrative(chain, ctx.rip);
            let sysname = syscalls::name(ctx.nr);
            events.push(Event::now(
                ctx.pid,
                Severity::Critical,
                Kind::ExploitationChain,
                sysname,
                ctx.rip,
                ctx.rsp,
                "correlated",
                narrative,
            ));
        }

        if is_external_input || requested_wx_span.is_some() {
            self.pending.insert(
                ctx.pid,
                PendingCompletion {
                    proc_key,
                    ctx: *ctx,
                    input: is_external_input,
                    wx_span: requested_wx_span,
                },
            );
        }
        events
    }

    /// Record only confirmed completion outcomes. Primitive request alerts stay
    /// at entry; failed/blocked calls and empty input cannot stage a chain.
    pub fn on_syscall_exit(&mut self, proc_key: i32, ctx: &SyscallCtx, result: i64) {
        let Some(pending) = self.pending.remove(&ctx.pid) else {
            return;
        };
        if pending.proc_key != proc_key || pending.ctx != *ctx || result < 0 {
            return;
        }
        let chain = self.chains.entry(proc_key).or_default();
        let timing = Evidence {
            sequence: chain.sequence,
            at: Instant::now(),
        };
        if pending.input && result > 0 {
            chain.net_input = Some(timing);
        }
        if let Some(requested) = pending.wx_span {
            let span = if syscalls::is_mmap(ctx.nr) {
                MemorySpan::new(result as u64, ctx.args[1])
            } else if result == 0 {
                Some(requested)
            } else {
                None
            };
            if let Some(span) = span {
                let huge = syscalls::is_mmap(ctx.nr) && ctx.args[3] & libc::MAP_HUGETLB as u64 != 0;
                if huge || !self.cfg.is_trusted_range(span.start, span.end - span.start) {
                    chain.wx_staged = Some(MemoryEvidence { span, timing });
                }
            }
        }
    }

    /// Coverage loss invalidates correlation evidence, but not independently
    /// captured kernel stack registration.
    pub fn clear_evidence(&mut self, proc_key: i32) {
        self.chains.remove(&proc_key);
        self.pending
            .retain(|_, pending| pending.proc_key != proc_key);
    }

    /// Called only after a successful native sigaltstack completion. Enrollment
    /// exempts RSP within this exact extent, never instruction origin or all heap.
    pub fn register_altstack(&mut self, pid: i32, proc_key: i32, start: u64, len: u64, flags: u64) {
        // A successful replacement supersedes old metadata even when the new
        // extent is disabled, empty, or cannot be represented without overflow.
        self.alt_stacks.remove(&pid);
        if flags & libc::SS_DISABLE as u64 == 0 && len > 0 {
            if let Some(end) = start.checked_add(len) {
                self.alt_stacks
                    .insert(pid, (proc_key, MemorySpan { start, end }));
            }
        }
    }

    pub fn retire_thread(&mut self, pid: i32) {
        self.pending.remove(&pid);
        self.alt_stacks.remove(&pid);
    }

    /// Forget all accumulated evidence for an address space whose last thread
    /// has exited. Without this the per-process chain map grows for the life of
    /// the trace — a slow leak when following a long-lived target that forks or
    /// spawns many short-lived children. A recycled key simply starts fresh.
    pub fn retire(&mut self, proc_key: i32) {
        self.clear_evidence(proc_key);
        self.alt_stacks.retain(|_, (group, _)| *group != proc_key);
    }
}

fn foreign_severity(cfg: &Config, origin: Origin, sensitive: bool) -> Severity {
    if matches!(origin, Origin::Unmapped | Origin::NonExec)
        || (origin == Origin::AnonExec && !cfg.jit_is_critical)
    {
        return Severity::Warn;
    }
    if sensitive {
        return Severity::Critical;
    }
    match origin {
        Origin::AnonExec => {
            if cfg.jit_is_critical {
                Severity::High
            } else {
                Severity::Warn
            }
        }
        _ => Severity::High,
    }
}

fn chain_narrative(chain: &ChainState, origin: u64) -> String {
    let mut steps = Vec::new();
    if chain.net_input.is_some() {
        steps.push("positive input syscall completed");
    }
    if chain.wx_staged.is_some_and(|e| e.span.contains(origin)) {
        steps.push("executable-memory staging completed in the observed address span");
    }
    if chain.stack_pivot.is_some() {
        steps.push("stack pivot");
    }
    steps.push("sensitive syscall from anomalous executable memory");
    format!("EXPLOITATION CHAIN: {}", steps.join(" -> "))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Map with the binary, libc, an RWX page, a writable-only anon page, heap
    // and stack.
    const MAP: &str = "\
55f000001000-55f000002000 r-xp 00000000 08:01 1 /usr/bin/app
55f000003000-55f000010000 rw-p 00000000 00:00 0 [heap]
7f0000000000-7f0000021000 r-xp 00000000 08:01 2 /usr/lib/libc.so.6
7f0000030000-7f0000031000 rwxp 00000000 00:00 0
7f0000050000-7f0000051000 rw-p 00000000 00:00 0
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]";

    fn map() -> MemoryMap {
        MemoryMap::parse(MAP)
    }

    fn ctx(nr: u64, rip: u64, rsp: u64, args: [u64; 6]) -> SyscallCtx {
        SyscallCtx {
            pid: 1,
            nr,
            rip,
            rsp,
            args,
        }
    }

    #[test]
    fn failed_or_empty_calls_do_not_become_chain_milestones() {
        let m = MemoryMap::parse(&format!("{MAP}\n7f0000060000-7f0000061000 r-xp 0 00:00 0"));
        for (nr, args, result) in [
            (
                10,
                [0x7f0000060000, 0x1000, 7, 0, 0, 0],
                -(libc::ENOMEM as i64),
            ),
            (45, [u64::MAX, 0, 32, 0, 0, 0], -(libc::EBADF as i64)),
            (0, [0; 6], 0),
        ] {
            let mut detector = Detector::new(Config {
                jit_is_critical: true,
                ..Config::default()
            });
            let request = ctx(nr, 0x7f0000000500, 0x7ffd00010000, args);
            detector.on_syscall(1, &request, &m);
            detector.on_syscall_exit(1, &request, result);
            let events =
                detector.on_syscall(1, &ctx(41, 0x7f0000060010, 0x7ffd00010000, [0; 6]), &m);
            assert!(
                !events
                    .iter()
                    .any(|event| event.kind == Kind::ExploitationChain),
                "{events:?}"
            );
        }
    }

    #[test]
    fn completion_evidence_is_recent_and_allocation_scoped() {
        let m = MemoryMap::parse(&format!("{MAP}\n7f0000060000-7f0000061000 r-xp 0 00:00 0"));
        let mut detector = Detector::new(Config {
            jit_is_critical: true,
            ..Config::default()
        });
        let input = ctx(0, 0x7f0000000500, 0x7ffd00010000, [0; 6]);
        detector.on_syscall(1, &input, &m);
        detector.on_syscall_exit(1, &input, 12);
        for _ in 0..100 {
            detector.on_syscall(1, &ctx(39, 0x7f0000000500, 0x7ffd00010000, [0; 6]), &m);
        }
        let events = detector.on_syscall(1, &ctx(41, 0x7f0000060010, 0x7ffd00010000, [0; 6]), &m);
        assert!(!events
            .iter()
            .any(|event| event.kind == Kind::ExploitationChain));

        let mut detector = Detector::new(Config {
            jit_is_critical: true,
            ..Config::default()
        });
        let stage = ctx(
            10,
            0x7f0000000500,
            0x7ffd00010000,
            [0x7f0000050000, 4096, 7, 0, 0, 0],
        );
        detector.on_syscall(1, &stage, &m);
        detector.on_syscall_exit(1, &stage, 0);
        let events = detector.on_syscall(1, &ctx(41, 0x7f0000060010, 0x7ffd00010000, [0; 6]), &m);
        assert!(
            !events
                .iter()
                .any(|event| event.kind == Kind::ExploitationChain),
            "unrelated executable allocation inherited staging"
        );
        let changed = MemoryMap::parse(&MAP.replace(
            "7f0000050000-7f0000051000 rw-p",
            "7f0000050000-7f0000051000 rwxp",
        ));
        let events = detector.on_syscall(
            1,
            &ctx(41, 0x7f0000050010, 0x7ffd00010000, [0; 6]),
            &changed,
        );
        assert!(events
            .iter()
            .any(|event| event.kind == Kind::ExploitationChain));
    }

    #[test]
    fn evidence_expires_with_idle_monotonic_time_without_sleeping() {
        let mut detector = Detector::new(Config {
            jit_is_critical: true,
            ..Config::default()
        });
        let m = MemoryMap::parse(&format!("{MAP}\n7f0000060000-7f0000061000 r-xp 0 00:00 0"));
        let input = ctx(0, 0x7f0000000500, 0x7ffd00010000, [0; 6]);
        detector.on_syscall(1, &input, &m);
        detector.on_syscall_exit(1, &input, 1);
        let events = detector.on_syscall_at(
            1,
            &ctx(41, 0x7f0000060010, 0x7ffd00010000, [0; 6]),
            &m,
            std::time::Instant::now() + std::time::Duration::from_secs(31),
        );
        assert!(!events
            .iter()
            .any(|event| event.kind == Kind::ExploitationChain));
    }

    #[test]
    fn trusted_origin_does_not_inherit_foreign_chain() {
        let m = MemoryMap::parse(&format!("{MAP}\n7f0000060000-7f0000061000 r-xp 0 00:00 0"));
        let cfg = Config {
            trusted_regions: vec![(0x7f0000060000, 0x7f0000061000)],
            ..Config::default()
        };
        let mut d = Detector::new(cfg);
        d.on_syscall(1, &ctx(0, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &m);
        let ev = d.on_syscall(1, &ctx(59, 0x7f0000060010, 0x7ffd00010000, [0; 6]), &m);
        assert!(
            ev.is_empty(),
            "trusted current origin must not inherit a chain: {ev:?}"
        );
    }

    #[test]
    fn trust_covers_effective_page_rounded_memory_span() {
        let cfg = Config {
            trusted_regions: vec![(0x1000, 0x1001)],
            ..Config::default()
        };
        assert!(!cfg.is_trusted_range(0x1000, 1));
        let mut d = Detector::new(cfg);
        let ev = d.on_syscall(
            1,
            &ctx(10, 0x7f0000000500, 0x7ffd00010000, [0x1000, 1, 7, 0, 0, 0]),
            &map(),
        );
        assert!(ev.iter().any(|e| e.kind == Kind::WxViolation));
        let full = Config {
            trusted_regions: vec![(0x1000, 0x2000)],
            ..Config::default()
        };
        assert!(full.is_trusted_range(0x1000, 1));
        assert!(!full.is_trusted_range(0x1000, 0x1001));
        let top = Config {
            trusted_regions: vec![(u64::MAX - 0xfff, u64::MAX)],
            ..Config::default()
        };
        assert!(!top.is_trusted_range(u64::MAX - 0xfff, 1));
    }

    #[test]
    fn trusted_ranges_reject_overflow_and_empty_spans() {
        let cfg = Config {
            trusted_regions: vec![(0x1000, 0x2000), (u64::MAX - 0x1000, u64::MAX)],
            ..Config::default()
        };
        assert!(cfg.is_trusted_range(0x1000, 0x1000));
        assert!(!cfg.is_trusted_range(0x1000, 0));
        assert!(!cfg.is_trusted_range(0x1000, 0x1001));
        assert!(!cfg.is_trusted_range(u64::MAX - 1, 2));
    }

    #[test]
    fn hugetlb_fixed_mmap_does_not_receive_base_page_trust_exemption() {
        let mut d = Detector::new(Config {
            trusted_regions: vec![(0x1000, 0x2000)],
            ..Config::default()
        });
        let ev = d.on_syscall(
            1,
            &ctx(
                9,
                0x7f0000000500,
                0x7ffd00010000,
                [
                    0x1000,
                    1,
                    7,
                    (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_HUGETLB) as u64,
                    0,
                    0,
                ],
            ),
            &map(),
        );
        assert!(ev.iter().any(|e| e.kind == Kind::WxViolation));
    }

    #[test]
    fn mmap_hint_does_not_establish_trusted_mapping() {
        let mut d = Detector::new(Config {
            trusted_regions: vec![(0x1000, 0x2000)],
            ..Config::default()
        });
        let ev = d.on_syscall(
            1,
            &ctx(
                9,
                0x7f0000000500,
                0x7ffd00010000,
                [0x1000, 0x1000, 7, libc::MAP_PRIVATE as u64, 0, 0],
            ),
            &map(),
        );
        assert!(ev.iter().any(|e| e.kind == Kind::WxViolation));
        let ev = d.on_syscall(
            1,
            &ctx(
                9,
                0x7f0000000500,
                0x7ffd00010000,
                [
                    0x1000,
                    0x1000,
                    7,
                    (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
                    0,
                    0,
                ],
            ),
            &map(),
        );
        assert!(ev.is_empty());
    }

    #[test]
    fn mprotect_detects_writable_later_region() {
        let m = MemoryMap::parse(&format!(
            "{MAP}\n1000-2000 r-xp 0 00:00 0\n2000-3000 rw-p 0 00:00 0"
        ));
        let mut d = Detector::new(Config::default());
        let ev = d.on_syscall(
            1,
            &ctx(
                10,
                0x7f0000000500,
                0x7ffd00010000,
                [0x1000, 0x2000, 5, 0, 0, 0],
            ),
            &m,
        );
        assert!(ev.iter().any(|e| e.kind == Kind::WxTransition));
    }

    #[test]
    fn trusted_start_does_not_exempt_untrusted_tail() {
        let cfg = Config {
            trusted_regions: vec![(0x7f0000050000, 0x7f0000051000)],
            ..Config::default()
        };
        let mut d = Detector::new(cfg);
        let ev = d.on_syscall(
            1,
            &ctx(
                10,
                0x7f0000000500,
                0x7ffd00010000,
                [0x7f0000050000, 0x2000, 7, 0, 0, 0],
            ),
            &map(),
        );
        assert!(ev.iter().any(|e| e.kind == Kind::WxViolation));
    }

    #[test]
    fn rx_jit_sensitive_with_input_is_not_confirmed_injection_by_default() {
        let m = MemoryMap::parse(&format!("{MAP}\n7f0000060000-7f0000061000 r-xp 0 00:00 0"));
        let mut d = Detector::new(Config::default());
        d.on_syscall(1, &ctx(0, 0x7f0000000500, 0x7ffd00010000, [0; 6]), &m);
        d.on_syscall(
            1,
            &ctx(
                10,
                0x7f0000000500,
                0x7ffd00010000,
                [0x7f0000050000, 0x1000, 5, 0, 0, 0],
            ),
            &m,
        );
        let ev = d.on_syscall(1, &ctx(41, 0x7f0000060010, 0x7ffd00010000, [0; 6]), &m);
        assert!(ev.iter().any(|e| e.kind == Kind::ForeignOriginSyscall));
        assert!(!ev.iter().any(|e| e.severity == Severity::Critical));
        let mut strict = Detector::new(Config {
            jit_is_critical: true,
            ..Config::default()
        });
        let ev = strict.on_syscall(1, &ctx(41, 0x7f0000060010, 0x7ffd00010000, [0; 6]), &m);
        assert!(ev.iter().any(|e| e.severity == Severity::Critical));
    }

    #[test]
    fn uncertain_origins_never_become_critical() {
        for rip in [0xdead0000, 0x7f0000050010] {
            let mut d = Detector::new(Config {
                jit_is_critical: true,
                ..Config::default()
            });
            d.on_syscall(1, &ctx(0, 0x7f0000000500, 0x7ffd00010000, [0; 6]), &map());
            let ev = d.on_syscall(1, &ctx(59, rip, 0x7ffd00010000, [0; 6]), &map());
            assert!(
                !ev.iter().any(|e| e.severity == Severity::Critical),
                "{ev:?}"
            );
        }
    }

    #[test]
    fn legit_syscall_from_libc_is_silent() {
        let mut d = Detector::new(Config::default());
        let ev = d.on_syscall(1, &ctx(1, 0x7f0000000500, 0x7ffd00010000, [0; 6]), &map());
        assert!(ev.is_empty());
    }

    #[test]
    fn syscall_from_rwx_page_is_flagged() {
        let mut d = Detector::new(Config::default());
        let ev = d.on_syscall(1, &ctx(1, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, Kind::ForeignOriginSyscall);
        assert_eq!(ev[0].severity, Severity::High);
    }

    #[test]
    fn execve_from_injected_code_is_critical() {
        let mut d = Detector::new(Config::default());
        // execve (59) from the RWX page.
        let ev = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(ev
            .iter()
            .any(|e| e.severity == Severity::Critical && e.kind == Kind::ForeignOriginSyscall));
    }

    #[test]
    fn pkey_mprotect_checks_wx_and_writable_transition() {
        for (prot, expected) in [(7, Kind::WxViolation), (5, Kind::WxTransition)] {
            let mut d = Detector::new(Config::default());
            let ev = d.on_syscall(
                1,
                &ctx(
                    329,
                    0x7f0000000500,
                    0x7ffd00010000,
                    [0x7f0000050000, 0x1000, prot, 0, 0, 0],
                ),
                &map(),
            );
            assert!(ev
                .iter()
                .any(|e| e.kind == expected && e.syscall == "pkey_mprotect"));
        }
    }

    #[test]
    fn wx_transition_policy_distinguishes_jit_from_direct_rwx() {
        for strict in [false, true] {
            for nr in [10, 329] {
                let mut d = Detector::new(Config {
                    jit_is_critical: strict,
                    ..Config::default()
                });
                let ev = d.on_syscall(
                    1,
                    &ctx(
                        nr,
                        0x7f0000000500,
                        0x7ffd00010000,
                        [0x7f0000050000, 0x1000, 5, 0, 0, 0],
                    ),
                    &map(),
                );
                assert!(ev.iter().any(|e| e.kind == Kind::WxTransition
                    && e.severity
                        == if strict {
                            Severity::High
                        } else {
                            Severity::Warn
                        }));
                let ev = d.on_syscall(
                    1,
                    &ctx(
                        nr,
                        0x7f0000000500,
                        0x7ffd00010000,
                        [0x7f0000050000, 0x1000, 7, 0, 0, 0],
                    ),
                    &map(),
                );
                assert!(ev
                    .iter()
                    .any(|e| e.kind == Kind::WxViolation && e.severity == Severity::High));
            }
        }
    }

    #[test]
    fn mprotect_rwx_is_wx_violation() {
        let mut d = Detector::new(Config::default());
        let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        // Called from legit code, so the only event is the W^X violation.
        let ev = d.on_syscall(
            1,
            &ctx(
                10,
                0x7f0000000500,
                0x7ffd00010000,
                [0x7f0000050000, 0x1000, prot, 0, 0, 0],
            ),
            &map(),
        );
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, Kind::WxViolation);
    }

    #[test]
    fn mprotect_wx_transition_on_writable_page() {
        let mut d = Detector::new(Config::default());
        let prot = (libc::PROT_READ | libc::PROT_EXEC) as u64; // exec only, but page is writable
        let ev = d.on_syscall(
            1,
            &ctx(
                10,
                0x7f0000000500,
                0x7ffd00010000,
                [0x7f0000050000, 0x1000, prot, 0, 0, 0],
            ),
            &map(),
        );
        assert!(ev.iter().any(|e| e.kind == Kind::WxTransition));
    }

    #[test]
    fn enrolled_stack_is_thread_local_rsp_only_and_disableable() {
        let mut detector = Detector::new(Config::default());
        detector.register_altstack(1, 1, 0x55f000002000, 0x4000, 0);
        let normal = ctx(1, 0x7f0000000500, 0x55f000004000, [0; 6]);
        assert!(!detector
            .on_syscall(1, &normal, &map())
            .iter()
            .any(|e| e.kind == Kind::StackPivot));
        let mut other = normal;
        other.pid = 2;
        assert!(detector
            .on_syscall(1, &other, &map())
            .iter()
            .any(|e| e.kind == Kind::StackPivot));
        let outside = ctx(1, 0x7f0000000500, 0x55f000008000, [0; 6]);
        assert!(detector
            .on_syscall(1, &outside, &map())
            .iter()
            .any(|e| e.kind == Kind::StackPivot));
        let injected = ctx(59, 0x7f0000030010, 0x55f000004000, [0; 6]);
        assert!(detector
            .on_syscall(1, &injected, &map())
            .iter()
            .any(|e| e.kind == Kind::ForeignOriginSyscall));
        detector.register_altstack(1, 1, 0, 0, libc::SS_DISABLE as u64);
        assert!(detector
            .on_syscall(1, &normal, &map())
            .iter()
            .any(|e| e.kind == Kind::StackPivot));
    }

    #[test]
    fn stack_registration_rejects_overflow_and_retires_with_lifecycle() {
        let mut detector = Detector::new(Config::default());
        let normal = ctx(1, 0x7f0000000500, 0x55f000004000, [0; 6]);
        detector.register_altstack(1, 1, 0x55f000002000, 0x4000, 0);
        detector.register_altstack(1, 1, u64::MAX - 32, 65536, 0);
        assert!(detector
            .on_syscall(1, &normal, &map())
            .iter()
            .any(|e| e.kind == Kind::StackPivot));
        detector.register_altstack(1, 1, 0x55f000002000, 0x4000, 0);
        detector.retire_thread(1);
        assert!(detector
            .on_syscall(1, &normal, &map())
            .iter()
            .any(|e| e.kind == Kind::StackPivot));
        detector.register_altstack(1, 1, 0x55f000002000, 0x4000, 0);
        detector.retire(1);
        assert!(detector
            .on_syscall(1, &normal, &map())
            .iter()
            .any(|e| e.kind == Kind::StackPivot));
    }

    #[test]
    fn stack_pivot_into_heap_detected() {
        let mut d = Detector::new(Config::default());
        let ev = d.on_syscall(1, &ctx(1, 0x7f0000000500, 0x55f000004000, [0; 6]), &map());
        assert!(ev.iter().any(|e| e.kind == Kind::StackPivot));
    }

    #[test]
    fn exploitation_chain_correlates() {
        let mut d = Detector::new(Config::default());
        // Step 1: successfully stage the same allocation later executing.
        let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        let request = ctx(
            10,
            0x7f0000000500,
            0x7ffd00010000,
            [0x7f0000030000, 0x1000, prot, 0, 0, 0],
        );
        d.on_syscall(1, &request, &map());
        d.on_syscall_exit(1, &request, 0);
        // Step 2: execve from the injected RWX page.
        let ev = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        let chain = ev
            .iter()
            .find(|event| event.kind == Kind::ExploitationChain)
            .unwrap();
        assert_eq!(chain.severity, Severity::Critical);
        assert!(chain.detail.contains("observed address span"));
        assert!(!chain.detail.contains("this allocation"));
    }

    #[test]
    fn trusted_region_suppresses_foreign_origin() {
        // The RWX page at 0x7f0000030000 would normally be flagged, but if the
        // operator vouches for it as a JIT region the syscall from it is silent.
        let cfg = Config {
            trusted_regions: vec![(0x7f0000030000, 0x7f0000031000)],
            ..Config::default()
        };
        let mut d = Detector::new(cfg);
        let ev = d.on_syscall(1, &ctx(1, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(
            ev.is_empty(),
            "trusted JIT region must not raise a foreign-origin event"
        );
    }

    #[test]
    fn trusted_region_suppresses_wx_and_chain() {
        // A JIT that maps RWX inside its trusted range, then runs a sensitive
        // syscall from it, must not escalate — no W^X event, no chain.
        let cfg = Config {
            trusted_regions: vec![(0x7f0000030000, 0x7f0000031000)],
            ..Config::default()
        };
        let mut d = Detector::new(cfg);
        let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        let staging = d.on_syscall(
            1,
            &ctx(
                10,
                0x7f0000000500,
                0x7ffd00010000,
                [0x7f0000030000, 0x1000, prot, 0, 0, 0],
            ),
            &map(),
        );
        assert!(
            staging.is_empty(),
            "W^X inside a trusted region must be exempt"
        );
        let firing = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(
            firing.is_empty(),
            "a sensitive syscall from a trusted region must not escalate, got: {firing:?}"
        );
    }

    #[test]
    fn untrusted_page_outside_range_still_flagged() {
        // A trusted range must not blanket-trust the whole address space: the
        // RWX page outside it is still caught.
        let cfg = Config {
            trusted_regions: vec![(0x400000, 0x401000)],
            ..Config::default()
        };
        let mut d = Detector::new(cfg);
        let ev = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(ev.iter().any(|e| e.kind == Kind::ForeignOriginSyscall));
    }

    #[test]
    fn chain_reported_only_once() {
        let mut d = Detector::new(Config::default());
        let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        let request = ctx(
            10,
            0x7f0000000500,
            0x7ffd00010000,
            [0x7f0000030000, 0x1000, prot, 0, 0, 0],
        );
        d.on_syscall(1, &request, &map());
        d.on_syscall_exit(1, &request, 0);
        let first = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        let second = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(first.iter().any(|e| e.kind == Kind::ExploitationChain));
        assert!(!second.iter().any(|e| e.kind == Kind::ExploitationChain));
    }

    #[test]
    fn retire_frees_chain_state_and_resets_correlation() {
        let mut d = Detector::new(Config::default());
        let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        // Stage a W^X milestone so the address space has accumulated evidence.
        d.on_syscall(
            1,
            &ctx(
                10,
                0x7f0000000500,
                0x7ffd00010000,
                [0x7f0000050000, 0x1000, prot, 0, 0, 0],
            ),
            &map(),
        );
        assert!(
            d.chains.contains_key(&1),
            "staging should record chain state"
        );

        d.retire(1);
        assert!(
            !d.chains.contains_key(&1),
            "retire must free the chain entry"
        );

        // A recycled key starts clean: a lone foreign-origin sensitive syscall
        // has no prior staging to correlate with, so no chain is reported.
        let ev = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(
            !ev.iter().any(|e| e.kind == Kind::ExploitationChain),
            "retired state must not resurrect an exploitation chain"
        );
    }
}
