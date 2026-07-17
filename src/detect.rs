//! The detection engine.
//!
//! [`Detector`] is fed one [`SyscallCtx`] per syscall-entry stop plus the
//! current [`MemoryMap`], and returns any [`Event`]s that fire. It also runs a
//! lightweight correlator: individual primitives (a W^X page, a foreign-origin
//! syscall, a stack pivot) are suspicious on their own, but seen together in
//! one process they are an exploitation chain, and Wraith says so explicitly.

use std::collections::HashMap;

use crate::event::{Event, Kind, Severity};
use crate::maps::MemoryMap;
use crate::provenance::{classify_rip, classify_rsp, Origin, Prot, StackState};
use crate::syscalls;

/// What Wraith does when it is confident it has caught exploitation (a
/// CRITICAL event). Detection is always on; enforcement decides whether Wraith
/// also intervenes to stop the attack in its tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Enforcement {
    /// Detect and report only — never touch the tracee. The default, and the
    /// only mode that is guaranteed side-effect-free.
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
    /// Treat anonymous-executable origins as HIGH rather than WARN. Off by
    /// default because legitimate JIT engines (browsers, JVMs) run code from
    /// anonymous executable pages; on for hardened targets that never JIT.
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            jit_is_critical: false,
            detect_stack_pivot: true,
            audit_sensitive: false,
            trusted_regions: Vec::new(),
            enforcement: Enforcement::Observe,
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
}

/// Register/argument snapshot at a syscall-entry stop.
#[derive(Debug, Clone, Copy)]
pub struct SyscallCtx {
    pub pid: i32,
    pub nr: u64,
    pub rip: u64,
    pub rsp: u64,
    /// Syscall arguments in the x86-64 ABI order: rdi, rsi, rdx, r10, r8, r9.
    pub args: [u64; 6],
}

/// Accumulated evidence for a single traced process.
#[derive(Debug, Default, Clone)]
struct ChainState {
    net_input: bool,
    wx_staged: bool,
    foreign_origin: bool,
    stack_pivot: bool,
    chain_reported: bool,
}

impl ChainState {
    /// Distinct staging milestones observed so far.
    fn staging_count(&self) -> u32 {
        self.net_input as u32 + self.wx_staged as u32 + self.stack_pivot as u32
    }
}

pub struct Detector {
    cfg: Config,
    /// One accumulating chain per traced address space (keyed by thread-group
    /// id). Threads of a process share memory, so an exploit staged in one
    /// thread and fired from another is a single chain; separate processes get
    /// separate chains so their evidence never bleeds together.
    chains: HashMap<i32, ChainState>,
}

impl Detector {
    pub fn new(cfg: Config) -> Self {
        Detector {
            cfg,
            chains: HashMap::new(),
        }
    }

    /// Inspect one syscall and return any events it triggers. `proc_key`
    /// identifies the address space the syscall belongs to (the tracee's
    /// thread-group id); all threads sharing memory pass the same key so their
    /// evidence correlates into one exploitation chain.
    pub fn on_syscall(&mut self, proc_key: i32, ctx: &SyscallCtx, map: &MemoryMap) -> Vec<Event> {
        let mut events = Vec::new();
        let sysname = syscalls::name(ctx.nr);
        // Disjoint field borrows: `cfg` is read-only, `chain` is the mutable
        // per-process accumulator for this address space.
        let cfg = &self.cfg;
        let chain = self.chains.entry(proc_key).or_default();

        // Breadcrumb: first-stage payloads usually arrive over a read/recv.
        // A bare `read` is only interesting when it comes from stdin (fd 0);
        // reads on other fds are just the loader/program doing routine I/O.
        // `recvfrom`/`recvmsg` operate on sockets, so they always count.
        if syscalls::is_network_input(ctx.nr) {
            let is_external_input = match ctx.nr {
                0 | 19 => ctx.args[0] == 0, // read/readv from stdin
                _ => true,                  // recvfrom/recvmsg
            };
            if is_external_input {
                chain.net_input = true;
            }
        }

        // 1. Provenance of the syscall instruction itself. A trusted JIT
        //    region is exempt: the operator has vouched that runtime-generated
        //    code lives there, so a syscall from it is not evidence of injection.
        let origin = classify_rip(map, ctx.rip);
        if origin.is_anomalous() && !cfg.is_trusted(ctx.rip) {
            chain.foreign_origin = true;
            let sensitive = syscalls::is_sensitive(ctx.nr);
            let severity = foreign_severity(cfg, origin, sensitive);
            let label = map.region_at(ctx.rip).map(|r| r.label()).unwrap_or_else(|| "unmapped".into());
            let detail = if sensitive {
                format!(
                    "sensitive syscall `{sysname}` issued from {} memory — injected code is now acting",
                    origin.as_str()
                )
            } else {
                format!("syscall `{sysname}` issued from {} memory (not legitimate code)", origin.as_str())
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
            let label = map.region_at(ctx.rip).map(|r| r.label()).unwrap_or_else(|| "?".into());
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
        if cfg.detect_stack_pivot {
            let ss = classify_rsp(map, ctx.rsp);
            if ss.is_anomalous() && ss != StackState::Unmapped {
                chain.stack_pivot = true;
                let label = map.region_at(ctx.rsp).map(|r| r.label()).unwrap_or_else(|| "?".into());
                events.push(Event::now(
                    ctx.pid,
                    Severity::High,
                    Kind::StackPivot,
                    sysname.clone(),
                    ctx.rip,
                    ctx.rsp,
                    label,
                    format!("stack pointer pivoted into {} at syscall time (ROP indicator)", ss.as_str()),
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
            if cfg.is_trusted(addr) {
                // Operator-vouched JIT page; not payload staging.
            } else if prot.is_wx() {
                chain.wx_staged = true;
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
                if let Some(region) = map.region_at(addr) {
                    if region.write {
                        chain.wx_staged = true;
                        events.push(Event::now(
                            ctx.pid,
                            Severity::High,
                            Kind::WxTransition,
                            sysname.clone(),
                            ctx.rip,
                            ctx.rsp,
                            region.label(),
                            "writable page is being made executable — payload staging (W->X)".to_string(),
                        ));
                    }
                }
            }
        }

        // 4. Correlate. A sensitive syscall from foreign code, combined with
        //    any prior staging milestone, is an exploitation chain — one high
        //    confidence verdict rather than a scatter of primitives.
        if !chain.chain_reported
            && chain.foreign_origin
            && syscalls::is_sensitive(ctx.nr)
            && origin.is_anomalous()
            && chain.staging_count() >= 1
        {
            chain.chain_reported = true;
            let narrative = chain_narrative(chain);
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

        events
    }

    /// Forget all accumulated evidence for an address space whose last thread
    /// has exited. Without this the per-process chain map grows for the life of
    /// the trace — a slow leak when following a long-lived target that forks or
    /// spawns many short-lived children. A recycled key simply starts fresh.
    pub fn retire(&mut self, proc_key: i32) {
        self.chains.remove(&proc_key);
    }
}

fn foreign_severity(cfg: &Config, origin: Origin, sensitive: bool) -> Severity {
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

fn chain_narrative(chain: &ChainState) -> String {
    let mut steps = Vec::new();
    if chain.net_input {
        steps.push("attacker-controlled input received");
    }
    if chain.wx_staged {
        steps.push("executable payload staged (W^X)");
    }
    if chain.stack_pivot {
        steps.push("stack pivot");
    }
    steps.push("sensitive syscall from injected code");
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
        SyscallCtx { pid: 1, nr, rip, rsp, args }
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
        assert!(ev.iter().any(|e| e.severity == Severity::Critical
            && e.kind == Kind::ForeignOriginSyscall));
    }

    #[test]
    fn mprotect_rwx_is_wx_violation() {
        let mut d = Detector::new(Config::default());
        let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        // Called from legit code, so the only event is the W^X violation.
        let ev = d.on_syscall(1, &ctx(10, 0x7f0000000500, 0x7ffd00010000, [0x7f0000050000, 0x1000, prot, 0, 0, 0]), &map());
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, Kind::WxViolation);
    }

    #[test]
    fn mprotect_wx_transition_on_writable_page() {
        let mut d = Detector::new(Config::default());
        let prot = (libc::PROT_READ | libc::PROT_EXEC) as u64; // exec only, but page is writable
        let ev = d.on_syscall(1, &ctx(10, 0x7f0000000500, 0x7ffd00010000, [0x7f0000050000, 0x1000, prot, 0, 0, 0]), &map());
        assert!(ev.iter().any(|e| e.kind == Kind::WxTransition));
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
        // Step 1: stage RWX via mprotect (from legit code).
        let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        d.on_syscall(1, &ctx(10, 0x7f0000000500, 0x7ffd00010000, [0x7f0000050000, 0x1000, prot, 0, 0, 0]), &map());
        // Step 2: execve from the injected RWX page.
        let ev = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(ev.iter().any(|e| e.kind == Kind::ExploitationChain
            && e.severity == Severity::Critical));
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
        assert!(ev.is_empty(), "trusted JIT region must not raise a foreign-origin event");
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
            &ctx(10, 0x7f0000000500, 0x7ffd00010000, [0x7f0000030000, 0x1000, prot, 0, 0, 0]),
            &map(),
        );
        assert!(staging.is_empty(), "W^X inside a trusted region must be exempt");
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
        d.on_syscall(1, &ctx(10, 0x7f0000000500, 0x7ffd00010000, [0x7f0000050000, 0x1000, prot, 0, 0, 0]), &map());
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
        d.on_syscall(1, &ctx(10, 0x7f0000000500, 0x7ffd00010000, [0x7f0000050000, 0x1000, prot, 0, 0, 0]), &map());
        assert!(d.chains.contains_key(&1), "staging should record chain state");

        d.retire(1);
        assert!(!d.chains.contains_key(&1), "retire must free the chain entry");

        // A recycled key starts clean: a lone foreign-origin sensitive syscall
        // has no prior staging to correlate with, so no chain is reported.
        let ev = d.on_syscall(1, &ctx(59, 0x7f0000030010, 0x7ffd00010000, [0; 6]), &map());
        assert!(
            !ev.iter().any(|e| e.kind == Kind::ExploitationChain),
            "retired state must not resurrect an exploitation chain"
        );
    }
}
