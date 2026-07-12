//! End-to-end tests that drive real processes through the ptrace engine.
//!
//! These exercise the whole pipeline — fork/exec, syscall stops, live
//! `/proc/<pid>/maps` parsing, provenance classification, and correlation — on
//! the two helper binaries Cargo builds alongside the test:
//!   * `benign`        must produce zero detections (false-positive control)
//!   * `shellcode-sim` must be caught executing a syscall from injected memory
//!
//! They are `x86_64`-only and require an unrestricted `ptrace` (they self-skip
//! where that is not available, e.g. a hardened CI sandbox), so a constrained
//! environment degrades to "skipped" rather than "failed".

#![cfg(target_arch = "x86_64")]

use std::sync::{Arc, Mutex, OnceLock};

use wraith::detect::Config;
use wraith::event::{Event, Kind, Severity};
use wraith::tracer::{ProcStat, Reporter, Summary, Tracer};

/// The tracer reaps its whole process tree with `waitpid(-1)`, which is exactly
/// right for the real sensor (a dedicated process with a single tracer) but
/// means two engines cannot run concurrently inside one process. `cargo test`
/// runs these cases in parallel threads of one binary, so we serialize them
/// through this lock; each trace runs start-to-finish before the next begins.
fn trace_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Trace `bin` to completion, returning the collected events and the summary.
/// Returns `None` if the tracer could not even start (no ptrace permission).
fn trace(bin: &str, cfg: Config) -> Option<(Vec<Event>, Summary)> {
    let _guard = trace_lock().lock().unwrap_or_else(|e| e.into_inner());

    let collected = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&collected);

    let tracer = match Tracer::spawn(&[bin.to_string()], cfg) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skipping: could not spawn tracer ({e})");
            return None;
        }
    };
    let summary = tracer
        .run(|ev| sink.lock().unwrap().push(ev.clone()))
        .expect("trace run failed");

    let events = collected.lock().unwrap().clone();
    Some((events, summary))
}

#[test]
fn benign_program_produces_no_detections() {
    let bin = env!("CARGO_BIN_EXE_benign");
    let Some((events, summary)) = trace(bin, Config::default()) else {
        return; // ptrace unavailable — skip
    };

    assert!(summary.syscalls_seen > 0, "expected to observe some syscalls");
    assert!(
        events.is_empty(),
        "benign program should produce no events, got: {:?}",
        events.iter().map(|e| e.to_line(false)).collect::<Vec<_>>()
    );
    assert!(summary.max_severity.is_none());
    assert_eq!(summary.exit_code, Some(0));
}

#[test]
fn benign_program_clean_even_when_auditing_sensitive() {
    // With --audit-sensitive the benign socket() surfaces as an INFO
    // breadcrumb, but nothing should ever exceed INFO.
    let bin = env!("CARGO_BIN_EXE_benign");
    let cfg = Config { audit_sensitive: true, ..Config::default() };
    let Some((events, summary)) = trace(bin, cfg) else {
        return;
    };
    assert!(
        events.iter().all(|e| e.severity == Severity::Info),
        "benign audit run should only yield INFO events"
    );
    assert!(matches!(summary.max_severity, None | Some(Severity::Info)));
}

#[test]
fn shellcode_simulator_is_detected() {
    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let Some((events, summary)) = trace(bin, Config::default()) else {
        return;
    };

    // The mmap RWX staging must be caught.
    assert!(
        events.iter().any(|e| e.kind == Kind::WxViolation),
        "expected a W^X violation from the RWX mmap"
    );

    // The syscall executed from the injected page must be caught as a
    // CRITICAL foreign-origin sensitive syscall.
    let foreign_critical = events.iter().any(|e| {
        e.kind == Kind::ForeignOriginSyscall && e.severity == Severity::Critical
    });
    assert!(
        foreign_critical,
        "expected a CRITICAL foreign-origin syscall from injected code, got: {:?}",
        events.iter().map(|e| e.to_line(false)).collect::<Vec<_>>()
    );

    // And the correlator must escalate to an exploitation chain.
    assert!(
        events.iter().any(|e| e.kind == Kind::ExploitationChain),
        "expected an exploitation-chain verdict"
    );

    assert_eq!(summary.max_severity, Some(Severity::Critical));
}

#[test]
fn benign_threads_produce_no_detections() {
    // Several worker threads doing ordinary work must stay clean: following a
    // clone is not, by itself, a reason to fire. This is the false-positive
    // control for thread-following.
    let bin = env!("CARGO_BIN_EXE_benign-threads");
    let Some((events, summary)) = trace(bin, Config::default()) else {
        return; // ptrace unavailable — skip
    };

    assert!(summary.syscalls_seen > 0, "expected to observe some syscalls");
    assert!(
        events.is_empty(),
        "benign multithreaded program should produce no events, got: {:?}",
        events.iter().map(|e| e.to_line(false)).collect::<Vec<_>>()
    );
    assert!(summary.max_severity.is_none());
    assert_eq!(summary.exit_code, Some(0));
}

#[test]
fn worker_thread_exploit_is_detected() {
    // The payload here stages RWX and issues its syscall from a *worker thread*
    // born of a clone. A tracer that only watched the main thread would report
    // this process clean; catching it proves thread-following works end-to-end.
    let bin = env!("CARGO_BIN_EXE_mt-shellcode-sim");
    let Some((events, summary)) = trace(bin, Config::default()) else {
        return;
    };

    assert!(
        events.iter().any(|e| e.kind == Kind::WxViolation),
        "expected a W^X violation from the worker-thread RWX mmap"
    );

    let foreign_critical = events.iter().any(|e| {
        e.kind == Kind::ForeignOriginSyscall && e.severity == Severity::Critical
    });
    assert!(
        foreign_critical,
        "expected a CRITICAL foreign-origin syscall from the worker thread, got: {:?}",
        events.iter().map(|e| e.to_line(false)).collect::<Vec<_>>()
    );

    // Staging and firing happen on the worker but share the process address
    // space, so the per-process correlator must still tie them into one chain.
    assert!(
        events.iter().any(|e| e.kind == Kind::ExploitationChain),
        "expected an exploitation-chain verdict correlated across the thread"
    );

    assert_eq!(summary.max_severity, Some(Severity::Critical));
}

#[test]
fn detection_survives_min_severity_gate() {
    // Even filtering to CRITICAL-only, the payload is caught.
    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let Some((events, _)) = trace(bin, Config::default()) else {
        return;
    };
    let criticals: Vec<_> = events
        .iter()
        .filter(|e| e.severity >= Severity::Critical)
        .collect();
    assert!(!criticals.is_empty(), "at least one CRITICAL event expected");
}

#[test]
fn kill_enforcement_terminates_on_exploitation() {
    // In --kill mode the simulator must be SIGKILLed the moment it issues the
    // injected socket() — it never gets to exit cleanly on its own.
    use wraith::detect::Enforcement;
    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let cfg = Config { enforcement: Enforcement::Kill, ..Config::default() };
    let Some((events, summary)) = trace(bin, cfg) else {
        return; // ptrace unavailable — skip
    };

    assert!(
        events.iter().any(|e| e.kind == Kind::Killed),
        "expected a `killed` enforcement event, got: {:?}",
        events.iter().map(|e| e.to_line(false)).collect::<Vec<_>>()
    );
    // Killed by SIGKILL (9) before it could exit normally.
    assert_eq!(
        summary.term_signal,
        Some(libc::SIGKILL),
        "target should be terminated by SIGKILL, summary: {summary:?}"
    );
    assert_eq!(summary.exit_code, None, "a killed target has no clean exit code");
    assert_eq!(summary.max_severity, Some(Severity::Critical));
}

#[test]
fn block_enforcement_neutralizes_but_lets_process_live() {
    // In --block mode the injected socket() is cancelled (returns -ENOSYS), so
    // the simulator survives and exits cleanly, but a `blocked` event proves
    // the exploit syscall was neutralised.
    use wraith::detect::Enforcement;
    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let cfg = Config { enforcement: Enforcement::Block, ..Config::default() };
    let Some((events, summary)) = trace(bin, cfg) else {
        return;
    };

    assert!(
        events.iter().any(|e| e.kind == Kind::Blocked),
        "expected a `blocked` enforcement event, got: {:?}",
        events.iter().map(|e| e.to_line(false)).collect::<Vec<_>>()
    );
    // The exploitation was still detected...
    assert_eq!(summary.max_severity, Some(Severity::Critical));
    // ...but the process was allowed to finish rather than killed.
    assert_eq!(
        summary.exit_code,
        Some(0),
        "blocked target should run to a clean exit, summary: {summary:?}"
    );
    assert_eq!(summary.term_signal, None);
}

#[test]
fn observe_mode_never_intervenes() {
    // The default mode must not emit enforcement events — detection only.
    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let Some((events, _)) = trace(bin, Config::default()) else {
        return;
    };
    assert!(
        !events.iter().any(|e| matches!(e.kind, Kind::Blocked | Kind::Killed)),
        "observe mode must not enforce"
    );
}

/// A [`Reporter`] that records what the live-UI path would see, so we can test
/// the per-process stats plumbing that feeds the dashboard.
#[derive(Clone)]
struct Recorder {
    events: Arc<Mutex<usize>>,
    refreshes: Arc<Mutex<usize>>,
    snapshot: Arc<Mutex<Vec<ProcStat>>>,
}

impl Reporter for Recorder {
    fn event(&mut self, _ev: &Event) {
        *self.events.lock().unwrap() += 1;
    }
    fn wants_refresh(&self) -> bool {
        true
    }
    fn refresh(&mut self, stats: &[ProcStat], _summary: &Summary) {
        *self.refreshes.lock().unwrap() += 1;
        *self.snapshot.lock().unwrap() = stats.to_vec();
    }
}

#[test]
fn run_with_surfaces_per_process_stats() {
    // The live-UI path (run_with + a refreshing Reporter) must accumulate
    // per-process stats: the shellcode simulator should show syscalls, events,
    // and a CRITICAL max-severity for its single process.
    let _guard = trace_lock().lock().unwrap_or_else(|e| e.into_inner());

    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let rec = Recorder {
        events: Arc::new(Mutex::new(0)),
        refreshes: Arc::new(Mutex::new(0)),
        snapshot: Arc::new(Mutex::new(Vec::new())),
    };
    let tracer = match Tracer::spawn(&[bin.to_string()], Config::default()) {
        Ok(t) => t,
        Err(_) => return, // ptrace unavailable — skip
    };
    let summary = tracer.run_with(rec.clone()).expect("run_with failed");

    assert!(*rec.refreshes.lock().unwrap() > 0, "reporter was never refreshed");
    assert!(*rec.events.lock().unwrap() > 0, "reporter saw no events");

    let snap = rec.snapshot.lock().unwrap();
    assert_eq!(snap.len(), 1, "expected exactly one traced process");
    let p = &snap[0];
    assert!(p.syscalls > 0, "process should have observed syscalls");
    assert!(p.events > 0, "process should have accumulated events");
    assert_eq!(p.max_severity, Some(Severity::Critical));
    assert!(!p.alive, "process should be marked exited by the final frame");
    assert_eq!(summary.max_severity, Some(Severity::Critical));
}
