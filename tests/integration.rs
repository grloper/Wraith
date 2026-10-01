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

/// Ordinary fixture lifecycles remain serialized. The backend scopes waits to
/// the creating OS thread, but unrelated children on that same thread are still
/// unsafe. Dedicated isolation regressions explicitly run separate creator /
/// driver pairs concurrently while holding this outer fixture lock.
fn trace_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Trace `bin` to completion, returning the collected events and the summary.
/// Returns `None` if the tracer could not even start (no ptrace permission).
fn trace(bin: &str, cfg: Config) -> Option<(Vec<Event>, Summary)> {
    trace_args(&[bin.to_string()], cfg)
}

fn unavailable(e: impl std::fmt::Display) {
    assert_ne!(
        std::env::var("WRAITH_REQUIRE_PTRACE").as_deref(),
        Ok("1"),
        "ptrace is required but tracer could not start: {e}"
    );
    eprintln!("skipping: could not start tracer ({e})");
}

fn trace_args(argv: &[String], cfg: Config) -> Option<(Vec<Event>, Summary)> {
    let _guard = trace_lock().lock().unwrap_or_else(|e| e.into_inner());

    let collected = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&collected);

    let tracer = match Tracer::spawn(argv, cfg) {
        Ok(t) => t,
        Err(e) => {
            unavailable(e);
            return None;
        }
    };
    let summary = tracer
        .run(|ev| sink.lock().unwrap().push(ev.clone()))
        .expect("trace run failed");

    let events = collected.lock().unwrap().clone();
    Some((events, summary))
}

struct Fixture(
    std::process::Child,
    std::sync::mpsc::Sender<()>,
    Option<std::thread::JoinHandle<()>>,
);

impl Fixture {
    fn new(child: std::process::Child) -> Self {
        let pid = child.id() as i32;
        let (cancel, timeout) = std::sync::mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if timeout
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_err()
            {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        });
        Self(child, cancel, Some(watchdog))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.1.send(());
        if let Some(watchdog) = self.2.take() {
            let _ = watchdog.join();
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn lifecycle_fixture_bin() -> &'static std::path::Path {
    use std::process::Command;
    static BIN: OnceLock<std::path::PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        // The tracer uses waitpid(-1): serialize compiler children too, not just
        // traced fixtures, so it cannot reap cc while Command::status waits.
        let _guard = trace_lock()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let path = std::env::temp_dir().join(format!(
            "wraith-provenance-lifecycle-{}",
            std::process::id()
        ));
        assert!(Command::new("cc")
            .args(["-pthread", "tests/fixtures/provenance_lifecycle.c", "-o"])
            .arg(&path)
            .status()
            .expect("lifecycle fixture requires C compiler")
            .success());
        path
    })
    .as_path()
}

#[test]
fn tracer_preserves_untraced_children_owned_by_another_os_thread() {
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;
    let _guard = trace_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let owner = std::thread::spawn(move || {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 37"])
            .spawn()
            .unwrap();
        ready_tx.send(()).unwrap();
        // Child::wait deliberately starts only after tracing completes. This
        // exposes a backend that steals a sibling OS thread's wait status.
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
        let _ = result_tx.send(child.wait());
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let tracer = Tracer::spawn(&["/bin/sleep".into(), "0.08".into()], Config::default()).unwrap();
    let traced = tracer.run(|_: &Event| {});
    release_tx.send(()).unwrap();
    let unrelated = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    owner.join().unwrap();
    assert_eq!(traced.unwrap().exit_code, Some(0));
    assert_eq!(
        unrelated
            .expect("tracer must not steal the unrelated child's wait status")
            .code(),
        Some(37)
    );
}

#[test]
fn independent_tracers_on_separate_os_threads_keep_their_own_outcomes() {
    use std::sync::mpsc;
    use std::time::Duration;
    let _guard = trace_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let mut starts = Vec::new();
    let mut workers = Vec::new();
    for expected in [17, 23] {
        let ready = ready_tx.clone();
        let results = result_tx.clone();
        let (start_tx, start_rx) = mpsc::channel();
        starts.push(start_tx);
        workers.push(std::thread::spawn(move || {
            let args = [
                "/bin/sh".into(),
                "-c".into(),
                format!("sleep 0.08; exit {expected}"),
            ];
            let tracer = Tracer::spawn(&args, Config::default()).unwrap();
            ready.send(()).unwrap();
            if start_rx.recv_timeout(Duration::from_secs(5)).is_ok() {
                let _ = results.send((expected, tracer.run(|_: &Event| {})));
            }
        }));
    }
    for _ in 0..2 {
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    for start in starts {
        start.send(()).unwrap();
    }
    let results: Vec<_> = (0..2)
        .map(|_| result_rx.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    for (expected, result) in results {
        let summary = result.expect("one tracer must not consume another tracer's stop");
        assert_eq!(summary.exit_code, Some(expected));
        assert_eq!(summary.term_signal, None);
        assert!(summary.syscalls_seen > 0);
    }
}

#[test]
fn handled_memory_signal_is_advisory_not_a_confirmed_crash() {
    let Some((events, summary)) = trace_args(
        &[
            lifecycle_fixture_bin().display().to_string(),
            "handled-segv".into(),
        ],
        Config::default(),
    ) else {
        return;
    };
    assert_eq!(summary.exit_code, Some(0));
    assert_eq!(summary.term_signal, None);
    assert!(
        !events
            .iter()
            .any(|event| event.kind == Kind::Crash || event.severity >= Severity::High),
        "delivery alone cannot prove a crash or memory corruption: {events:?}"
    );
    assert!(events
        .iter()
        .any(|event| event.kind.as_str() == "signal_delivery" && event.severity == Severity::Info));
}

#[test]
fn unhandled_memory_signals_emit_confirmed_terminal_crash() {
    for (mode, signal) in [
        ("fatal-segv", libc::SIGSEGV),
        ("fatal-fpe", libc::SIGFPE),
        ("fatal-ill", libc::SIGILL),
        ("fatal-bus", libc::SIGBUS),
        ("fatal-abrt", libc::SIGABRT),
        ("threaded-fatal", libc::SIGSEGV),
    ] {
        let Some((events, summary)) = trace_args(
            &[lifecycle_fixture_bin().display().to_string(), mode.into()],
            Config::default(),
        ) else {
            return;
        };
        assert_eq!(summary.exit_code, None);
        assert_eq!(summary.term_signal, Some(signal));
        let crashes: Vec<_> = events
            .iter()
            .filter(|event| event.kind == Kind::Crash)
            .collect();
        assert_eq!(crashes.len(), 1, "one confirmed fatal outcome: {events:?}");
        assert_eq!(crashes[0].severity, Severity::High);
        assert!(
            crashes[0].detail.contains("terminated"),
            "must describe a terminal outcome, not just delivery"
        );
        assert!(
            !crashes[0].detail.contains("memory-corruption"),
            "signal number cannot establish cause"
        );
    }
}

#[test]
fn registered_heap_altstack_is_a_benign_control() {
    let Some((events, summary)) = trace_args(
        &[
            lifecycle_fixture_bin().display().to_string(),
            "altstack".into(),
        ],
        Config::default(),
    ) else {
        return;
    };
    assert_eq!(summary.exit_code, Some(0));
    assert_eq!(summary.term_signal, None);
    assert!(
        !events.iter().any(|event| event.kind == Kind::StackPivot),
        "kernel-registered alternate stack is not a heap pivot: {events:?}"
    );
}

#[test]
fn failed_input_and_expired_staging_do_not_fabricate_strict_rx_chain() {
    let Some((events, summary)) = trace_args(
        &[
            lifecycle_fixture_bin().display().to_string(),
            "failed-input".into(),
        ],
        Config {
            jit_is_critical: true,
            ..Config::default()
        },
    ) else {
        return;
    };
    assert_eq!(summary.exit_code, Some(0));
    assert_eq!(summary.term_signal, None);
    assert!(
        events
            .iter()
            .any(|event| event.kind == Kind::ForeignOriginSyscall
                && event.severity == Severity::Critical),
        "explicit strict RX policy must remain active: {events:?}"
    );
    assert!(!events.iter().any(|event| event.kind == Kind::ExploitationChain),
        "expired staging, EBADF receive and zero-byte read cannot fabricate successful milestones: {events:?}");
}

#[test]
fn failed_mprotect_still_observes_its_partial_permission_change() {
    let Some((events, summary)) = trace_args(
        &[
            lifecycle_fixture_bin().display().to_string(),
            "partial".into(),
        ],
        Config::default(),
    ) else {
        return;
    };
    assert_eq!(
        summary.exit_code,
        Some(0),
        "fixture must execute after ENOMEM partial mutation"
    );
    assert_eq!(summary.term_signal, None);
    assert!(
        events
            .iter()
            .any(|event| event.kind == Kind::ForeignOriginSyscall
                && event.severity == Severity::Warn),
        "partial failure must still invalidate maps and reveal the RX anonymous origin: {events:?}"
    );
    assert!(!events
        .iter()
        .any(|event| event.kind == Kind::ExploitationChain));
}

fn fixture_bin() -> &'static std::path::Path {
    use std::process::Command;
    static BIN: OnceLock<std::path::PathBuf> = OnceLock::new();
    let bin = BIN.get_or_init(|| {
        let path = std::env::temp_dir().join(format!("wraith-attach-{}", std::process::id()));
        assert!(Command::new("cc")
            .args(["-pthread", "tests/fixtures/attach.c", "-o"])
            .arg(&path)
            .status()
            .expect("fixture requires a C compiler")
            .success());
        path
    });
    bin.as_path()
}

fn attach_fixture(thread: bool, drop_only: bool) {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let _guard = trace_lock().lock().unwrap_or_else(|e| e.into_inner());
    let child = Command::new(fixture_bin())
        .arg(if thread { "thread" } else { "solo" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Fixture::new(child);
    let mut ready = String::new();
    std::io::BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "READY");
    let pid = child.0.id() as i32;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let blocked = std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .filter_map(Result::ok)
            .any(|tid| {
                std::fs::read_to_string(tid.path().join("syscall"))
                    .is_ok_and(|line| line.starts_with("0 "))
            });
        if blocked {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixture never entered blocking read"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let cfg = Config {
        enforcement: wraith::detect::Enforcement::Block,
        ..Config::default()
    };
    let attach_pid = if thread {
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|tid| tid.file_name().to_string_lossy() != pid.to_string())
            .unwrap()
            .file_name()
            .to_string_lossy()
            .parse()
            .unwrap()
    } else {
        pid
    };
    let tracer = match Tracer::attach(attach_pid, cfg) {
        Ok(tracer) => tracer,
        Err(e) => {
            unavailable(e);
            return;
        }
    };
    if drop_only {
        drop(tracer);
        child.0.stdin.take().unwrap().write_all(b"x").unwrap();
        assert_eq!(
            child.0.wait().unwrap().code(),
            Some(23),
            "Drop must detach every existing thread and leave the process running"
        );
        return;
    }
    child.0.stdin.take().unwrap().write_all(b"x").unwrap();
    let mut events = Vec::new();
    let mut inspected_exit = false;
    let summary = tracer
        .run(|event| {
            if event.kind == Kind::ForeignOriginSyscall {
                let regs =
                    nix::sys::ptrace::getregs(nix::unistd::Pid::from_raw(event.pid)).unwrap();
                inspected_exit |= regs.rax != (-libc::ENOSYS as i64) as u64;
            }
            events.push(event.clone());
        })
        .unwrap();
    assert_eq!(
        summary.exit_code,
        Some(0),
        "socket was not blocked at entry: {events:?}"
    );
    assert!(events
        .iter()
        .any(|event| event.kind == Kind::Blocked && event.syscall == "socket"));
    assert!(
        !inspected_exit,
        "detection/enforcement must only run at an actual ENTRY stop"
    );
}

#[test]
fn attach_mid_syscall_enforces_at_next_entry() {
    attach_fixture(false, false);
}

#[test]
fn attach_includes_existing_sibling_threads() {
    attach_fixture(true, false);
}

#[test]
fn dropping_attached_tracer_detaches_existing_threads() {
    attach_fixture(true, true);
}

#[test]
fn nonleader_thread_exec_replacement_runs_to_completion() {
    let argv = [
        fixture_bin().to_string_lossy().into_owned(),
        "exec".to_string(),
    ];
    let Some((events, summary)) = trace_args(&argv, Config::default()) else {
        return;
    };
    assert_eq!(
        summary.exit_code,
        Some(0),
        "worker exec did not finish: {summary:?}"
    );
    assert_eq!(summary.term_signal, None);
    assert!(
        events.is_empty(),
        "benign worker exec generated events: {events:?}"
    );
}

#[test]
fn exec_replacement_runs_to_completion() {
    let argv = ["/bin/sh", "-c", "exec /bin/echo EXEC_REACHED"].map(String::from);
    let Some((events, summary)) = trace_args(&argv, Config::default()) else {
        return;
    };
    assert_eq!(
        summary.term_signal, None,
        "exec must not forward a synthetic SIGTRAP"
    );
    assert_eq!(summary.exit_code, Some(0));
    assert!(
        events.is_empty(),
        "benign replacement generated events: {events:?}"
    );
}

#[test]
fn benign_program_produces_no_detections() {
    let bin = env!("CARGO_BIN_EXE_benign");
    let Some((events, summary)) = trace(bin, Config::default()) else {
        return; // ptrace unavailable — skip
    };

    assert!(
        summary.syscalls_seen > 0,
        "expected to observe some syscalls"
    );
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
    let cfg = Config {
        audit_sensitive: true,
        ..Config::default()
    };
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
    let foreign_critical = events
        .iter()
        .any(|e| e.kind == Kind::ForeignOriginSyscall && e.severity == Severity::Critical);
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

    assert!(
        summary.syscalls_seen > 0,
        "expected to observe some syscalls"
    );
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

    let foreign_critical = events
        .iter()
        .any(|e| e.kind == Kind::ForeignOriginSyscall && e.severity == Severity::Critical);
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
    assert!(
        !criticals.is_empty(),
        "at least one CRITICAL event expected"
    );
}

#[test]
fn repeated_kill_enforcement_drains_single_and_multithreaded_targets() {
    for iteration in 0..64 {
        let bin = if iteration % 2 == 0 {
            env!("CARGO_BIN_EXE_shellcode-sim")
        } else {
            env!("CARGO_BIN_EXE_mt-shellcode-sim")
        };
        let cfg = Config {
            enforcement: wraith::detect::Enforcement::Kill,
            ..Config::default()
        };
        let Some((events, summary)) = trace(bin, cfg) else {
            return;
        };
        assert_eq!(
            summary.term_signal,
            Some(libc::SIGKILL),
            "iteration {iteration}"
        );
        assert_eq!(summary.exit_code, None, "iteration {iteration}");
        assert!(events.iter().any(|event| event.kind == Kind::Killed));
    }
}

#[test]
fn kill_enforcement_terminates_on_exploitation() {
    // In --kill mode the simulator must be SIGKILLed the moment it issues the
    // injected socket() — it never gets to exit cleanly on its own.
    use wraith::detect::Enforcement;
    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let cfg = Config {
        enforcement: Enforcement::Kill,
        ..Config::default()
    };
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
    assert_eq!(
        summary.exit_code, None,
        "a killed target has no clean exit code"
    );
    assert_eq!(summary.max_severity, Some(Severity::Critical));
}

#[test]
fn block_enforcement_neutralizes_but_lets_process_live() {
    // In --block mode the injected socket() is cancelled (returns -ENOSYS), so
    // the simulator survives and exits cleanly, but a `blocked` event proves
    // the exploit syscall was neutralised.
    use wraith::detect::Enforcement;
    let bin = env!("CARGO_BIN_EXE_shellcode-sim");
    let cfg = Config {
        enforcement: Enforcement::Block,
        ..Config::default()
    };
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
        !events
            .iter()
            .any(|e| matches!(e.kind, Kind::Blocked | Kind::Killed)),
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
        Err(e) => {
            unavailable(e);
            return;
        }
    };
    let summary = tracer.run_with(rec.clone()).expect("run_with failed");

    assert!(
        *rec.refreshes.lock().unwrap() > 0,
        "reporter was never refreshed"
    );
    assert!(*rec.events.lock().unwrap() > 0, "reporter saw no events");

    let snap = rec.snapshot.lock().unwrap();
    assert_eq!(snap.len(), 1, "expected exactly one traced process");
    let p = &snap[0];
    assert!(p.syscalls > 0, "process should have observed syscalls");
    assert!(p.events > 0, "process should have accumulated events");
    assert_eq!(p.max_severity, Some(Severity::Critical));
    assert!(
        !p.alive,
        "process should be marked exited by the final frame"
    );
    assert_eq!(summary.max_severity, Some(Severity::Critical));
}
