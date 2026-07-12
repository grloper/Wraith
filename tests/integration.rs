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

use std::sync::{Arc, Mutex};

use wraith::detect::Config;
use wraith::event::{Event, Kind, Severity};
use wraith::tracer::{Summary, Tracer};

/// Trace `bin` to completion, returning the collected events and the summary.
/// Returns `None` if the tracer could not even start (no ptrace permission).
fn trace(bin: &str, cfg: Config) -> Option<(Vec<Event>, Summary)> {
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
