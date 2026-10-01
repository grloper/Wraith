//! Doctor probes only an owned harmless child, never changes host policy.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::{Command, Output};

fn doctor(args: &[&str]) -> Output {
    Command::new("timeout")
        .arg("15")
        .arg(env!("CARGO_BIN_EXE_wraith"))
        .arg("doctor")
        .args(args)
        .output()
        .expect("Linux timeout and Wraith must be available")
}

#[test]
fn doctor_reports_actual_child_tracing_and_platform() {
    let output = doctor(&[]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("platform: PASS"), "{text}");
    assert!(text.contains("ptrace: PASS"), "{text}");
    assert!(text.contains("Ready for owned-child monitoring"), "{text}");
}

#[test]
fn doctor_json_is_clean_versioned_and_ready() {
    let output = doctor(&["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with('{') && text.trim_end().ends_with('}'), "{text}");
    assert!(text.contains("\"schema_version\":1"), "{text}");
    assert!(text.contains("\"ready\":true"), "{text}");
    assert!(text.contains("\"ptrace\""), "{text}");
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
}

#[test]
fn doctor_rejects_enforcement_and_target_flags_without_reporting_ready() {
    for flag in ["--kill", "--block", "--all", "--match", "--json-file", "extra-target"] {
        let output = doctor(&[flag]);
        assert_eq!(output.status.code(), Some(2), "unexpected acceptance of {flag}");
        assert!(output.stdout.is_empty(), "invalid flags must not run the probe");
    }
}

#[test]
fn doctor_help_is_available_without_a_probe() {
    let output = doctor(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("wraith doctor"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("ptrace: PASS"));
}
