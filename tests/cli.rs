//! CLI contracts use separate sensor processes and a hard timeout.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new("timeout")
        .arg("15")
        .arg(env!("CARGO_BIN_EXE_wraith"))
        .args(args)
        .output()
        .expect("Linux timeout utility and sensor must be available")
}

#[test]
fn json_stdout_is_not_contaminated_by_target_output() {
    let output = cli(&["run", "--quiet", "--json", "-", "--", "/bin/echo", "NOT_JSON"]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.is_empty(), "target stdout polluted JSON: {:?}", output.stdout);
    assert!(String::from_utf8_lossy(&output.stderr).contains("NOT_JSON"));
}

#[test]
fn failed_json_sink_is_an_operational_error() {
    let output = cli(&["run", "--json", "/dev/full", "--", env!("CARGO_BIN_EXE_shellcode-sim")]);
    assert_eq!(output.status.code(), Some(2), "lost telemetry must not look like a complete run");
    assert!(String::from_utf8_lossy(&output.stderr).contains("JSON"));
}

#[test]
fn target_exit_status_is_visible_but_does_not_replace_sensor_policy() {
    let output = cli(&["run", "--", "/bin/sh", "-c", "exit 42"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("target exit: 42"));
}

#[test]
fn enforcement_modes_are_mutually_exclusive() {
    let output = cli(&["run", "--block", "--kill", "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("mutually exclusive"));
}
