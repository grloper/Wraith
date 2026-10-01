//! Operator knobs must validate before launching the target.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::process::{Command, Output};

fn policy(flag: &str, value: &str) -> Output {
    Command::new("timeout")
        .args([
            "15",
            env!("CARGO_BIN_EXE_wraith"),
            "run",
            flag,
            value,
            "--",
            "/bin/true",
        ])
        .output()
        .expect("Linux timeout must be available")
}

#[test]
fn configurable_correlation_budget_is_usable() {
    let output = policy("--correlation-window", "8");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn zero_retired_history_keeps_live_tracing_usable() {
    let output = policy("--max-history", "0");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn correlation_budget_rejects_out_of_range_or_non_numeric_values() {
    for value in ["0", "1000001", "-1", "nope"] {
        let output = policy("--correlation-window", value);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("correlation window must be 1..=1000000"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn history_limit_rejects_out_of_range_or_non_numeric_values() {
    for value in ["10001", "-1", "nope"] {
        let output = policy("--max-history", value);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("history limit must be 0..=10000"));
        assert!(output.stdout.is_empty());
    }
}
