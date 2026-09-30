//! Fail explicitly rather than silently bypassing unsupported launched job control.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;

#[test]
fn launched_group_stop_is_not_silently_bypassed() {
    let output = Command::new("timeout")
        .arg("10")
        .arg(env!("CARGO_BIN_EXE_wraith"))
        .args(["run", "--", "/bin/sh", "-c", "kill -STOP $$; echo STOP_BYPASSED"])
        .output()
        .expect("sensor and Linux timeout must be available");
    assert_eq!(output.status.code(), Some(2), "unsupported group stop must report an operational error");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("STOP_BYPASSED"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("group stop"));
}
