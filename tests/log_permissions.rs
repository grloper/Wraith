//! Private evidence creation must not depend on a permissive caller umask.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn directory() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("wraith-log-mode-{}-{stamp}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}

fn log(path: &Path) {
    let mut command = Command::new("timeout");
    command.args([
        "15",
        env!("CARGO_BIN_EXE_wraith"),
        "run",
        "--quiet",
        "--json",
    ]);
    command.arg(path).args(["--", "/bin/true"]);
    // Only the spawned test process changes its mask; the parent stays intact.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let result = command.output().unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn new_json_log_is_owner_only_even_with_umask_zero() {
    let root = directory();
    let path = root.join("events.jsonl");
    log(&path);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    fs::remove_dir_all(root).unwrap();
    assert_eq!(mode, 0o600, "new evidence must not be world-readable");
}

#[test]
fn existing_log_permissions_are_not_silently_reconfigured() {
    let root = directory();
    let path = root.join("events.jsonl");
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    log(&path);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    fs::remove_dir_all(root).unwrap();
    assert_eq!(mode, 0o640);
}
