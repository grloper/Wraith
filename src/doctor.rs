//! Non-destructive environment preflight for focused, owned-child monitoring.
//!
//! Readiness is not permission to attach arbitrary processes and does not attest
//! the completeness of Wraith's detection rules. The probe changes no host policy.
use std::fs;
use std::io;

use crate::detect::Config;
use crate::event::{json_escape, sanitize_display};
use crate::maps::MemoryMap;
use crate::tracer::Tracer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Info,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Info => "info",
        }
    }
}

#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn ready(&self) -> bool {
        self.checks.iter().all(|check| check.status != Status::Fail)
    }

    pub fn to_json(&self) -> String {
        let checks: Vec<String> = self
            .checks
            .iter()
            .map(|check| {
                format!(
                    "{{\"name\":\"{}\",\"status\":\"{}\",\"detail\":\"{}\"}}",
                    check.name,
                    check.status.label(),
                    json_escape(&check.detail)
                )
            })
            .collect();
        format!("{{\"schema_version\":1,\"tool\":\"wraith\",\"version\":\"{}\",\"ready\":{},\"checks\":[{}]}}",
            env!("CARGO_PKG_VERSION"), self.ready(), checks.join(","))
    }

    pub fn to_text(&self) -> String {
        let mut text = format!(
            "Wraith {} environment preflight\n",
            env!("CARGO_PKG_VERSION")
        );
        for check in &self.checks {
            text.push_str(&format!(
                "{}: {} — {}\n",
                check.name,
                check.status.label().to_uppercase(),
                sanitize_display(&check.detail)
            ));
        }
        text.push_str(if self.ready() {
            "Ready for owned-child monitoring. Existing-process attachment still depends on ownership, namespaces and security policy.\n"
        } else {
            "Not ready: resolve failed checks before monitoring. No host security policy was modified.\n"
        });
        text
    }
}

/// Check procfs and actually drive a harmless child through syscall stops.
pub fn inspect() -> Report {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown kernel".to_string());
    let mut checks = vec![Check {
        name: "platform",
        status: Status::Pass,
        detail: format!("Linux x86-64; {kernel}; requires native syscall ABI"),
    }];
    let maps = MemoryMap::read(std::process::id() as i32);
    let (status, detail) = match maps {
        Ok(map) if !map.is_empty() => (
            Status::Pass,
            "current process mappings readable".to_string(),
        ),
        Ok(_) => (
            Status::Fail,
            "procfs returned no usable mappings".to_string(),
        ),
        Err(error) => (
            Status::Fail,
            format!("cannot read procfs mappings: {error}"),
        ),
    };
    checks.push(Check {
        name: "procfs",
        status,
        detail,
    });
    let probe = probe_child();
    let (status, detail) = match probe {
        Ok(count) => (Status::Pass, format!("harmless owned child completed with {count} syscall entries; kernel stop API available")),
        Err(error) => (Status::Fail, format!("owned-child tracing failed: {error}; check ptrace/seccomp/procfs restrictions")),
    };
    checks.push(Check {
        name: "ptrace",
        status,
        detail,
    });
    let policy = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|value| format!("ptrace_scope={}; readiness does not override attachment policy", value.trim()))
        .unwrap_or_else(|_| "Yama policy unavailable or not enabled; kernel tracing probe is authoritative for this child".to_string());
    checks.push(Check {
        name: "yama",
        status: Status::Info,
        detail: policy,
    });
    Report { checks }
}

fn probe_child() -> io::Result<u64> {
    let argv = vec!["/bin/true".to_string()];
    let tracer = Tracer::spawn(&argv, Config::default())?;
    let summary = tracer.run(&mut |_: &crate::event::Event| {})?;
    if summary.exit_code != Some(0) || summary.term_signal.is_some() || summary.syscalls_seen == 0 {
        return Err(io::Error::other(
            "probe did not finish normally through syscall stops",
        ));
    }
    if summary.coverage_gaps != 0 {
        return Err(io::Error::other(
            "probe encountered incomplete provenance coverage",
        ));
    }
    Ok(summary.syscalls_seen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_prevent_readiness_and_json_escapes_details() {
        let report = Report {
            checks: vec![Check {
                name: "ptrace",
                status: Status::Fail,
                detail: "blocked \"probe\"\nby policy".to_string(),
            }],
        };
        assert!(!report.ready());
        assert!(report
            .to_json()
            .contains("blocked \\\"probe\\\"\\nby policy"));
        assert!(report.to_json().contains("\"ready\":false"));
    }
}
