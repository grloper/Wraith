//! Detection events and their serialization.
//!
//! JSON is emitted by hand rather than through `serde` on purpose: a security
//! sensor that other people run should carry the smallest dependency surface
//! we can manage. The whole engine links only `nix` and `libc`.

use std::time::{SystemTime, UNIX_EPOCH};

/// How alarming an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Context only — an audit breadcrumb or an unconfirmed signal delivery.
    Info,
    /// Worth a look — anonymous-exec origin, could be a JIT.
    Warn,
    /// Strong anomaly or confirmed diagnostic termination; cause may be benign.
    High,
    /// Exploitation. Injected code issuing syscalls, or a correlated chain.
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// The class of anomaly an event represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A syscall was issued from a memory region that is not legitimate code.
    ForeignOriginSyscall,
    /// A page was requested/made writable *and* executable.
    WxViolation,
    /// A page that was writable became executable (payload staging).
    WxTransition,
    /// The stack pointer was pivoted out of any real stack at syscall time.
    StackPivot,
    /// A sensitive syscall from a legitimate origin (audit breadcrumb).
    SensitiveCall,
    /// Current provenance could not be inspected; not evidence of exploitation.
    CoverageGap,
    /// Multiple primitives correlated into a single exploitation verdict.
    ExploitationChain,
    /// A signal-delivery stop, which may be handled and does not prove a crash.
    SignalDelivery,
    /// Kernel-confirmed termination by a diagnostic signal. Cause is unknown;
    /// this alone does not establish memory corruption or exploitation.
    Crash,
    /// Enforcement neutralised the offending syscall in place (`--block`): the
    /// kernel was told to skip it and return an error.
    Blocked,
    /// Enforcement killed the traced tree on confirmed exploitation (`--kill`).
    Killed,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::ForeignOriginSyscall => "foreign_origin_syscall",
            Kind::WxViolation => "wx_violation",
            Kind::WxTransition => "wx_transition",
            Kind::StackPivot => "stack_pivot",
            Kind::SensitiveCall => "sensitive_call",
            Kind::CoverageGap => "coverage_gap",
            Kind::ExploitationChain => "exploitation_chain",
            Kind::SignalDelivery => "signal_delivery",
            Kind::Crash => "crash",
            Kind::Blocked => "blocked",
            Kind::Killed => "killed",
        }
    }
}

/// A single detection.
#[derive(Debug, Clone)]
pub struct Event {
    pub ts_ns: u128,
    pub pid: i32,
    pub severity: Severity,
    pub kind: Kind,
    pub syscall: String,
    pub rip: u64,
    pub rsp: u64,
    /// Region label for `rip` (e.g. `libc.so.6`, `[heap]`, `anon`).
    pub origin: String,
    /// One-line human explanation.
    pub detail: String,
}

impl Event {
    #[allow(clippy::too_many_arguments)]
    pub fn now(
        pid: i32,
        severity: Severity,
        kind: Kind,
        syscall: impl Into<String>,
        rip: u64,
        rsp: u64,
        origin: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let ts_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Event {
            ts_ns,
            pid,
            severity,
            kind,
            syscall: syscall.into(),
            rip,
            rsp,
            origin: origin.into(),
            detail: detail.into(),
        }
    }

    /// A single JSON object on one line (JSONL-friendly).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":2,\"sensor_version\":\"{}\",\"ts_ns\":{},\"pid\":{},\"severity\":\"{}\",\"kind\":\"{}\",\"syscall\":\"{}\",\"rip\":\"{:#x}\",\"rsp\":\"{:#x}\",\"origin\":\"{}\",\"detail\":\"{}\"}}",
            env!("CARGO_PKG_VERSION"),
            self.ts_ns,
            self.pid,
            self.severity.as_str(),
            self.kind.as_str(),
            json_escape(&self.syscall),
            self.rip,
            self.rsp,
            json_escape(&self.origin),
            json_escape(&self.detail),
        )
    }

    /// A colourized, human-readable one-liner for a terminal.
    pub fn to_line(&self, color: bool) -> String {
        let tag = self.severity.as_str();
        let painted = if color {
            let code = match self.severity {
                Severity::Info => "36",       // cyan
                Severity::Warn => "33",       // yellow
                Severity::High => "35",       // magenta
                Severity::Critical => "1;31", // bold red
            };
            format!("\x1b[{code}m{tag:>8}\x1b[0m")
        } else {
            format!("{tag:>8}")
        };
        format!(
            "{} pid={} {:<24} {} @ {:#x} [{}]  {}",
            painted,
            self.pid,
            self.kind.as_str(),
            self.syscall,
            self.rip,
            sanitize_display(&self.origin),
            sanitize_display(&self.detail),
        )
    }
}

/// Strip terminal control characters from an untrusted string before it reaches
/// a TTY. A region's label comes from the mapped file's path and a process's
/// name comes from `/proc/<pid>/comm` — both attacker-influenceable — so without
/// this a hostile process could smuggle ANSI escape sequences into the operator's
/// display to rewrite or hide a detection row. Printable Unicode is preserved;
/// only control characters (C0, C1, DEL) are removed. The JSON sink neutralises
/// the same bytes differently, escaping them numerically (see [`json_escape`]).
pub fn sanitize_display(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Escape the characters that would break a JSON string literal.
pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_identifies_schema_and_sensor_version_without_removing_fields() {
        let event = Event::now(
            1,
            Severity::Warn,
            Kind::SensitiveCall,
            "read",
            1,
            2,
            "app",
            "audit",
        );
        let json = event.to_json();
        assert!(json.contains("\"schema_version\":2"));
        assert!(json.contains(&format!(
            "\"sensor_version\":\"{}\"",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(json.contains("\"pid\":1") && json.contains("\"syscall\":\"read\""));
    }

    #[test]
    fn json_is_wellformed_and_escaped() {
        let e = Event::now(
            42,
            Severity::Critical,
            Kind::ForeignOriginSyscall,
            "execve",
            0xdead,
            0xbeef,
            "[heap]",
            r#"quote " and \ backslash"#,
        );
        let j = e.to_json();
        assert!(j.contains("\"severity\":\"CRITICAL\""));
        assert!(j.contains("\"syscall\":\"execve\""));
        assert!(j.contains("\"rip\":\"0xdead\""));
        assert!(j.contains("\\\"")); // escaped quote survives
        assert!(j.contains("\\\\")); // escaped backslash survives
    }

    #[test]
    fn severity_orders_by_alarm() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Warn);
        assert!(Severity::Warn > Severity::Info);
    }

    #[test]
    fn line_contains_key_fields() {
        let e = Event::now(
            7,
            Severity::High,
            Kind::WxViolation,
            "mprotect",
            0x1000,
            0x2000,
            "anon",
            "rwx requested",
        );
        let l = e.to_line(false);
        assert!(l.contains("pid=7"));
        assert!(l.contains("wx_violation"));
        assert!(l.contains("mprotect"));
    }

    #[test]
    fn human_details_cannot_inject_terminal_controls() {
        let event = Event::now(
            1,
            Severity::Warn,
            Kind::CoverageGap,
            "read",
            1,
            2,
            "app",
            "bad\x1b[2J\nlabel",
        );
        let line = event.to_line(false);
        assert!(!line.contains('\x1b') && !line.contains('\n'));
        let json = event.to_json();
        assert!(
            json.contains("\\u001b") && json.contains("\\n"),
            "JSON retains escaped forensic bytes"
        );
    }

    #[test]
    fn sanitize_strips_control_but_keeps_printable() {
        // Control characters (here a clear-screen ANSI sequence) are removed;
        // the surrounding printable text — including non-ASCII — survives.
        assert_eq!(sanitize_display("evil\x1b[2Jname"), "evil[2Jname");
        assert_eq!(sanitize_display("café-server"), "café-server");
        assert_eq!(sanitize_display("a\r\n\tb"), "ab");
    }

    #[test]
    fn line_neutralizes_hostile_origin_label() {
        // A mapped-file label carrying an escape sequence must not reach the TTY
        // as a live escape — the raw clear-screen bytes are gone from the line.
        let e = Event::now(
            1,
            Severity::High,
            Kind::ForeignOriginSyscall,
            "execve",
            0x1000,
            0x2000,
            "eviltool\x1b[2J\x1b[H",
            "injected code is now acting",
        );
        let l = e.to_line(false);
        assert!(
            !l.contains('\x1b'),
            "escape from origin must be stripped: {l:?}"
        );
        assert!(
            l.contains("eviltool"),
            "sanitised label text should remain: {l:?}"
        );
    }
}
