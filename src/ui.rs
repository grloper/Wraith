//! A live, full-screen terminal dashboard for a running trace.
//!
//! This is the "advanced" console UI: a [`Dashboard`] that implements
//! [`Reporter`](crate::tracer::Reporter), so the tracer feeds it detections and
//! periodic per-process snapshots and it paints them into an alternate-screen
//! TUI — one row per traced process with live syscall/event counters and a
//! colour-coded verdict, above a scrolling feed of recent detections and an
//! aggregate status bar.
//!
//! In keeping with the rest of Wraith it pulls in no TUI framework: the whole
//! thing is hand-rolled ANSI, the same way events are serialized to JSON by
//! hand. Terminal size comes from a `TIOCGWINSZ` ioctl (via `libc`), and a
//! [`TerminalGuard`] plus a `SIGINT`/`SIGTERM` handler make sure the terminal
//! is always restored — alternate screen left, cursor shown — even on Ctrl-C.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::time::Instant;

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

use crate::detect::Enforcement;
use crate::event::{Event, Severity};
use crate::tracer::{ProcStat, Reporter, Summary};

/// How many recent detections to retain for the feed (only the tail is drawn).
const FEED_CAP: usize = 512;

/// The live dashboard. Construct one, hand it to
/// [`Tracer::run_with`](crate::tracer::Tracer::run_with) inside a
/// [`TerminalGuard`] scope, and it renders until the trace ends.
pub struct Dashboard {
    mode: String,
    enforcement: Enforcement,
    min: Severity,
    started: Instant,
    feed: VecDeque<Event>,
    json: Option<Box<dyn Write>>,
}

impl Dashboard {
    /// `mode` is a short human label for the run (e.g. `scan --match nginx`);
    /// `min` gates which detections reach the feed and the JSON sink, matching
    /// the plain output's `--min`. An optional `json` sink receives every
    /// reported event as JSONL, exactly as in non-UI mode.
    pub fn new(
        mode: String,
        enforcement: Enforcement,
        min: Severity,
        json: Option<Box<dyn Write>>,
    ) -> Self {
        Dashboard {
            mode,
            enforcement,
            min,
            started: Instant::now(),
            feed: VecDeque::new(),
            json,
        }
    }

    /// Build the frame as a vector of already-styled lines, each with a visible
    /// width no greater than `cols`. Split out from painting so it can be unit
    /// tested without a terminal.
    fn frame(&self, stats: &[ProcStat], summary: &Summary, cols: usize, rows: usize) -> Vec<String> {
        let cols = cols.max(20);
        let elapsed = self.elapsed();
        let mut out = Vec::new();

        // --- title bar -----------------------------------------------------
        out.push(bar(
            " WRAITH — runtime exploitation sensor",
            &format!("{elapsed} "),
            cols,
        ));

        // --- subtitle: mode / enforcement / totals -------------------------
        let enforce = match self.enforcement {
            Enforcement::Observe => "observe",
            Enforcement::Block => "block",
            Enforcement::Kill => "kill",
        };
        let subtitle = format!(
            " {}   ·   enforce: {}   ·   {} proc · {} syscalls · {} events",
            self.mode,
            enforce,
            stats.len(),
            human(summary.syscalls_seen),
            human(summary.events),
        );
        out.push(dim(&clip(&subtitle, cols)));

        // Tiny terminals: stop after the header so we never overflow.
        if rows < 8 {
            out.push(footer(summary, cols));
            out.truncate(rows.max(1));
            return out;
        }

        // --- process table -------------------------------------------------
        // Fixed columns (pid, syscalls, events, verdict + separators) take 41
        // cells; the process name gets whatever is left.
        let name_w = cols.saturating_sub(41);
        out.push(dim(&padr(
            &format!(
                "  {:>6} {:<name_w$} {:>8} {:>6}  {}",
                "PID", "PROCESS", "SYSCALLS", "EVENTS", "VERDICT",
                name_w = name_w
            ),
            cols,
        )));

        // Budget the remaining rows between the process table and the feed.
        let body = rows.saturating_sub(4); // title, subtitle, header, footer
        let list = body.saturating_sub(1); // one line for the feed divider
        let proc_cap = (list * 3 / 5).max(1);
        let proc_show = stats.len().min(proc_cap).max(1);
        let event_rows = list.saturating_sub(proc_show);

        if stats.len() > proc_show {
            // Leave the last slot for a "+N more" marker.
            for s in stats.iter().take(proc_show - 1) {
                out.push(proc_row(s, name_w, cols));
            }
            out.push(dim(&clip(
                &format!("  … and {} more process(es)", stats.len() - (proc_show - 1)),
                cols,
            )));
        } else {
            for s in stats.iter().take(proc_show) {
                out.push(proc_row(s, name_w, cols));
            }
        }

        // --- recent-events feed --------------------------------------------
        out.push(dim(&rule("recent detections", cols)));
        if self.feed.is_empty() {
            out.push(dim("  (no detections yet)"));
        } else {
            let shown: Vec<&Event> = self.feed.iter().rev().take(event_rows).collect();
            for ev in shown.iter().rev() {
                out.push(event_row(ev, cols));
            }
        }

        // --- status bar ----------------------------------------------------
        // Pad up to the footer row so the bar sits at the bottom edge.
        while out.len() < rows.saturating_sub(1) {
            out.push(String::new());
        }
        out.push(footer(summary, cols));
        out.truncate(rows);
        out
    }

    fn elapsed(&self) -> String {
        let s = self.started.elapsed().as_secs();
        format!("{:02}:{:02}", s / 60, s % 60)
    }

    /// Repaint the whole screen from the current snapshot.
    fn paint(&mut self, stats: &[ProcStat], summary: &Summary) {
        let (cols, rows) = term_size();
        let lines = self.frame(stats, summary, cols as usize, rows as usize);
        // Home the cursor, redraw each line clearing to end-of-line, then clear
        // everything below — one write, so the frame updates without flicker.
        let mut buf = String::from("\x1b[H");
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                buf.push_str("\r\n");
            }
            buf.push_str(line);
            buf.push_str("\x1b[K");
        }
        buf.push_str("\x1b[J");
        let mut err = io::stderr();
        let _ = err.write_all(buf.as_bytes());
        let _ = err.flush();
    }
}

impl Reporter for Dashboard {
    fn event(&mut self, ev: &Event) {
        if ev.severity < self.min {
            return;
        }
        if let Some(sink) = self.json.as_mut() {
            let _ = writeln!(sink, "{}", ev.to_json());
        }
        self.feed.push_back(ev.clone());
        if self.feed.len() > FEED_CAP {
            self.feed.pop_front();
        }
    }

    fn wants_refresh(&self) -> bool {
        true
    }

    fn refresh(&mut self, stats: &[ProcStat], summary: &Summary) {
        self.paint(stats, summary);
    }
}

// ---------------------------------------------------------------------------
// Line builders
// ---------------------------------------------------------------------------

fn proc_row(s: &ProcStat, name_w: usize, cols: usize) -> String {
    let (color, label) = verdict_style(s.max_severity);
    let dot = if s.alive { '●' } else { '○' };
    let verd_plain = padr(&format!("{dot} {label}"), 14);
    let prefix = format!(
        "  {:>6} {} {:>8} {:>6}  ",
        s.tgid,
        padr(&s.name, name_w),
        clip(&human(s.syscalls), 8),
        clip(&human(s.events), 6),
    );
    // Colour the verdict inline when the whole row fits; on a terminal too
    // narrow for that, fall back to a plain clip so no ANSI code is cut.
    if prefix.chars().count() + 14 <= cols {
        format!("{prefix}\x1b[{color}m{verd_plain}\x1b[0m")
    } else {
        clip(&format!("{prefix}{verd_plain}"), cols)
    }
}

fn event_row(ev: &Event, cols: usize) -> String {
    let color = sev_color(ev.severity);
    let head = format!("\x1b[{color}m{:>9}\x1b[0m", ev.severity.as_str());
    let rest = format!(
        " {} {} @ {:#x} [{}]  {}",
        ev.kind.as_str(),
        ev.syscall,
        ev.rip,
        ev.origin,
        ev.detail,
    );
    format!("{head}{}", clip(&rest, cols.saturating_sub(9)))
}

fn footer(summary: &Summary, cols: usize) -> String {
    let (color, label) = verdict_style(summary.max_severity);
    let left = format!(" VERDICT: {label}");
    let right = format!(
        "{} syscalls · {} events ",
        human(summary.syscalls_seen),
        human(summary.events)
    );
    // Colour the whole bar by the current verdict for an at-a-glance read.
    let plain = bar_plain(&left, &right, cols);
    format!("\x1b[7;{color}m{plain}\x1b[0m")
}

/// A reverse-video bar with `left` flushed left and `right` flushed right.
fn bar(left: &str, right: &str, cols: usize) -> String {
    format!("\x1b[7m{}\x1b[0m", bar_plain(left, right, cols))
}

fn bar_plain(left: &str, right: &str, cols: usize) -> String {
    let l = clip(left, cols);
    let ll = l.chars().count();
    let rem = cols - ll;
    let r = clip(right, rem);
    let gap = rem - r.chars().count();
    let mut s = String::with_capacity(cols);
    s.push_str(&l);
    for _ in 0..gap {
        s.push(' ');
    }
    s.push_str(&r);
    s
}

/// A dim horizontal rule with an inline label: `── recent detections ──────`.
fn rule(label: &str, cols: usize) -> String {
    let head = format!("── {label} ");
    let n = head.chars().count();
    let mut s = head;
    for _ in n..cols {
        s.push('─');
    }
    clip(&s, cols)
}

// ---------------------------------------------------------------------------
// Styling helpers
// ---------------------------------------------------------------------------

fn dim(s: &str) -> String {
    format!("\x1b[2m{s}\x1b[0m")
}

/// The ANSI colour and short label for a verdict derived from a max severity.
fn verdict_style(sev: Option<Severity>) -> (&'static str, &'static str) {
    match sev {
        None => ("2", "clean"),
        Some(Severity::Info) => ("36", "info"),
        Some(Severity::Warn) => ("33", "minor"),
        Some(Severity::High) => ("35", "suspicious"),
        Some(Severity::Critical) => ("1;31", "EXPLOITATION"),
    }
}

fn sev_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "36",
        Severity::Warn => "33",
        Severity::High => "35",
        Severity::Critical => "1;31",
    }
}

/// Compact a count: `950`, `1.2k`, `3.4M`, `1.1G`.
fn human(n: u64) -> String {
    const UNITS: [(&str, f64); 4] = [("T", 1e12), ("G", 1e9), ("M", 1e6), ("k", 1e3)];
    for (suffix, scale) in UNITS {
        if n as f64 >= scale {
            return format!("{:.1}{}", n as f64 / scale, suffix);
        }
    }
    n.to_string()
}

/// Truncate `s` to at most `w` visible columns, marking a cut with `…`.
fn clip(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w {
        return s.to_string();
    }
    match w {
        0 => String::new(),
        1 => "…".to_string(),
        _ => {
            let mut out: String = s.chars().take(w - 1).collect();
            out.push('…');
            out
        }
    }
}

/// Left-align `s` in a field of exactly `w` columns (clipping if longer).
fn padr(s: &str, w: usize) -> String {
    let c = clip(s, w);
    let n = c.chars().count();
    let mut out = c;
    for _ in n..w {
        out.push(' ');
    }
    out
}

// ---------------------------------------------------------------------------
// Terminal control
// ---------------------------------------------------------------------------

/// The terminal's `(cols, rows)`, or a sane default if it can't be queried.
fn term_size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
            && ws.ws_row > 0
            && ws.ws_col > 0
        {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

/// Bytes that restore the terminal: show the cursor, leave the alternate
/// screen. Written both by [`TerminalGuard::drop`] and, for Ctrl-C, by the
/// signal handler (where only async-signal-safe work is allowed).
const RESTORE: &[u8] = b"\x1b[?25h\x1b[?1049l";

/// Enters the alternate screen and hides the cursor on construction; restores
/// both on drop. Hold it for the lifetime of the dashboard.
pub struct TerminalGuard;

impl TerminalGuard {
    /// Switch to the alternate screen, hide the cursor, and arm a signal
    /// handler that restores the terminal if the process is interrupted.
    pub fn enter() -> io::Result<Self> {
        install_restore_handler();
        let mut err = io::stderr();
        // Enter alternate screen, hide cursor, clear it.
        err.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J")?;
        err.flush()?;
        Ok(TerminalGuard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let mut err = io::stderr();
        let _ = err.write_all(RESTORE);
        let _ = err.flush();
    }
}

extern "C" fn on_term_signal(_sig: i32) {
    // Only async-signal-safe calls here: a raw write of a constant, then _exit.
    unsafe {
        let _ = libc::write(
            libc::STDERR_FILENO,
            RESTORE.as_ptr() as *const libc::c_void,
            RESTORE.len(),
        );
        libc::_exit(130);
    }
}

fn install_restore_handler() {
    let action = SigAction::new(
        SigHandler::Handler(on_term_signal),
        SaFlags::empty(),
        SigSet::empty(),
    );
    // Best-effort: a failure to install just means Ctrl-C falls back to the
    // default (terminal not restored), which the Drop guard still handles on a
    // normal return.
    unsafe {
        let _ = sigaction(Signal::SIGINT, &action);
        let _ = sigaction(Signal::SIGTERM, &action);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, Kind};

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // Skip until the terminating letter of the escape sequence.
                for e in chars.by_ref() {
                    if e.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn stat(tgid: i32, name: &str, sys: u64, ev: u64, sev: Option<Severity>, alive: bool) -> ProcStat {
        ProcStat {
            tgid,
            name: name.to_string(),
            syscalls: sys,
            events: ev,
            max_severity: sev,
            alive,
        }
    }

    fn dash() -> Dashboard {
        Dashboard::new("scan --match nginx".into(), Enforcement::Kill, Severity::Warn, None)
    }

    #[test]
    fn human_scales() {
        assert_eq!(human(0), "0");
        assert_eq!(human(999), "999");
        assert_eq!(human(1_500), "1.5k");
        assert_eq!(human(2_400_000), "2.4M");
        assert_eq!(human(3_000_000_000), "3.0G");
    }

    #[test]
    fn clip_and_pad_respect_width() {
        assert_eq!(clip("hello", 10), "hello");
        assert_eq!(clip("hello", 4), "hel…");
        assert_eq!(clip("hello", 1), "…");
        assert_eq!(padr("hi", 5).chars().count(), 5);
        assert_eq!(padr("toolongname", 4), "too…");
    }

    #[test]
    fn every_frame_line_fits_width() {
        let d = dash();
        let stats = vec![
            stat(100, "nginx", 1200, 0, None, true),
            stat(101, "nginx: worker", 3400, 3, Some(Severity::Critical), true),
            stat(102, "redis-server", 890, 0, Some(Severity::Warn), false),
        ];
        let summary = Summary {
            syscalls_seen: 5490,
            events: 3,
            max_severity: Some(Severity::Critical),
            ..Summary::default()
        };
        for (cols, rows) in [(80usize, 24usize), (120, 40), (40, 12), (200, 60)] {
            let frame = d.frame(&stats, &summary, cols, rows);
            assert!(frame.len() <= rows, "frame taller than terminal");
            for line in &frame {
                let w = strip_ansi(line).chars().count();
                assert!(w <= cols, "line {w} cols > {cols}: {:?}", strip_ansi(line));
            }
        }
    }

    #[test]
    fn frame_shows_processes_and_verdict() {
        let d = dash();
        let stats = vec![stat(4242, "nginx", 1200, 3, Some(Severity::Critical), true)];
        let summary = Summary {
            syscalls_seen: 1200,
            events: 3,
            max_severity: Some(Severity::Critical),
            ..Summary::default()
        };
        let text = d
            .frame(&stats, &summary, 100, 24)
            .iter()
            .map(|l| strip_ansi(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("nginx"), "process name missing:\n{text}");
        assert!(text.contains("4242"), "pid missing");
        assert!(text.contains("EXPLOITATION"), "critical verdict missing:\n{text}");
        assert!(text.contains("scan --match nginx"), "mode label missing");
    }

    #[test]
    fn feed_records_and_caps() {
        let mut d = dash();
        // Below-min events are dropped from the feed.
        d.event(&Event::now(1, Severity::Info, Kind::SensitiveCall, "read", 0, 0, "libc", "info"));
        assert!(d.feed.is_empty(), "info event below warn floor must not be fed");
        for i in 0..(FEED_CAP + 50) {
            d.event(&Event::now(1, Severity::High, Kind::WxViolation, "mmap", i as u64, 0, "anon", "x"));
        }
        assert_eq!(d.feed.len(), FEED_CAP, "feed must be capped");
    }

    #[test]
    fn exited_process_shows_hollow_dot() {
        let alive = proc_row(&stat(1, "x", 0, 0, None, true), 10, 80);
        let dead = proc_row(&stat(1, "x", 0, 0, None, false), 10, 80);
        assert!(alive.contains('●'));
        assert!(dead.contains('○'));
    }
}
