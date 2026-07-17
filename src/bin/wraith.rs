//! `wraith` — the command-line sensor.
//!
//! Usage:
//!   wraith run [OPTIONS] -- <program> [args...]   spawn and monitor a program
//!   wraith attach [OPTIONS] <pid>                  monitor a running process
//!   wraith scan [OPTIONS] (--match <s> | --all)    monitor many running procs
//!
//! Options:
//!   --json <FILE|->      also write JSONL events (`-` for stdout; a FILE is appended)
//!   --min <SEV>          minimum severity to report: info|warn|high|critical
//!   --jit-critical       treat anonymous-exec origins as HIGH (no-JIT targets)
//!   --trust-region A-B   treat the hex range [A,B) as legitimate JIT (repeatable)
//!   --block              neutralise the offending syscall on detection
//!   --kill               SIGKILL the traced tree on detection
//!   --match <substr>     (scan) attach to processes whose name/cmdline matches
//!   --all                (scan) attach to every process we're allowed to trace
//!   --max-targets <N>    (scan) attach to at most N matching processes
//!   --ui                 live full-screen dashboard instead of the log stream
//!   --no-stack-pivot     disable the ROP stack-pivot heuristic
//!   --audit-sensitive    also log sensitive syscalls from legitimate code
//!   --quiet              suppress the human event stream (use with --json)
//!   -V, --version        print the wraith version and exit
//!   -h, --help           show this help

use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use wraith::detect::{Config, Enforcement};
use wraith::event::{Event, Severity};
use wraith::tracer::Tracer;
use wraith::ui::{Dashboard, TerminalGuard};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("wraith: error: {e}");
            ExitCode::from(2)
        }
    }
}

struct Opts {
    json: Option<String>,
    min: Severity,
    quiet: bool,
    ui: bool,
    cfg: Config,
}

fn run(args: Vec<String>) -> io::Result<ExitCode> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }

    // Version is essential for incident response: a log is only as useful as
    // knowing exactly which build produced it.
    if args[0] == "-V" || args[0] == "--version" {
        println!("wraith {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }

    let mode = args[0].clone();
    let rest = &args[1..];

    let mut opts = Opts {
        json: None,
        min: Severity::Warn,
        quiet: false,
        ui: false,
        cfg: Config::default(),
    };

    // Split option flags from the trailing target specification.
    let mut i = 0;
    let mut target: Vec<String> = Vec::new();
    let mut attach_pid: Option<i32> = None;
    let mut scan_matches: Vec<String> = Vec::new();
    let mut scan_all = false;
    let mut max_targets: Option<usize> = None;

    while i < rest.len() {
        let a = &rest[i];
        match a.as_str() {
            "--" => {
                target = rest[i + 1..].to_vec();
                break;
            }
            "--json" => {
                i += 1;
                opts.json = Some(rest.get(i).cloned().ok_or_else(|| bad("--json needs a value"))?);
            }
            "--min" => {
                i += 1;
                let v = rest.get(i).ok_or_else(|| bad("--min needs a value"))?;
                opts.min = parse_sev(v)?;
            }
            "--jit-critical" => opts.cfg.jit_is_critical = true,
            "--trust-region" => {
                i += 1;
                let v = rest.get(i).ok_or_else(|| bad("--trust-region needs a START-END range"))?;
                opts.cfg.trusted_regions.push(parse_region(v)?);
            }
            "--block" => opts.cfg.enforcement = Enforcement::Block,
            "--kill" => opts.cfg.enforcement = Enforcement::Kill,
            "--match" => {
                i += 1;
                let v = rest.get(i).ok_or_else(|| bad("--match needs a substring"))?;
                scan_matches.push(v.clone());
            }
            "--all" => scan_all = true,
            "--max-targets" => {
                i += 1;
                let v = rest.get(i).ok_or_else(|| bad("--max-targets needs a number"))?;
                max_targets = Some(
                    v.parse::<usize>()
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or_else(|| bad("--max-targets must be a positive integer"))?,
                );
            }
            "--ui" | "--dashboard" => opts.ui = true,
            "--no-stack-pivot" => opts.cfg.detect_stack_pivot = false,
            "--audit-sensitive" => opts.cfg.audit_sensitive = true,
            "--quiet" => opts.quiet = true,
            other => {
                if mode == "attach" && attach_pid.is_none() {
                    attach_pid = Some(other.parse().map_err(|_| bad("invalid pid"))?);
                } else {
                    return Err(bad(&format!("unexpected argument: {other}")));
                }
            }
        }
        i += 1;
    }

    // Set up output sinks.
    let color = io::stderr().is_terminal();
    let json_sink: Option<Box<dyn Write>> = match opts.json.as_deref() {
        None => None,
        Some("-") => Some(Box::new(io::stdout())),
        // Append rather than truncate: a JSONL evidence log must never lose prior
        // detections just because the sensor is re-run against the same file.
        Some(path) => Some(Box::new(
            OpenOptions::new().create(true).append(true).open(path)?,
        )),
    };
    let min = opts.min;
    let quiet = opts.quiet;
    let ui = opts.ui;
    let enforcement = opts.cfg.enforcement;

    if ui && !io::stderr().is_terminal() {
        return Err(bad(
            "--ui needs an interactive terminal on stderr; drop --ui, or use --json for a stream",
        ));
    }

    // Everything downstream — memory maps, tgids, comm names — reads /proc. Fail
    // early and clearly if it isn't mounted/readable (some restricted or rootless
    // containers) instead of deep inside the trace with a cryptic error.
    if std::fs::metadata("/proc/self/maps").is_err() {
        return Err(bad(
            "/proc is not available or readable — Wraith needs a mounted procfs to inspect memory maps",
        ));
    }

    let enforce_note = match enforcement {
        Enforcement::Observe => "",
        Enforcement::Block => " [enforcing: block]",
        Enforcement::Kill => " [enforcing: kill]",
    };

    // A short label for the run, used by the dashboard header. Assigned by
    // every non-returning arm below.
    let ui_label;

    let tracer = match mode.as_str() {
        "run" => {
            if target.is_empty() {
                return Err(bad("no program to run; use: wraith run -- <program> [args...]"));
            }
            ui_label = format!("run — {}", target.join(" "));
            if !ui {
                eprintln!(
                    "wraith: monitoring `{}` (provenance mode){enforce_note}",
                    target.join(" ")
                );
            }
            Tracer::spawn(&target, opts.cfg)?
        }
        "attach" => {
            let pid = attach_pid.ok_or_else(|| bad("attach needs a pid"))?;
            ui_label = format!("attach — pid {pid}");
            if !ui {
                eprintln!("wraith: attaching to pid {pid}{enforce_note}");
            }
            Tracer::attach(pid, opts.cfg)?
        }
        "scan" => {
            if !scan_all && scan_matches.is_empty() {
                return Err(bad(
                    "scan needs a filter: --match <substring> (repeatable) or --all",
                ));
            }
            let mut pids = enumerate_scan_pids(&scan_matches, scan_all);
            if pids.is_empty() {
                return Err(bad("scan matched no running processes"));
            }
            // Attaching adds two ptrace stops per syscall to every target, so a
            // broad `--all` on a busy host can bog the system down. `--max-targets`
            // caps how many we take on.
            if let Some(max) = max_targets {
                if pids.len() > max {
                    eprintln!(
                        "wraith: --max-targets {max}: watching {max} of {} matching process(es)",
                        pids.len()
                    );
                    pids.truncate(max);
                }
            }
            let filter = if scan_all {
                "--all".to_string()
            } else {
                format!("--match {}", scan_matches.join(","))
            };
            ui_label = format!("scan {filter}");
            if !ui {
                eprintln!(
                    "wraith: scanning {} process(es) {filter}{enforce_note}",
                    pids.len(),
                );
            }
            Tracer::attach_many(&pids, opts.cfg)?
        }
        other => {
            return Err(bad(&format!(
                "unknown mode `{other}` (expected run|attach|scan)"
            )))
        }
    };

    let summary = if ui {
        // Live dashboard: the tracer drives a Dashboard reporter inside a guard
        // that restores the terminal on exit (and on Ctrl-C via a signal handler).
        let dash = Dashboard::new(ui_label, enforcement, min, json_sink);
        let _guard = TerminalGuard::enter()?;
        tracer.run_with(dash)?
    } else {
        // Plain stream: colored log lines to stderr, optional JSONL to the sink.
        let mut json_sink = json_sink;
        let mut json_broken = false;
        let mut on_event = |ev: &Event| {
            if ev.severity >= min {
                if !quiet {
                    let _ = writeln!(io::stderr(), "{}", ev.to_line(color));
                }
                if let Some(sink) = json_sink.as_mut() {
                    // Don't swallow a failed write: for a security sensor a lost
                    // detection is the worst outcome. Warn once so a full disk or
                    // broken pipe is visible without flooding stderr.
                    if writeln!(sink, "{}", ev.to_json()).is_err() && !json_broken {
                        json_broken = true;
                        eprintln!(
                            "wraith: warning: writing to the JSON sink failed — later events may be missing from it"
                        );
                    }
                }
            }
        };
        tracer.run(&mut on_event)?
    };

    // A short verdict on stderr so a human sees the bottom line.
    eprintln!(
        "wraith: {} syscalls, {} event(s); verdict: {}",
        summary.syscalls_seen,
        summary.events,
        verdict(summary.max_severity),
    );

    // Exit non-zero when something serious fired, so wraith is CI/pipeline
    // friendly (a HIGH/CRITICAL trips the build).
    Ok(match summary.max_severity {
        Some(Severity::Critical) => ExitCode::from(3),
        Some(Severity::High) => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

fn verdict(sev: Option<Severity>) -> &'static str {
    match sev {
        Some(Severity::Critical) => "EXPLOITATION DETECTED",
        Some(Severity::High) => "suspicious activity",
        Some(Severity::Warn) => "minor anomalies",
        _ => "clean",
    }
}

/// Walk `/proc` and return the PIDs to scan. A process is selected when `all`
/// is set, or when any `needle` is a substring of its `comm` or `cmdline`. Our
/// own process, its whole ancestor chain (the shell/terminal that launched us),
/// and PID 1 are excluded — a `scan` should watch its targets, never the tools
/// that started it. The attach itself (in [`Tracer::attach_many`]) then skips
/// anything we lack permission to trace.
fn enumerate_scan_pids(needles: &[String], all: bool) -> Vec<i32> {
    let excluded = ancestor_pids();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        if pid == 1 || excluded.contains(&pid) {
            continue;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        // cmdline is NUL-separated argv; join it into one searchable string.
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
            .unwrap_or_default();
        if proc_matches(comm.trim(), cmdline.trim(), needles, all) {
            out.push(pid);
        }
    }
    out
}

/// The set of PIDs from us up to the root of the process tree — our own PID and
/// every ancestor. Used to keep `scan` from attaching to the shell, terminal,
/// or supervisor that launched it (which would otherwise match a broad filter
/// and, being long-lived, keep the trace running forever).
fn ancestor_pids() -> std::collections::HashSet<i32> {
    let mut set = std::collections::HashSet::new();
    let mut pid = std::process::id() as i32;
    // Bounded walk: real trees are shallow, and this guards against a cycle.
    for _ in 0..128 {
        if !set.insert(pid) {
            break;
        }
        match read_ppid(pid) {
            Some(ppid) if ppid > 1 => pid = ppid,
            _ => break,
        }
    }
    set
}

/// The parent PID of `pid` from `/proc/<pid>/status`, if readable.
fn read_ppid(pid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Pure predicate: does a process with this `comm`/`cmdline` pass the filter?
/// Split out from the `/proc` walk so it can be unit-tested without a live
/// process table.
fn proc_matches(comm: &str, cmdline: &str, needles: &[String], all: bool) -> bool {
    if all {
        return true;
    }
    needles
        .iter()
        .any(|n| comm.contains(n.as_str()) || cmdline.contains(n.as_str()))
}

/// Parse a `START-END` hex range (each side optionally `0x`-prefixed) into a
/// half-open `[start, end)` pair, e.g. `7f0000030000-7f0000031000`.
fn parse_region(s: &str) -> io::Result<(u64, u64)> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| bad("--trust-region wants START-END (hex), e.g. 7f00aa000000-7f00aa010000"))?;
    let parse_hex = |x: &str| u64::from_str_radix(x.trim().trim_start_matches("0x"), 16);
    let start = parse_hex(a).map_err(|_| bad("--trust-region START is not hex"))?;
    let end = parse_hex(b).map_err(|_| bad("--trust-region END is not hex"))?;
    if end <= start {
        return Err(bad("--trust-region END must be greater than START"));
    }
    // A trusted region exempts its whole span from provenance and W^X checks, so
    // an accidentally huge range (a typo like `0-ffffffffffffffff`) would quietly
    // blind the sensor. Real JIT arenas are megabytes; warn well above that.
    const HUGE_SPAN: u64 = 1 << 32; // 4 GiB
    if end - start > HUGE_SPAN {
        eprintln!(
            "wraith: warning: --trust-region {s} spans {} bytes — this exempts a very large area from detection; double-check the range",
            end - start
        );
    }
    Ok((start, end))
}

fn parse_sev(s: &str) -> io::Result<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "warn" => Ok(Severity::Warn),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        _ => Err(bad("severity must be info|warn|high|critical")),
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

fn print_help() {
    println!(
        "wraith — signature-free runtime exploitation detection\n\n\
USAGE:\n  \
wraith run [OPTIONS] -- <program> [args...]   spawn and monitor a program\n  \
wraith attach [OPTIONS] <pid>                 monitor one running process\n  \
wraith scan [OPTIONS] (--match <s> | --all)   monitor many running processes\n\n\
OPTIONS:\n  \
--json <FILE|->      also write JSONL events (`-` = stdout; a FILE is appended, not truncated)\n  \
--min <SEV>          minimum severity to report: info|warn|high|critical (default: warn)\n  \
--jit-critical       treat anonymous-exec origins as HIGH (targets that never JIT)\n  \
--trust-region A-B    treat the hex range [A,B) as legitimate JIT (repeatable)\n  \
--block              neutralise the offending syscall on exploitation (CRITICAL)\n  \
--kill               SIGKILL the traced tree on exploitation (CRITICAL)\n  \
--match <substr>     (scan) attach to processes whose name/cmdline matches (repeatable)\n  \
--all                (scan) attach to every process we're allowed to trace\n  \
--max-targets <N>    (scan) attach to at most N matching processes\n  \
--ui                 live full-screen dashboard (per-process rows + event feed)\n  \
--no-stack-pivot     disable the ROP stack-pivot heuristic\n  \
--audit-sensitive    also log sensitive syscalls from legitimate code\n  \
--quiet              suppress the human stream (pair with --json)\n  \
-V, --version        print the wraith version and exit\n  \
-h, --help           show this help\n\n\
ENFORCEMENT:\n  \
Detection is always on. --block and --kill add active response and fire only on\n  \
a CRITICAL verdict (injected code issuing a sensitive syscall, or a correlated\n  \
chain): --block cancels that syscall in place; --kill terminates the tree.\n\n\
SCAN:\n  \
`scan` attaches to a set of already-running processes at once. It needs\n  \
CAP_SYS_PTRACE (or ownership of the targets) and adds two stops per syscall to\n  \
each, so favour --match over --all on a busy host. Stopping wraith leaves the\n  \
scanned processes running.\n\n\
EXIT CODES:\n  \
0 clean/minor · 1 suspicious (HIGH) · 3 exploitation (CRITICAL) · 2 usage error\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needles(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn all_matches_everything() {
        assert!(proc_matches("anything", "", &[], true));
        assert!(proc_matches("", "", &needles(&["nomatch"]), true));
    }

    #[test]
    fn match_by_comm_or_cmdline() {
        let n = needles(&["nginx"]);
        assert!(proc_matches("nginx", "/usr/sbin/nginx -g daemon off;", &n, false));
        assert!(proc_matches("worker", "/usr/sbin/nginx: worker process", &n, false));
        assert!(!proc_matches("sshd", "/usr/sbin/sshd -D", &n, false));
    }

    #[test]
    fn empty_filter_matches_nothing() {
        assert!(!proc_matches("anything", "any cmdline", &[], false));
    }

    #[test]
    fn any_of_several_needles_matches() {
        let n = needles(&["redis", "postgres"]);
        assert!(proc_matches("postgres", "postgres: writer", &n, false));
        assert!(!proc_matches("mysqld", "/usr/sbin/mysqld", &n, false));
    }

    #[test]
    fn region_parsing() {
        assert_eq!(parse_region("1000-2000").unwrap(), (0x1000, 0x2000));
        assert_eq!(parse_region("0x1000-0x2000").unwrap(), (0x1000, 0x2000));
        assert!(parse_region("2000-1000").is_err());
        assert!(parse_region("nope").is_err());
        assert!(parse_region("1000-zzzz").is_err());
    }
}
