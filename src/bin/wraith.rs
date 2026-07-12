//! `wraith` — the command-line sensor.
//!
//! Usage:
//!   wraith run [OPTIONS] -- <program> [args...]   spawn and monitor a program
//!   wraith attach [OPTIONS] <pid>                  monitor a running process
//!
//! Options:
//!   --json <FILE|->      also write JSONL events (`-` for stdout)
//!   --min <SEV>          minimum severity to report: info|warn|high|critical
//!   --jit-critical       treat anonymous-exec origins as HIGH (no-JIT targets)
//!   --no-stack-pivot     disable the ROP stack-pivot heuristic
//!   --audit-sensitive    also log sensitive syscalls from legitimate code
//!   --quiet              suppress the human event stream (use with --json)
//!   -h, --help           show this help

use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use wraith::detect::Config;
use wraith::event::{Event, Severity};
use wraith::tracer::Tracer;

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
    cfg: Config,
}

fn run(args: Vec<String>) -> io::Result<ExitCode> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }

    let mode = args[0].clone();
    let rest = &args[1..];

    let mut opts = Opts {
        json: None,
        min: Severity::Warn,
        quiet: false,
        cfg: Config::default(),
    };

    // Split option flags from the trailing target specification.
    let mut i = 0;
    let mut target: Vec<String> = Vec::new();
    let mut attach_pid: Option<i32> = None;

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
    let mut json_sink: Option<Box<dyn Write>> = match opts.json.as_deref() {
        None => None,
        Some("-") => Some(Box::new(io::stdout())),
        Some(path) => Some(Box::new(File::create(path)?)),
    };
    let min = opts.min;
    let quiet = opts.quiet;

    let mut on_event = |ev: &Event| {
        if ev.severity >= min {
            if !quiet {
                let _ = writeln!(io::stderr(), "{}", ev.to_line(color));
            }
            if let Some(sink) = json_sink.as_mut() {
                let _ = writeln!(sink, "{}", ev.to_json());
            }
        }
    };

    let tracer = match mode.as_str() {
        "run" => {
            if target.is_empty() {
                return Err(bad("no program to run; use: wraith run -- <program> [args...]"));
            }
            eprintln!("wraith: monitoring `{}` (provenance mode)", target.join(" "));
            Tracer::spawn(&target, opts.cfg)?
        }
        "attach" => {
            let pid = attach_pid.ok_or_else(|| bad("attach needs a pid"))?;
            eprintln!("wraith: attaching to pid {pid}");
            Tracer::attach(pid, opts.cfg)?
        }
        other => return Err(bad(&format!("unknown mode `{other}` (expected run|attach)"))),
    };

    let summary = tracer.run(&mut on_event)?;

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
wraith attach [OPTIONS] <pid>                 monitor a running process\n\n\
OPTIONS:\n  \
--json <FILE|->     also write JSONL events (`-` = stdout)\n  \
--min <SEV>         minimum severity to report: info|warn|high|critical (default: warn)\n  \
--jit-critical      treat anonymous-exec origins as HIGH (targets that never JIT)\n  \
--no-stack-pivot    disable the ROP stack-pivot heuristic\n  \
--audit-sensitive   also log sensitive syscalls from legitimate code\n  \
--quiet             suppress the human stream (pair with --json)\n  \
-h, --help          show this help\n\n\
EXIT CODES:\n  \
0 clean/minor · 1 suspicious (HIGH) · 3 exploitation (CRITICAL) · 2 usage error\n"
    );
}
