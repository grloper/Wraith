#!/usr/bin/env python3
"""Owned loopback HTTP/SQLite measurements and an explicit benign-runtime corpus.

Python standard library only. No remote clients, privilege changes or installers.
The default policy is observe-only, without JIT-critical or trust exclusions.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).resolve()
MARKER = "WRAITH_WORKLOAD_COMPLETE "
POLICY = {"mode": "run", "enforcement": "observe", "jit_critical": False,
          "trust_regions": [], "stack_pivot": "default", "output": "--quiet --json -"}


class EvidenceError(ValueError):
    """The captured output cannot support the requested evidence claim."""


@dataclass(frozen=True)
class Settings:
    samples: int = 5
    requests: int = 20
    operations: int = 200
    timeout: float = 60.0

    def __post_init__(self):
        for name, maximum in (("samples", 20), ("requests", 200), ("operations", 10000)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in 1..{maximum}")
        if not math.isfinite(self.timeout) or not 0.05 <= self.timeout <= 180:
            raise ValueError("timeout must be a finite number in 0.05..180 seconds")


def execute_process(command, timeout):
    """Bound and reap an owned process group, including the sensor's children."""
    started = time.perf_counter()
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        start_new_session=(os.name == "posix"))
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        stdout, stderr = process.communicate(timeout=5)
    return {"returncode": process.returncode, "stdout": stdout, "stderr": stderr,
            "seconds": time.perf_counter() - started, "timed_out": timed_out}


def parse_sample(raw, workload, expected, traced):
    events = []
    if traced:
        if not raw["timed_out"] and raw["returncode"] not in (0, 1, 2, 3):
            raise EvidenceError(f"unexpected sensor status: {raw['returncode']}")
        for line in raw["stdout"].splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise EvidenceError("sensor stdout contains non-JSON data") from error
            if not isinstance(event, dict) or event.get("schema_version") != 2:
                raise EvidenceError("only event schema_version 2 is supported")
            if not isinstance(event.get("sensor_version"), str) or event.get("severity") not in ("INFO", "WARN", "HIGH", "CRITICAL") or not isinstance(event.get("kind"), str):
                raise EvidenceError("invalid schema-2 event metadata")
            events.append(event)
    lines = (raw["stderr"] if traced else raw["stdout"]).splitlines()
    markers = [line[len(MARKER):] for line in lines if line.startswith(MARKER)]
    completion = None
    if len(markers) == 1:
        try:
            completion = json.loads(markers[0])
        except json.JSONDecodeError as error:
            raise EvidenceError("malformed target completion marker") from error
    reasons = []
    if raw["timed_out"]:
        reasons.append("owned process exceeded the bounded timeout")
    completion_verified = (isinstance(completion, dict)
        and completion.get("workload") == workload
        and type(completion.get("completed")) is int and completion["completed"] == expected
        and type(completion.get("requested")) is int and completion["requested"] == expected
        and isinstance(completion.get("checksum"), str) and bool(completion["checksum"]))
    if not completion_verified:
        reasons.append("missing or mismatched target completion evidence")
    target_codes = re.findall(r"^wraith: target exit: (\d+)$", raw["stderr"], re.MULTILINE) if traced else [str(raw["returncode"])]
    target_code = int(target_codes[0]) if len(target_codes) == 1 else None
    target_signals = re.findall(r"^wraith: target signal: (\d+)$", raw["stderr"], re.MULTILINE) if traced else []
    if target_code != 0:
        reasons.append("target did not report successful exit 0")
    counts = dict(Counter(event["kind"] for event in events))
    no_reported_gaps = not bool(counts.get("coverage_gap")) if traced else None
    operational_ok = not raw["timed_out"] and (raw["returncode"] in (0, 1, 3) if traced else raw["returncode"] == 0)
    if not operational_ok:
        reasons.append("operational observation failed or ended without an accepted status")
    if no_reported_gaps is False:
        reasons.append("sensor reported provenance coverage gaps")
    return {"wall_seconds": raw["seconds"], "process_returncode": raw["returncode"],
        "sensor_exit_code": raw["returncode"] if traced else None,
        "target_exit_code": target_code, "target_signal": int(target_signals[0]) if len(target_signals) == 1 else None,
        "timed_out": raw["timed_out"], "no_reported_coverage_gaps": no_reported_gaps,
        "operational_observation_ok": operational_ok,
        "observation_qualification": "status and absence of reported gaps do not prove complete coverage" if traced else "untraced baseline: sensor gap reporting is not applicable; outcomes do not prove complete coverage",
        "measurement_valid": not reasons, "invalid_reasons": reasons,
        "completion": completion, "target_completion_verified": completion_verified,
        "event_counts": counts,
        "severity_counts": dict(Counter(event["severity"] for event in events)),
        "events": events, "raw_stdout": raw["stdout"], "raw_stderr": raw["stderr"]}


def summarize(seconds):
    if not seconds:
        return None
    ordered = sorted(seconds)
    def rank(percent):
        return ordered[max(0, math.ceil(percent * len(ordered)) - 1)]
    return {"sample_count": len(seconds), "median_seconds": statistics.median(seconds),
        "minimum_seconds": ordered[0], "maximum_seconds": ordered[-1],
        "sample_p90_seconds": rank(.90), "sample_p95_seconds": rank(.95),
        "tail_qualifier": "nearest-rank tails of this small empirical sample, not population percentiles or an SLA"}


def emit_completion(name, count, checksum, durations, **extra):
    print(MARKER + json.dumps({"workload": name, "requested": count,
        "completed": count, "checksum": str(checksum), "operation_seconds": durations, **extra}), flush=True)


def http_workload(count):
    payload = b"wraith-owned-loopback" * 32
    digest = hashlib.sha256(payload).hexdigest().encode("ascii")
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = hashlib.sha256(payload).hexdigest().encode("ascii")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            return
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
    thread.start()
    durations = []
    try:
        for _ in range(count):
            started = time.perf_counter()
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            try:
                connection.request("GET", "/owned")
                response = connection.getresponse()
                body = response.read()
                if response.status != 200 or body != digest:
                    raise EvidenceError("owned HTTP response mismatch")
            finally:
                connection.close()
            durations.append(time.perf_counter() - started)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    if thread.is_alive():
        raise EvidenceError("owned HTTP server did not stop")
    emit_completion("http", count, digest.decode("ascii"), durations,
        transport="127.0.0.1 ephemeral port", server_shutdown="complete",
        scope="owned client, server and handler threads; one connection per request")


def sqlite_workload(count):
    durations = []
    with tempfile.TemporaryDirectory(prefix="wraith-sqlite-") as directory:
        connection = sqlite3.connect(str(Path(directory) / "owned.sqlite"), timeout=1)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, digest TEXT NOT NULL)")
            connection.commit()
            checksum = hashlib.sha256()
            for index in range(count):
                started = time.perf_counter()
                value = hashlib.sha256(f"owned-{index}".encode("ascii") * 32).hexdigest()
                connection.execute("INSERT INTO records VALUES (?, ?)", (index, value))
                connection.commit()
                row = connection.execute("SELECT digest FROM records WHERE id=?", (index,)).fetchone()
                if row != (value,):
                    raise EvidenceError("SQLite committed row mismatch")
                checksum.update(row[0].encode("ascii"))
                durations.append(time.perf_counter() - started)
            verified = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            if verified != count:
                raise EvidenceError("SQLite row count mismatch")
        finally:
            connection.close()
    emit_completion("sqlite", count, checksum.hexdigest(), durations,
        verified_rows=verified, storage="owned temporary database in the system temporary directory",
        journal_mode="DELETE", synchronous="FULL", transactions=count)


def python_control(count):
    def calculate(worker):
        return sum((index * index + worker) % 65521 for index in range(count // 4))
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(calculate, range(4)))
    emit_completion("python", count, sum(values), [], workers=4)


def is_native_elf(path):
    try:
        path = Path(path).resolve()
        with path.open("rb") as stream:
            return path.suffix.lower() != ".exe" and stream.read(4) == b"\x7fELF"
    except OSError:
        return False


def small_command(command):
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=10)
        return {"status": result.returncode, "text": (result.stdout + result.stderr).strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": None, "text": "unavailable: " + str(error)}


def source_fingerprint():
    inputs = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted((ROOT / "src").rglob("*.rs"))]
    for name in ("build.rs", ".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml"):
        if (ROOT / name).is_file():
            inputs.append(ROOT / name)
    hashes = {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode("utf-8")).hexdigest()
    git = small_command(["git", "rev-parse", "HEAD"])
    status = small_command(["git", "status", "--porcelain"])
    return {"head_commit": git["text"] if git["status"] == 0 else None,
        "working_tree_dirty": bool(status["text"]) if status["status"] == 0 else None,
        "rust_input_snapshot_sha256": digest, "input_sha256": hashes,
        "evidence_program_sha256": hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        "qualification": "observed Rust/build-input snapshot at measurement time; HEAD alone is not the built source and this is not compiler attestation"}


def metadata(sensor):
    version = small_command([str(sensor), "--version"])
    if version["status"] != 0 or not re.search(r"\bwraith 0\.2\.0\b", version["text"]):
        raise EvidenceError("release sensor must identify continuous-development wraith 0.2.0")
    cpu = platform.processor() or "unavailable"
    if Path("/proc/cpuinfo").exists():
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    rustc = shutil.which("rustc")
    toolchain = small_command([rustc, "--version", "--verbose"]) if rustc and is_native_elf(rustc) else {"status": None, "text": "native rustc unavailable on PATH"}
    return {"recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "kernel": platform.release(), "machine": platform.machine(),
        "environment": "WSL (not native Linux)" if "microsoft" in platform.release().lower() else "Linux",
        "cpu_model": cpu, "logical_cpus": os.cpu_count(), "python_version": platform.python_version(),
        "sensor": {"path": "$ROOT/" + sensor.relative_to(ROOT).as_posix() if sensor.is_relative_to(ROOT) else str(sensor),
                   "version": version["text"],
                   "sha256": hashlib.sha256(sensor.read_bytes()).hexdigest()},
        "rust_toolchain": toolchain, "source": source_fingerprint(), "policy": POLICY}


def capture(command, name, count, sensor, timeout, traced):
    invoked = [str(sensor), "run", "--quiet", "--json", "-", "--", *command] if traced else command
    raw = execute_process(invoked, timeout)
    sample = parse_sample(raw, name, count, traced)
    sample["command"] = [part.replace(str(ROOT), "$ROOT") for part in invoked]
    return sample


def workload_benchmark(settings, sensor, meta):
    workloads = []
    for name, flag, count, classification in (("http", "--requests", settings.requests, "loopback threaded service / I/O"), ("sqlite", "--operations", settings.operations, "local durable SQLite transactions plus CPU hashing")):
        command = [sys.executable, str(SCRIPT), "--worker", name, flag, str(count)]
        baseline, traced = [], []
        # Pair in alternating order to expose rather than conceal order effects.
        for index in range(settings.samples):
            order = (False, True) if index % 2 == 0 else (True, False)
            for monitoring in order:
                sample = capture(command, name, count, sensor, settings.timeout, monitoring)
                (traced if monitoring else baseline).append(sample)
        valid = all(sample["measurement_valid"] for sample in baseline + traced)
        normal = summarize([sample["wall_seconds"] for sample in baseline]) if valid else None
        observed = summarize([sample["wall_seconds"] for sample in traced]) if valid else None
        workloads.append({"name": name, "classification": classification, "units_per_sample": count,
            "all_measurements_valid": valid, "baseline_summary": normal, "traced_summary": observed,
            "median_wall_slowdown": observed["median_seconds"] / normal["median_seconds"] if valid else None,
            "baseline_samples": baseline, "traced_samples": traced})
    return {"artifact_schema_version": 1, "kind": "owned_workload_benchmark", "metadata": meta,
        "settings": asdict(settings), "workloads": workloads,
        "limits": ["wall time includes Python startup, imports and shutdown; this is not production throughput",
            "small paired samples with no warmup; empirical tails are not population percentiles",
            "HTTP binds loopback only; SQLite uses an owned temporary file; no external service was contacted",
            "observation changes scheduling; performance evidence is not safety, exploit coverage or a population false-positive rate",
            "accepted status and absence of reported coverage gaps do not establish complete syscall/provenance coverage; baseline gap reporting is not applicable"]}


def classify_policy(events):
    known, unexplained = Counter(), Counter()
    for event in events:
        if event["kind"] in ("wx_violation", "wx_transition") and event["severity"] != "CRITICAL":
            known[event["kind"]] += 1
        else:
            unexplained[event["kind"]] += 1
    return {"known_policy_signal_counts": dict(known), "unexplained_signal_counts": dict(unexplained),
        "qualification": "known memory-permission heuristic, not attested runtime/JIT causality; critical chains and all other origins remain unexplained by this harness"}


def runtime_controls(settings, sensor, meta):
    controls = []
    with tempfile.TemporaryDirectory(prefix="wraith-controls-") as directory:
        for name in ("python", "node", "java"):
            executable = sys.executable if name == "python" else shutil.which(name)
            if not executable or not is_native_elf(executable):
                controls.append({"runtime": name, "availability": "unavailable", "reason": "not found as a native Linux ELF on PATH; Windows executables/wrappers are not run", "discovered_path": executable})
                continue
            version = small_command([executable, "-version" if name == "java" else "--version"])
            count = 100000
            if name == "python":
                command = [executable, str(SCRIPT), "--worker", "python", "--operations", str(count)]
            elif name == "node":
                source = Path(directory) / "owned.js"
                source.write_text("const {Worker}=require('node:worker_threads'); let x=0; for(let i=0;i<50000;i++)x=(x+i)|0; const w=new Worker('let y=0; for(let i=0;i<50000;i++)y=(y+i)|0; require(\"node:worker_threads\").parentPort.postMessage(y)',{eval:true}); w.once('message', y=>console.log('WRAITH_WORKLOAD_COMPLETE '+JSON.stringify({workload:'node',requested:100000,completed:100000,checksum:String(x+y),operation_seconds:[],workers:1})));", encoding="utf-8")
                command = [executable, "--max-old-space-size=64", str(source)]
            else:
                match = re.search(r'(?:version\s+"|openjdk\s+)(\d+)', version["text"])
                if match and int(match.group(1)) < 11:
                    controls.append({"runtime": name, "availability": "unavailable", "version": version, "reason": "owned source-file control needs Java 11+; no compiler installation attempted"})
                    continue
                source = Path(directory) / "WraithRuntimeControl.java"
                source.write_text(r'''class WraithRuntimeControl {
    public static void main(String[] args) {
        long checksum = 0;
        for (int i = 0; i < 100000; i++) checksum = Long.rotateLeft(checksum + i, 1);
        System.out.println("WRAITH_WORKLOAD_COMPLETE {\"workload\":\"java\",\"requested\":100000,\"completed\":100000,\"checksum\":\"" + checksum + "\",\"operation_seconds\":[]}");
    }
}''', encoding="utf-8")
                command = [executable, "-Xms16m", "-Xmx64m", str(source)]
            baseline = capture(command, name, count, sensor, settings.timeout, False)
            traced = capture(command, name, count, sensor, settings.timeout, True)
            finding = "none observed in this finite control"
            if traced["severity_counts"].get("HIGH") or traced["severity_counts"].get("CRITICAL"):
                finding = "benign-policy anomaly observed; review the preserved events, not proof of an attack"
            elif traced["events"]:
                finding = "lower-severity policy observations preserved"
            controls.append({"runtime": name, "availability": "available", "native_executable": str(Path(executable).resolve()),
                "version": version, "scope": "owned finite threaded/JIT-capable runtime computation, not a production corpus",
                "baseline": baseline, "traced": traced, "policy_interpretation": finding,
                "policy_review": classify_policy(traced["events"]),
                "target_completed_successfully": traced["target_exit_code"] == 0 and traced["target_completion_verified"],
                "no_reported_coverage_gaps": traced["no_reported_coverage_gaps"],
                "operational_observation_ok": traced["operational_observation_ok"],
                "observation_qualification": traced["observation_qualification"]})
    return {"artifact_schema_version": 1, "kind": "finite_benign_runtime_controls", "metadata": meta,
        "controls": controls, "limits": ["PATH discovery only; no runtimes installed and no Windows executable run",
            "one baseline and one observed sample per available runtime, not a false-positive population estimate",
            "Java source-file compilation/startup is included; Node has an owned worker and JIT-capable computation",
            "HIGH/CRITICAL benign-policy findings, operational failures and unsuccessful targets are reported separately",
            "status/event summaries cannot prove complete coverage; no_reported_coverage_gaps describes reported events only, and is null for untraced baselines"]}


def validate_output_paths(output, controls, mode):
    paths = ([output] if mode != "controls" else []) + ([controls] if mode != "benchmark" else [])
    for path in paths:
        if path.suffix.lower() != ".json" or path.resolve() == (ROOT / "docs/benchmark-wsl.json").resolve():
            raise EvidenceError("output must be JSON and must not overwrite the prior published synthetic benchmark")
    if len(paths) == 2 and output.resolve() == controls.resolve():
        raise EvidenceError("benchmark and control artifacts need distinct output paths")


def write_json(path, document):
    if path.suffix.lower() != ".json" or path.resolve() == (ROOT / "docs/benchmark-wsl.json").resolve():
        raise EvidenceError("output must be JSON and must not overwrite the published prior synthetic benchmark")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--operations", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--mode", choices=("benchmark", "controls", "all"), default="all")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/benchmark-workloads-wsl.json")
    parser.add_argument("--controls-output", type=Path, default=ROOT / "docs/runtime-controls-wsl.json")
    parser.add_argument("--sensor", type=Path, default=ROOT / "target/release/wraith")
    parser.add_argument("--worker", choices=("http", "sqlite", "python"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker:
            if args.worker == "http":
                Settings(requests=args.requests)
                http_workload(args.requests)
            elif args.worker == "sqlite":
                Settings(operations=args.operations)
                sqlite_workload(args.operations)
            else:
                if not 4 <= args.operations <= 1000000 or args.operations % 4:
                    raise ValueError("Python control operations must be a multiple of four in 4..1000000")
                python_control(args.operations)
            return 0
        settings = Settings(args.samples, args.requests, args.operations, args.timeout)
        # Resolve in the caller's directory before any child is executed with
        # cwd=ROOT; every identification, invocation and final hash uses this path.
        args.sensor = args.sensor.resolve(strict=True)
        validate_output_paths(args.output, args.controls_output, args.mode)
        if sys.platform != "linux" or not is_native_elf(sys.executable) or not is_native_elf(args.sensor):
            raise EvidenceError("measurements require native Linux Python and an existing ELF release sensor")
        if os.geteuid() == 0:
            raise EvidenceError("run owned evidence without root; no tracing capability changes are needed")
        meta = metadata(args.sensor)
        benchmark = workload_benchmark(settings, args.sensor, meta) if args.mode != "controls" else None
        controls = runtime_controls(settings, args.sensor, meta) if args.mode != "benchmark" else None
        observed = source_fingerprint()
        if any(observed[key] != meta["source"][key] for key in ("rust_input_snapshot_sha256", "evidence_program_sha256")) or hashlib.sha256(args.sensor.read_bytes()).hexdigest() != meta["sensor"]["sha256"]:
            raise EvidenceError("Rust inputs, evidence program or sensor binary changed during capture; artifacts were not written")
        if benchmark is not None:
            write_json(args.output, benchmark)
        if controls is not None:
            write_json(args.controls_output, controls)
        complete = ((benchmark is None or all(workload["all_measurements_valid"] for workload in benchmark["workloads"]))
            and (controls is None or all(control["baseline"]["measurement_valid"] and control["traced"]["measurement_valid"]
                for control in controls["controls"] if control["availability"] == "available")))
        print(json.dumps({"benchmark_output": str(args.output) if benchmark else None,
            "controls_output": str(args.controls_output) if controls else None,
            "sensor_sha256": meta["sensor"]["sha256"], "all_available_measurements_valid": complete}))
        return 0 if complete else 2
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
