#!/usr/bin/env python3
"""Measure ptrace cost on a repeatable getpid workload; never imply an SLA."""
import argparse
import json
import pathlib
import platform
import statistics
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def timed(command):
    start = time.perf_counter()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    elapsed = time.perf_counter() - start
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {result.stderr}")
    return elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20000)
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 1000000 or not 3 <= args.samples <= 20:
        parser.error("iterations must be 1..1000000; samples must be 3..20")
    sensor = ROOT / "target/release/wraith"
    if not sensor.exists():
        parser.error("build first: cargo build --release --locked")
    workload = ["/usr/bin/python3", "-c", f"import os; [os.getpid() for _ in range({args.iterations})]"]
    traced = [str(sensor), "run", "--quiet", "--", *workload]
    timed(workload)
    timed(traced)
    baseline, monitored = [], []
    for _ in range(args.samples):
        baseline.append(timed(workload))
        monitored.append(timed(traced))
    normal, observed = statistics.median(baseline), statistics.median(monitored)
    print(json.dumps({"kernel": platform.release(), "machine": platform.machine(), "iterations": args.iterations, "samples": args.samples, "baseline_seconds": baseline, "traced_seconds": monitored, "median_baseline_seconds": normal, "median_traced_seconds": observed, "median_slowdown": observed / normal, "scope": "Python startup plus getpid loop, wall clock, observe-only; not whole-system throughput"}, indent=2))


if __name__ == "__main__":
    main()
