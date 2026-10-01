#!/usr/bin/env python3
"""Fast stdlib regressions; workloads are owned local processes, never a live service."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/benchmark_workloads.py"


def module():
    spec = importlib.util.spec_from_file_location("wraith_workloads", SCRIPT)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


def complete(name="http", count=2):
    return 'WRAITH_WORKLOAD_COMPLETE ' + json.dumps({"workload": name, "completed": count,
        "requested": count, "checksum": "owned", "operation_seconds": [0.01] * count})


class WorkloadTests(unittest.TestCase):
    def test_evidence_program_fingerprint_is_recorded(self):
        m = module()
        fingerprint = m.source_fingerprint()
        self.assertEqual(len(fingerprint["evidence_program_sha256"]), 64)

    def test_mismatched_completion_is_not_a_successful_target_proof(self):
        m = module()
        raw = {"returncode": 0, "stdout": "", "stderr": complete(count=1) + "\nwraith: target exit: 0\n", "seconds": 0.1, "timed_out": False}
        sample = m.parse_sample(raw, "http", 2, traced=True)
        self.assertFalse(sample["target_completion_verified"])

    def test_invalid_output_paths_are_rejected_before_execution(self):
        m = module()
        for output, controls in ((ROOT / "README.md", ROOT / "docs/runtime-controls-wsl.json"),
                                 (ROOT / "docs/benchmark-wsl.json", ROOT / "docs/runtime-controls-wsl.json"),
                                 (ROOT / "docs/shared.json", ROOT / "docs/shared.json")):
            with self.subTest(output=output, controls=controls), self.assertRaises(m.EvidenceError):
                m.validate_output_paths(output, controls, "all")

    def test_owned_http_workload_completes_loopback_requests(self):
        m = module()
        result = m.execute_process([sys.executable, str(SCRIPT), "--worker", "http", "--requests", "2"], 10)
        sample = m.parse_sample(result, "http", 2, traced=False)
        self.assertTrue(sample["measurement_valid"])
        self.assertEqual(sample["completion"]["transport"], "127.0.0.1 ephemeral port")
        self.assertEqual(sample["completion"]["server_shutdown"], "complete")

    def test_owned_sqlite_workload_commits_and_verifies_rows(self):
        m = module()
        result = m.execute_process([sys.executable, str(SCRIPT), "--worker", "sqlite", "--operations", "3"], 10)
        sample = m.parse_sample(result, "sqlite", 3, traced=False)
        self.assertTrue(sample["measurement_valid"])
        self.assertEqual(sample["completion"]["verified_rows"], 3)

    def test_malformed_settings_are_rejected(self):
        m = module()
        for settings in ({"samples": 0}, {"samples": 21}, {"requests": 0},
                         {"operations": 10001}, {"timeout": 0}, {"timeout": float("nan")}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                m.Settings(**settings)

    def test_sample_metadata_does_not_claim_complete_coverage(self):
        m = module()
        raw = {"returncode": 0, "stdout": "", "stderr": complete() + "\nwraith: target exit: 0\n", "seconds": 0.1, "timed_out": False}
        sample = m.parse_sample(raw, "http", 2, traced=True)
        self.assertNotIn("coverage_complete", sample)
        self.assertTrue(sample["no_reported_coverage_gaps"])
        self.assertTrue(sample["operational_observation_ok"])
        self.assertIn("not prove complete coverage", sample["observation_qualification"])

    def test_untraced_baseline_has_no_sensor_coverage_claim(self):
        m = module()
        raw = {"returncode": 0, "stdout": complete(), "stderr": "", "seconds": 0.1, "timed_out": False}
        sample = m.parse_sample(raw, "http", 2, traced=False)
        self.assertIsNone(sample["no_reported_coverage_gaps"])
        self.assertTrue(sample["operational_observation_ok"])

    def test_operational_error_without_gap_event_remains_operational(self):
        m = module()
        raw = {"returncode": 2, "stdout": "", "stderr": complete() + "\nwraith: target exit: 0\n", "seconds": 0.1, "timed_out": False}
        sample = m.parse_sample(raw, "http", 2, traced=True)
        self.assertTrue(sample["no_reported_coverage_gaps"])
        self.assertFalse(sample["operational_observation_ok"])
        self.assertFalse(sample["measurement_valid"])

    def test_no_completion_cannot_be_reported_as_valid(self):
        m = module()
        raw = {"returncode": 0, "stdout": "", "stderr": "wraith: target exit: 0\n", "seconds": 0.1, "timed_out": False}
        sample = m.parse_sample(raw, "http", 2, traced=True)
        self.assertFalse(sample["measurement_valid"])
        self.assertIn("completion", " ".join(sample["invalid_reasons"]))

    def test_operational_coverage_failure_is_preserved(self):
        m = module()
        event = {"schema_version": 2, "sensor_version": "0.2.0", "severity": "HIGH", "kind": "coverage_gap"}
        raw = {"returncode": 2, "stdout": json.dumps(event) + "\n", "stderr": complete() + "\nwraith: target exit: 0\n", "seconds": 0.2, "timed_out": False}
        sample = m.parse_sample(raw, "http", 2, traced=True)
        self.assertFalse(sample["no_reported_coverage_gaps"])
        self.assertFalse(sample["operational_observation_ok"])
        self.assertFalse(sample["measurement_valid"])
        self.assertEqual(sample["sensor_exit_code"], 2)
        self.assertEqual(sample["target_exit_code"], 0)
        self.assertEqual(sample["event_counts"]["coverage_gap"], 1)

    def test_high_policy_events_do_not_hide_successful_benign_target(self):
        m = module()
        event = {"schema_version": 2, "sensor_version": "0.2.0", "severity": "HIGH", "kind": "wx_violation"}
        raw = {"returncode": 1, "stdout": json.dumps(event) + "\n", "stderr": complete() + "\nwraith: target exit: 0\n", "seconds": 0.2, "timed_out": False}
        sample = m.parse_sample(raw, "http", 2, traced=True)
        self.assertTrue(sample["measurement_valid"])
        self.assertEqual(sample["sensor_exit_code"], 1)
        self.assertEqual(sample["severity_counts"]["HIGH"], 1)

    def test_invalid_sensor_status_and_event_schema_are_rejected(self):
        m = module()
        for code, text in [(4, ""), (0, "not-json"), (0, '{"schema_version":1}')]:
            with self.subTest(code=code, text=text), self.assertRaises(m.EvidenceError):
                m.parse_sample({"returncode": code, "stdout": text, "stderr": complete() + "\nwraith: target exit: 0\n", "seconds": 0.1, "timed_out": False}, "http", 2, traced=True)

    def test_owned_process_timeout_is_bounded_and_not_success(self):
        m = module()
        raw = m.execute_process([sys.executable, "-c", "import time; time.sleep(10)"], 0.1)
        self.assertTrue(raw["timed_out"])
        self.assertLess(raw["seconds"], 3)
        sample = m.parse_sample(raw, "http", 2, traced=False)
        self.assertFalse(sample["measurement_valid"])

    def test_sample_tail_is_labeled_empirical_not_population(self):
        m = module()
        summary = m.summarize([1, 2, 3, 4, 5])
        self.assertEqual(summary["median_seconds"], 3)
        self.assertEqual(summary["sample_count"], 5)
        self.assertIn("sample", summary["tail_qualifier"])

    def test_cli_preserves_incomplete_evidence_but_returns_operational_status(self):
        m = module()
        with tempfile.TemporaryDirectory() as directory:
            sensor = Path(directory) / "sensor"
            sensor.write_bytes(b"\x7fELF owned test bytes")
            output = Path(directory) / "incomplete.json"
            source = {"rust_input_snapshot_sha256": "a" * 64, "evidence_program_sha256": "b" * 64}
            meta = {"source": source, "sensor": {"sha256": m.hashlib.sha256(sensor.read_bytes()).hexdigest()}}
            with patch.object(sys, "argv", [str(SCRIPT), "--mode", "benchmark", "--sensor", str(sensor), "--output", str(output)]), \
                 patch.object(m, "is_native_elf", return_value=True), \
                 patch.object(m.os, "geteuid", return_value=1000), \
                 patch.object(m, "metadata", return_value=meta), \
                 patch.object(m, "source_fingerprint", return_value=source), \
                 patch.object(m, "workload_benchmark", return_value={"workloads": [{"all_measurements_valid": False}]}), \
                 patch("builtins.print"):
                self.assertEqual(m.main(), 2)
            self.assertFalse(json.loads(output.read_text())["workloads"][0]["all_measurements_valid"])

    def test_relative_sensor_uses_callers_binary_for_all_stages(self):
        m = module()
        with tempfile.TemporaryDirectory() as directory:
            sensor = Path(directory) / "owned-sensor"
            sensor.write_bytes(b"\x7fELF owned relative-path test bytes")
            output = Path(directory) / "relative.json"
            source = {"rust_input_snapshot_sha256": "a" * 64, "evidence_program_sha256": "b" * 64}
            meta = {"source": source, "sensor": {"sha256": m.hashlib.sha256(sensor.read_bytes()).hexdigest()}}
            def inspect_metadata(actual):
                self.assertEqual(actual, sensor.resolve())
                return meta
            def inspect_workload(settings, actual, observed):
                self.assertEqual(actual, sensor.resolve())
                return {"workloads": [{"all_measurements_valid": True}]}
            previous = Path.cwd()
            m.os.chdir(directory)
            try:
                with patch.object(sys, "argv", [str(SCRIPT), "--mode", "benchmark", "--sensor", "owned-sensor", "--output", str(output)]), \
                     patch.object(m, "is_native_elf", return_value=True), \
                     patch.object(m.os, "geteuid", return_value=1000), \
                     patch.object(m, "metadata", side_effect=inspect_metadata), \
                     patch.object(m, "source_fingerprint", return_value=source), \
                     patch.object(m, "workload_benchmark", side_effect=inspect_workload), \
                     patch("builtins.print"):
                    self.assertEqual(m.main(), 0)
            finally:
                m.os.chdir(previous)
            self.assertTrue(output.is_file())

    def test_metadata_records_actual_custom_sensor_path(self):
        m = module()
        with tempfile.TemporaryDirectory() as directory:
            sensor = (Path(directory) / "custom-sensor").resolve()
            sensor.write_bytes(b"\x7fELF owned metadata bytes")
            with patch.object(m, "small_command", return_value={"status": 0, "text": "wraith 0.2.0"}):
                observed = m.metadata(sensor)
            self.assertEqual(observed["sensor"]["path"], str(sensor))
            self.assertEqual(observed["sensor"]["sha256"], m.hashlib.sha256(sensor.read_bytes()).hexdigest())

    def test_binary_replacement_during_capture_invalidates_artifacts(self):
        m = module()
        with tempfile.TemporaryDirectory() as directory:
            sensor = Path(directory) / "owned-sensor"
            sensor.write_bytes(b"\x7fELF original owned bytes")
            output = Path(directory) / "replaced.json"
            source = {"rust_input_snapshot_sha256": "a" * 64, "evidence_program_sha256": "b" * 64}
            meta = {"source": source, "sensor": {"sha256": m.hashlib.sha256(sensor.read_bytes()).hexdigest()}}
            def replace_binary(*args):
                sensor.write_bytes(b"\x7fELF changed owned bytes")
                return {"workloads": [{"all_measurements_valid": True}]}
            with patch.object(sys, "argv", [str(SCRIPT), "--mode", "benchmark", "--sensor", str(sensor), "--output", str(output)]), \
                 patch.object(m, "is_native_elf", return_value=True), \
                 patch.object(m.os, "geteuid", return_value=1000), \
                 patch.object(m, "metadata", return_value=meta), \
                 patch.object(m, "source_fingerprint", return_value=source), \
                 patch.object(m, "workload_benchmark", side_effect=replace_binary), \
                 patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failure:
                    m.main()
                self.assertEqual(failure.exception.code, 2)
            self.assertFalse(output.exists())

    def test_available_native_control_templates_really_complete_without_sensor(self):
        m = module()
        def baseline_only(command, name, count, sensor, timeout, traced):
            return m.parse_sample(m.execute_process(command, timeout), name, count, traced=False)
        with patch.object(m, "capture", side_effect=baseline_only):
            document = m.runtime_controls(m.Settings(timeout=15), None, {})
        for control in document["controls"]:
            if control["availability"] == "available":
                with self.subTest(runtime=control["runtime"]):
                    self.assertTrue(control["target_completed_successfully"], control["traced"]["raw_stderr"])
                    self.assertTrue(control["traced"]["measurement_valid"])

    def test_policy_review_does_not_explain_critical_chains_as_jit(self):
        m = module()
        review = m.classify_policy([
            {"kind": "wx_violation", "severity": "HIGH"},
            {"kind": "exploitation_chain", "severity": "CRITICAL"}])
        self.assertEqual(review["known_policy_signal_counts"], {"wx_violation": 1})
        self.assertEqual(review["unexplained_signal_counts"], {"exploitation_chain": 1})

    def test_only_elf_native_runtimes_are_accepted(self):
        m = module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.exe"
            path.write_bytes(b"MZ fake Windows executable")
            self.assertFalse(m.is_native_elf(path))
            path = Path(directory) / "wrapper"
            path.write_bytes(b"#!/bin/sh\nnode real.js")
            self.assertFalse(m.is_native_elf(path))


if __name__ == "__main__":
    unittest.main()
