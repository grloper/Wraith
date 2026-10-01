#!/usr/bin/env python3
"""Dependency-free regressions for JSONL event-stream triage (owned fixtures only)."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/wraith_report.py"
LINE_LIMIT = 64 * 1024


def event(**changes):
    record = {
        "schema_version": 2,
        "sensor_version": "0.2.0",
        "pid": 123,
        "ts_ns": 1700000000000000000,
        "severity": "WARN",
        "kind": "foreign_origin_syscall",
        "syscall": "socket",
        "origin": "anon",
        "detail": "An origin observation, not proof of malicious intent.",
        "rip": "0x7f0000000000",
        "rsp": "0x7fff00000000",
    }
    record.update(changes)
    return record


def encoded(*records):
    return b"".join(json.dumps(record, ensure_ascii=True).encode("utf-8") + b"\n" for record in records)


def run_report(data, *flags):
    return subprocess.run(
        [sys.executable, str(HELPER), *flags],
        input=data,
        capture_output=True,
        timeout=10,
        cwd=ROOT,
    )


class ReportTests(unittest.TestCase):
    def summary(self, data, *flags):
        result = run_report(data, "--json", *flags)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout)

    def rejects(self, data, *flags):
        result = run_report(data, "--json", *flags)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"", "invalid input must not emit a partial summary")
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertIn(b"wraith-report:", result.stderr)
        return result

    def test_empty_stream_is_not_a_clean_verdict(self):
        report = self.summary(b"")
        self.assertEqual(report["event_count"], 0)
        self.assertIsNone(report["max_severity"])
        self.assertEqual(report["scope"], "event-stream-only")
        self.assertEqual(report["coverage_assessment"], "not_derivable_from_events")
        self.assertNotIn("clean", json.dumps(report))

    def test_current_records_aggregate_severity_kind_and_pids(self):
        report = self.summary(encoded(event(), event(severity="CRITICAL"), event(pid=124, kind="wx_violation", severity="HIGH")))
        self.assertEqual(report["event_count"], 3)
        self.assertEqual(report["unique_pids"], 2)
        self.assertEqual(report["by_severity"], {"INFO": 0, "WARN": 1, "HIGH": 1, "CRITICAL": 1})
        self.assertEqual(report["by_kind"], {"foreign_origin_syscall": 2, "wx_violation": 1})
        self.assertEqual(report["max_severity"], "CRITICAL")
        self.assertEqual(report["schema_2_events"], 3)
        self.assertEqual(report["legacy_events"], 0)

    def test_all_severities_have_an_order(self):
        for severity in ("INFO", "WARN", "HIGH", "CRITICAL"):
            with self.subTest(severity=severity):
                self.assertEqual(self.summary(encoded(event(severity=severity)))["max_severity"], severity)

    def test_legacy_missing_and_explicit_schema_one_are_marked(self):
        legacy = event()
        del legacy["schema_version"]
        del legacy["sensor_version"]
        explicit = dict(legacy, schema_version=1)
        report = self.summary(encoded(legacy, explicit, event()))
        self.assertEqual(report["legacy_events"], 2)
        self.assertEqual(report["schema_2_events"], 1)

    def test_schema_one_may_include_a_sensor_version(self):
        report = self.summary(encoded(event(schema_version=1)))
        self.assertEqual(report["legacy_events"], 1)

    def test_coverage_gap_records_count_not_failed_inspections(self):
        # Two notices for one PID still represent two emitted notices, not a count
        # of unsuccessful map refreshes or a population-wide coverage measurement.
        report = self.summary(encoded(event(kind="coverage_gap"), event(kind="coverage_gap", ts_ns=1700000000000000001)))
        self.assertEqual(report["coverage_gap_events"], 2)
        self.assertEqual(report["by_kind"], {"coverage_gap": 2})
        self.assertEqual(report["unique_pids"], 1)
        self.assertEqual(report["coverage_assessment"], "not_derivable_from_events")

    def test_human_output_uses_stream_scope_and_never_echoes_event_detail(self):
        result = run_report(encoded(event(detail="\x1b[2Jsecret\nspoofed", origin="\x1b[31mhidden")))
        self.assertEqual(result.returncode, 0)
        text = result.stdout.decode()
        self.assertIn("event-stream-only", text)
        self.assertIn("Coverage cannot be inferred", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("clean", text.lower())

    def test_file_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(encoded(event()))
            result = subprocess.run([sys.executable, str(HELPER), "--json", str(path)], capture_output=True, timeout=10, cwd=ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["event_count"], 1)

    def test_explicit_stdin_input(self):
        self.assertEqual(self.summary(encoded(event()), "-")["event_count"], 1)

    def test_multiple_files_share_state_and_aggregate_records(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("first.jsonl", "second.jsonl")]
            paths[0].write_bytes(encoded(event()))
            paths[1].write_bytes(encoded(event(pid=124, severity="HIGH")))
            result = run_report(b"", "--json", *(str(path) for path in paths))
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["event_count"], 2)
            self.assertEqual(report["unique_pids"], 2)
            self.assertEqual(report["max_severity"], "HIGH")
            self.rejects(b"", *(str(path) for path in paths), "--max-pids", "1")

    def test_invalid_later_file_emits_no_partial_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first.jsonl", Path(directory) / "second.jsonl"
            first.write_bytes(encoded(event()))
            second.write_bytes(b"not-json\n")
            result = self.rejects(b"", str(first), str(second))
            self.assertIn(b"input 2, line 1", result.stderr)

    def test_standard_input_cannot_be_selected_twice(self):
        self.rejects(encoded(event()), "-", "-")

    def test_unknown_cli_option_does_not_echo_terminal_controls(self):
        result = self.rejects(b"", "--unknown\x1b[2J")
        self.assertNotIn(b"unknown", result.stderr)

    def test_crlf_records_are_accepted(self):
        self.assertEqual(self.summary(encoded(event()).replace(b"\n", b"\r\n"))["event_count"], 1)

    def test_deep_json_and_overlong_numeric_conversion_are_rejected(self):
        self.rejects(b'{"extra":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}\n")
        self.rejects(encoded(event()).replace(b'"ts_ns": 1700000000000000000', b'"ts_ns": ' + b"9" * 1000))

    def test_no_partial_stdout_after_valid_then_invalid_input(self):
        result = self.rejects(encoded(event()) + b'{"bad":\x1b}\n')
        self.assertIn(b"line 2", result.stderr)
        self.assertNotIn(b"bad", result.stderr)

    def test_invalid_json_arrays_and_blank_lines(self):
        for data in (b"not-json\n", b"[]\n", b"null\n", b"true\n", b"42\n", b"\n", b"{\n"):
            with self.subTest(data=data):
                self.rejects(data)

    def test_duplicate_keys_are_rejected(self):
        raw = encoded(event()).replace(b'"pid": 123', b'"pid": 123, "pid": 124')
        self.rejects(raw)

    def test_nonstandard_nan_and_infinities_are_rejected(self):
        for value in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(value=value):
                self.rejects(encoded(event()).replace(b'"ts_ns": 1700000000000000000', b'"ts_ns": ' + value))

    def test_invalid_utf8_is_rejected(self):
        self.rejects(b'{"detail":"\xff"}\n')

    def test_missing_and_unknown_fields_are_rejected(self):
        for field in event():
            with self.subTest(missing=field):
                record = event()
                del record[field]
                # Missing schema/version together is specifically legacy, not an
                # invalid current record. Keep schema2 when sensor_version is absent.
                if field == "schema_version":
                    record["unexpected_field"] = "not a core event"
                self.rejects(encoded(record))
        self.rejects(encoded(event(unexpected_field={"nested": 1})))

    def test_future_and_invalid_schema_versions_are_rejected(self):
        for value in (3, 0, -1, True, False, "2", 2.0, None):
            with self.subTest(value=value):
                self.rejects(encoded(event(schema_version=value)))

    def test_invalid_integer_fields_do_not_accept_bool_as_int(self):
        for field, values in (("pid", (True, False, 0, -1, 1.0, "123", None, 2147483648)), ("ts_ns", (True, False, -1, 1.0, "0", None, 2 ** 128))):
            for value in values:
                with self.subTest(field=field, value=value):
                    self.rejects(encoded(event(**{field: value})))

    def test_invalid_strings_severity_kind_and_addresses_are_rejected(self):
        cases = {
            "sensor_version": (None, 2, "", "0.2.0\x1b[2J"),
            "severity": (None, 2, "critical", "NOTICE"),
            "kind": (None, 2, "", "Coverage_Gap", "coverage-gap", "bad\x1bkind", "a" * 65),
            "syscall": (None, 2),
            "origin": (None, 2),
            "detail": (None, 2),
            "rip": (0, None, "123", "0x", "0xg", "0x10000000000000000"),
            "rsp": (False, None, "-0x1", "0x10000000000000000"),
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.rejects(encoded(event(**{field: value})))

    def test_timestamp_zero_and_u64_address_boundaries(self):
        self.assertEqual(self.summary(encoded(event(ts_ns=0, rip="0x0", rsp="0xffffffffffffffff")))["event_count"], 1)

    def test_unpaired_unicode_surrogate_is_rejected(self):
        self.rejects(encoded(event(detail="\ud800")))

    def test_exact_line_byte_limit_and_no_final_newline(self):
        base = encoded(event(detail=""))
        record = event(detail="x" * (LINE_LIMIT - len(base)))
        line = encoded(record)
        self.assertEqual(len(line), LINE_LIMIT)
        self.assertEqual(self.summary(line)["event_count"], 1)
        self.assertEqual(self.summary(line.rstrip(b"\n"))["event_count"], 1)
        self.rejects(line[:-1] + b" \n")

    def test_unicode_line_limit_is_bytes_not_characters(self):
        raw = json.dumps(event(detail="é" * 33000), ensure_ascii=False).encode("utf-8") + b"\n"
        self.rejects(raw)

    def test_unique_pid_limit_fails_without_partial_summary(self):
        self.rejects(encoded(event(pid=1), event(pid=2)), "--max-pids", "1")
        self.assertEqual(self.summary(encoded(event(pid=1), event(pid=1)), "--max-pids", "1")["event_count"], 2)

    def test_unique_kind_limit_fails_without_partial_summary(self):
        self.rejects(encoded(event(kind="one"), event(kind="two")), "--max-kinds", "1")
        self.assertEqual(self.summary(encoded(event(kind="one"), event(kind="one")), "--max-kinds", "1")["event_count"], 2)

    def test_limit_options_must_be_positive_and_bounded(self):
        for flag, value in (("--max-pids", "0"), ("--max-kinds", "-1"), ("--max-pids", "1000001"), ("--max-kinds", "1025")):
            with self.subTest(flag=flag, value=value):
                self.rejects(b"", flag, value)

    def test_input_filename_failure_does_not_echo_control_characters(self):
        result = run_report(b"", "--json", "missing\x1b[2J.jsonl")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertNotIn(b"missing", result.stderr)

    def test_stream_reader_requests_only_bounded_lines(self):
        spec = importlib.util.spec_from_file_location("wraith_report_test_target", HELPER)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class BoundedReader(io.BytesIO):
            def read(self, *args):
                raise AssertionError("whole-stream reads are forbidden")

            def readline(self, size=-1):
                if not 0 < size <= LINE_LIMIT + 1:
                    raise AssertionError(f"unbounded readline: {size}")
                return super().readline(size)

        report = module.summarize(BoundedReader(encoded(event(), event(pid=124))))
        self.assertEqual(report["event_count"], 2)


if __name__ == "__main__":
    unittest.main()
