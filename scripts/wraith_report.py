#!/usr/bin/env python3
"""Stream and strictly validate Wraith JSONL; summarize events, not sensor coverage.

Python 3.10+, standard library only. No detector, collector, network connection or
sensor exit-code inference is implemented here. Summary output begins only after
all selected input streams have validated successfully.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import BinaryIO, TypedDict, cast

MAX_LINE_BYTES = 64 * 1024
DEFAULT_MAX_PIDS = 4096
DEFAULT_MAX_KINDS = 128
HARD_MAX_PIDS = 1_000_000
HARD_MAX_KINDS = 1024
SEVERITIES = ("INFO", "WARN", "HIGH", "CRITICAL")
CORE_FIELDS = frozenset({"pid", "ts_ns", "severity", "kind", "syscall", "origin", "detail", "rip", "rsp"})
VERSION_FIELDS = frozenset({"schema_version", "sensor_version"})
KIND_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
ADDRESS_PATTERN = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")


class Summary(TypedDict):
    """Machine-readable aggregate; no target verdict or identity is inferred."""

    report_schema_version: int
    scope: str
    coverage_assessment: str
    event_count: int
    unique_pids: int
    by_severity: dict[str, int]
    by_kind: dict[str, int]
    max_severity: str | None
    coverage_gap_events: int
    legacy_events: int
    schema_2_events: int


class ReportInputError(ValueError):
    """A safe diagnostic containing no input values or paths."""


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReportInputError("duplicate object key")
        result[key] = value
    return result


def _nonstandard_constant(_value: str) -> object:
    raise ReportInputError("nonstandard JSON numeric constant")


def _integer(value: str) -> int:
    # Sensor timestamps are u128. Restrict conversion before Python 3.10 can
    # allocate an arbitrarily large integer from a malicious JSON number.
    if len(value.lstrip("-")) > 39:
        raise ReportInputError("integer exceeds core numeric range")
    return int(value)


def _floating_point(_value: str) -> object:
    raise ReportInputError("floating-point values are not core event fields")


def _string(record: dict[str, object], field: str) -> str:
    value = record[field]
    if not isinstance(value, str):
        raise ReportInputError(f"{field} must be a string")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ReportInputError(f"{field} contains an unpaired Unicode surrogate")
    return value


def _parse_record(raw: bytes) -> tuple[dict[str, object], bool]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ReportInputError("input is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_constant=_nonstandard_constant,
            parse_int=_integer,
            parse_float=_floating_point,
        )
    except (json.JSONDecodeError, RecursionError) as error:
        raise ReportInputError("malformed JSON object") from error
    if not isinstance(value, dict):
        raise ReportInputError("each JSONL record must be an object")
    record: dict[str, object] = value
    schema = record.get("schema_version", 1)
    if type(schema) is not int or schema not in (1, 2):
        raise ReportInputError("unsupported schema_version; expected legacy 1 or current 2")
    required = CORE_FIELDS | VERSION_FIELDS if schema == 2 else CORE_FIELDS
    if not required.issubset(record) or not set(record).issubset(CORE_FIELDS | VERSION_FIELDS):
        raise ReportInputError("missing or unknown core event fields")
    if "sensor_version" in record:
        version = _string(record, "sensor_version")
        if not version or len(version) > 128 or any(not 0x20 <= ord(char) <= 0x7E for char in version):
            raise ReportInputError("sensor_version must be nonempty printable ASCII, at most 128 characters")
    pid, timestamp = record["pid"], record["ts_ns"]
    if type(pid) is not int or not 1 <= pid <= 2 ** 31 - 1:
        raise ReportInputError("pid must be a positive i32 integer")
    if type(timestamp) is not int or not 0 <= timestamp < 2 ** 128:
        raise ReportInputError("ts_ns must be a nonnegative u128 integer")
    severity = _string(record, "severity")
    if severity not in SEVERITIES:
        raise ReportInputError("severity must be INFO, WARN, HIGH or CRITICAL")
    kind = _string(record, "kind")
    if len(kind) > 64 or KIND_PATTERN.fullmatch(kind) is None:
        raise ReportInputError("kind must be lowercase snake_case, at most 64 characters")
    for field in ("syscall", "origin", "detail"):
        _string(record, field)
    for field in ("rip", "rsp"):
        address = _string(record, field)
        if ADDRESS_PATTERN.fullmatch(address) is None:
            raise ReportInputError(f"{field} must be a 0x-prefixed unsigned u64 hexadecimal string")
    return record, schema == 1


class _Triage:
    """Retain only bounded PID/kind sets and fixed-size aggregate counters."""

    __slots__ = ("max_pids", "max_kinds", "pids", "by_kind", "by_severity", "event_count", "legacy_events", "coverage_gap_events")

    def __init__(self, max_pids: int, max_kinds: int) -> None:
        if type(max_pids) is not int or not 1 <= max_pids <= HARD_MAX_PIDS:
            raise ReportInputError("max-pids must be between 1 and 1000000")
        if type(max_kinds) is not int or not 1 <= max_kinds <= HARD_MAX_KINDS:
            raise ReportInputError("max-kinds must be between 1 and 1024")
        self.max_pids = max_pids
        self.max_kinds = max_kinds
        self.pids: set[int] = set()
        self.by_kind: dict[str, int] = {}
        self.by_severity = dict.fromkeys(SEVERITIES, 0)
        self.event_count = 0
        self.legacy_events = 0
        self.coverage_gap_events = 0

    def consume(self, stream: BinaryIO, stream_number: int = 1) -> None:
        line_number = 0
        while True:
            raw = stream.readline(MAX_LINE_BYTES + 1)
            if raw == b"":
                return
            line_number += 1
            try:
                if not isinstance(raw, bytes):
                    raise ReportInputError("input must be a binary UTF-8 stream")
                if len(raw) > MAX_LINE_BYTES:
                    raise ReportInputError("line exceeds 64 KiB byte limit (including newline)")
                record, legacy = _parse_record(raw)
                # The strict decoder has already verified these concrete types.
                pid = cast(int, record["pid"])
                kind = cast(str, record["kind"])
                severity = cast(str, record["severity"])
                if pid not in self.pids and len(self.pids) >= self.max_pids:
                    raise ReportInputError("unique PID state limit exceeded")
                if kind not in self.by_kind and len(self.by_kind) >= self.max_kinds:
                    raise ReportInputError("unique kind state limit exceeded")
                self.pids.add(pid)
                self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
                self.by_severity[severity] += 1
                self.event_count += 1
                self.legacy_events += int(legacy)
                self.coverage_gap_events += int(kind == "coverage_gap")
            except ReportInputError as error:
                raise ReportInputError(f"input {stream_number}, line {line_number}: {error}") from error

    def summary(self) -> Summary:
        maximum = next((severity for severity in reversed(SEVERITIES) if self.by_severity[severity]), None)
        return {
            "report_schema_version": 1,
            "scope": "event-stream-only",
            "coverage_assessment": "not_derivable_from_events",
            "event_count": self.event_count,
            "unique_pids": len(self.pids),
            "by_severity": dict(self.by_severity),
            "by_kind": dict(sorted(self.by_kind.items())),
            "max_severity": maximum,
            "coverage_gap_events": self.coverage_gap_events,
            "legacy_events": self.legacy_events,
            "schema_2_events": self.event_count - self.legacy_events,
        }


def summarize(
    stream: BinaryIO,
    *,
    max_pids: int = DEFAULT_MAX_PIDS,
    max_kinds: int = DEFAULT_MAX_KINDS,
) -> Summary:
    """Consume bounded UTF-8 JSONL lines; do not load or retain whole streams."""
    triage = _Triage(max_pids, max_kinds)
    triage.consume(stream)
    return triage.summary()


def _human(report: Summary) -> str:
    maximum = report["max_severity"] or "none observed in the supplied stream"
    rows = [
        "Wraith event triage (event-stream-only)",
        f"Events: {report['event_count']}; distinct event pid/TID values: {report['unique_pids']}",
        f"Maximum event severity: {maximum}",
        "By severity: " + ", ".join(f"{key}={value}" for key, value in report["by_severity"].items()),
        "By kind: " + (", ".join(f"{key}={value}" for key, value in report["by_kind"].items()) or "none in supplied stream"),
        f"Coverage-gap notices: {report['coverage_gap_events']} (emitted notices, not failed inspection counts)",
        f"Legacy events: {report['legacy_events']}; schema-2 events: {report['schema_2_events']}",
        "Coverage cannot be inferred from this event stream, including an empty or filtered stream.",
        "No sensor verdict is inferred; retain the sensor exit code separately.",
    ]
    return "\n".join(rows)


class _SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        # argparse normally repeats untrusted option values and filenames.
        self.exit(2, "wraith-report: invalid command-line arguments; use --help\n")


def main(argv: list[str] | None = None) -> int:
    parser = _SafeParser(prog="wraith-report", description=__doc__)
    parser.add_argument("inputs", nargs="*", metavar="FILE", help="UTF-8 JSONL files; '-' or no FILE reads stdin")
    parser.add_argument("--json", action="store_true", help="emit one aggregate JSON summary after successful validation")
    parser.add_argument("--max-pids", type=int, default=DEFAULT_MAX_PIDS, help="distinct PID limit (default 4096, maximum 1000000)")
    parser.add_argument("--max-kinds", type=int, default=DEFAULT_MAX_KINDS, help="distinct kind limit (default 128, maximum 1024)")
    options = parser.parse_args(argv)
    try:
        triage = _Triage(options.max_pids, options.max_kinds)
        paths = options.inputs or ["-"]
        if paths.count("-") > 1:
            raise ReportInputError("standard input may be selected only once")
        for index, path in enumerate(paths, start=1):
            if path == "-":
                triage.consume(sys.stdin.buffer, index)
            else:
                try:
                    with Path(path).open("rb") as stream:
                        triage.consume(stream, index)
                except OSError as error:
                    raise ReportInputError(f"input {index}: cannot open or read input file") from error
        report = triage.summary()
        output = json.dumps(report, ensure_ascii=True, sort_keys=False) if options.json else _human(report)
    except ReportInputError as error:
        print(f"wraith-report: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("wraith-report: cannot read input stream", file=sys.stderr)
        return 2
    try:
        print(output)
        sys.stdout.flush()
    except OSError:
        print("wraith-report: cannot write summary output", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
