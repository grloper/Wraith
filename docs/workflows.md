# Owned-target workflows and event triage

Wraith contributes a focused runtime question: **where did this syscall execute?**
Use it alongside source review, vulnerability analysis and your workload's existing
controls, not as an AV, Nmap, sandbox or full EDR replacement. Only monitor programs
and environments you own or are explicitly authorized to assess.

Run experiments in an operator-owned Linux VM suitable for your workload. Wraith
**does not isolate the target**: observe mode still permits its filesystem/network
operations and changes execution timing. The local simulator opens a socket but
does not connect or exfiltrate. Do not replace it with untrusted samples on a
normal workstation. Read [the threat model](threat-model.md) and
[operator limits](operations.md) before enforcement.

## 1. Establish an owned-child baseline

From the source checkout, use Linux x86-64 with a supported kernel/toolchain:

```bash
cargo build --release --locked
./target/release/wraith doctor
bash demo.sh
```

The doctor probes a harmless owned child; it does not weaken host ptrace/Yama
policy. A denied probe is an environment failure, not a clean security verdict.
The demo has explicit benign/injected main/worker and enforcement expectations.
For a real service, begin with representative benign behavior in observe mode;
keep JIT/custom-stack assumptions explicit. Do not start with whole-host scans.

## 2. Capture a fixture and summarize actual JSONL

The optional `scripts/wraith_report.py` is a **dependency-free Python 3.10+** helper
from the source checkout. The `.deb` remains sensor-only: it does not install this
helper or introduce a Python runtime dependency for the sensor.

Use a fresh private artifact directory so appended old records cannot silently
become part of a new experiment:

```bash
set -euo pipefail
umask 077
work=$(mktemp -d)
sensor_status=0
./target/release/wraith run --json "$work/events.jsonl" -- \
  ./target/release/shellcode-sim || sensor_status=$?

# The controlled injection fixture is expected to trip sensor policy (exit 3).
if [[ $sensor_status -ne 3 ]]; then
  printf 'Unexpected sensor exit: %s; inspect the run before interpreting events.\n' "$sensor_status" >&2
  exit 1
fi
python3 scripts/wraith_report.py "$work/events.jsonl"
python3 scripts/wraith_report.py --json "$work/events.jsonl" > "$work/summary.json"
printf 'Sensor exit: %s; artifacts retained at %s\n' "$sensor_status" "$work"
```

Run the same capture with `./target/release/benign` as the owned target when you
want a negative control; its sensor expectation is `0`. An empty event stream
is an empty **input to the helper**, not independent proof of a clean sensor,
complete coverage, or absence of exploitation. Keep the actual sensor status and
its diagnostics. Target exit status is separate again from sensor policy status.

## 3. Preserve the sensor's exit code in automation

The triage helper returns `0` when input validated, even if it contains CRITICAL
events. Its exit status is not Wraith's detector verdict. For an owned regression
target in CI, keep both outcomes instead of hiding the sensor status behind a pipe:

```bash
set -euo pipefail
umask 077
work=$(mktemp -d)
sensor_status=0
./target/release/wraith run --json "$work/events.jsonl" -- \
  ./target/release/benign || sensor_status=$?
python3 scripts/wraith_report.py --json "$work/events.jsonl" > "$work/summary.json"
printf 'Wraith sensor exit: %s; artifacts: %s\n' "$sensor_status" "$work"
exit "$sensor_status"
```

Malformed/unsupported input makes the helper return `2` before it writes any
stdout summary; with `set -e`, that error stops this workflow. The redirected
summary file may exist but will be empty on malformed input. Do not consume it
without checking the helper status. Wraith operational errors also need attention,
regardless of whether an event file happens to be empty.

For a streaming shell composition, `set -o pipefail` is the minimum protection
against masking the sensor exit. Preserve the sensor's `PIPESTATUS[0]` immediately
if you need its exact code: `pipefail` alone identifies a failed pipeline, not
which component failed. A JSONL file capture is clearer when the sensor and target
also produce human output.

## 4. Files, stdin and finite stream snapshots

```bash
# One input; human summary.
python3 scripts/wraith_report.py ./events.jsonl

# Stdin; one machine-readable JSON summary.
python3 scripts/wraith_report.py --json - < ./events.jsonl

# Aggregate several completed logs under the same state bounds.
python3 scripts/wraith_report.py --json ./startup.jsonl ./steady-state.jsonl

# Explicit limits for a known workload; defaults are 4096 PID values / 128 kinds.
python3 scripts/wraith_report.py --max-pids 8192 --max-kinds 256 ./events.jsonl
```

Input is consumed one bounded line at a time. A summary is emitted **only at EOF,
after every selected file validates**; this is batch triage, not a live dashboard.
`tail -f` will not yield periodic summaries while its pipe remains open. Summarize
a completed/rotated log, not a partially written capture; a truncated record fails
strictly instead of being silently dropped. Rotating collection and protecting
artifact access are operator responsibilities, not features installed by this script.

The helper does not deduplicate logs. Repeating a record or passing overlapping
files counts the records again. `event.pid` is the stopped syscall **thread ID**;
`unique_pids` counts distinct observed pid/TID values, not logical processes,
address spaces, hosts or stable process identities. Threads inflate this value,
and numeric IDs can be reused across runs/hosts. No host/run identity is inferred.

## 5. Schema and summary contract

This illustrative current-schema record is structurally valid; it is not a live
capture or a claim that the shown PID exists:

```json
{"schema_version":2,"sensor_version":"0.2.0","pid":123,"ts_ns":0,"severity":"WARN","kind":"coverage_gap","syscall":"mmap","origin":"unknown","detail":"Illustrative mapping-coverage notice.","rip":"0x0","rsp":"0x0"}
```

The helper validates exact current core fields:

- `schema_version: 2` and a nonempty printable ASCII `sensor_version` string,
  at most 128 characters.
- `pid`: positive signed-32-bit integer; `ts_ns`: nonnegative unsigned-128-bit
  integer. Booleans, floats and numeric strings are not integer substitutes.
- `severity`: `INFO`, `WARN`, `HIGH` or `CRITICAL`; `kind`: lowercase snake_case,
  at most 64 characters. New kind names are allowed within the state bound.
- `syscall`, `origin`, `detail`: Unicode strings without unpaired surrogates.
- `rip`, `rsp`: `0x`-prefixed hexadecimal unsigned-64-bit strings.

Legacy records with missing `schema_version` or explicit version `1` remain
accepted if they have the same valid core fields. Their `sensor_version` is
optional; they are counted in `legacy_events`, not quietly relabeled as current.
Unsupported future versions, missing/unknown fields, duplicate object keys,
nonstandard NaN/Infinity, arrays, blank lines, invalid UTF-8 and malformed JSON
are rejected. Core integer conversion is bounded before allocating huge values.

Each physical input line is limited to **64 KiB including its newline**. State is
bounded by unique pid/TID values and kind names; exceeding either limit fails,
not silently truncates. CLI overrides have hard maxima of 1,000,000 pid values
and 1024 kinds. Lines are streamed; details/origins are not retained or echoed
in the summary. Safe errors identify input ordinal and line number, not untrusted
record contents or filenames.

JSON output is an aggregate object with `report_schema_version: 1` (the helper's
summary format, distinct from the sensor event schema), including:

| Field | Meaning |
|---|---|
| `scope` | Always `event-stream-only` |
| `event_count` | Number of accepted records across selected inputs |
| `unique_pids` | Distinct observed numeric event pid/TID values |
| `by_severity`, `by_kind` | Aggregate record counts; severity order is explicit |
| `max_severity` | Maximum event severity, or `null` for empty input |
| `coverage_gap_events` | Emitted coverage-gap **notice records**, not unsuccessful syscall inspections |
| `legacy_events`, `schema_2_events` | Explicit compatibility counts |
| `coverage_assessment` | Always `not_derivable_from_events` |

The sensor may emit one gap notice for a period containing many failed inspections.
This helper counts notices, without deduplication or estimating those inspections.
`--min` filters the sensor's JSONL stream too. A gap count of zero—especially from
a silent, filtered, interrupted, legacy or incomplete stream—cannot establish
full coverage. No count is a calibrated exploitation probability or SIEM certification.

## 6. Local verification

```bash
python3 scripts/test_report.py
```

The suite uses only `unittest` and the Python standard library. It covers current
and legacy compatibility, emitted-notice semantics, malformed inputs with empty
stdout, schema/type boundaries, byte limits, state bounds, stdin/file CLI paths
and bounded line-reader behavior. It does not replace real sensor tests or claim
population-wide false-positive rates. Keep sensor regressions and platform evidence
in [verification](verification.md).
