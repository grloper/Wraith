# Operator guide

## Deployment envelope

Use a dedicated Linux x86-64 development VM or focused monitored service. The
tracer requires procfs and Linux ptrace permission; kernel 5.3+ provides the
explicit syscall-stop API used for phase-safe inspection. Windows/macOS and
32-bit/x32 tracees are not supported. WSL2 validation is not equivalent to a
fleet-wide Linux rollout.

Start with `run`, an owned child, not broad root-level `scan --all`. Attach can
be restricted by ownership, Yama, namespaces or an existing tracer. Review these
policies locally; do not globally disable them to make monitoring convenient.

```bash
cargo build --release --locked
./target/release/wraith --version
./target/release/wraith doctor --json
./target/release/wraith run --json ./events.jsonl -- /usr/bin/your-service --foreground
```

Use foreground targets; wrapper scripts and daemonization make ownership and
outcome interpretation harder. A second tracer may conflict with debuggers.

## Preflight and package use

`wraith doctor` reads local platform/procfs/policy facts and actually traces an
owned `/bin/true` child through native syscall stops. `doctor --json` emits a
versioned diagnostic object. Healthy probe: code 0; failed readiness or invalid
usage: code 2. It does not authorize attachment to arbitrary PIDs, verify every
rule, or disable Yama/seccomp. The probe changes no host security policy.

The self-built amd64 `.deb` installs the sensor, manual and curated guidance;
no daemon, capability, setuid bit or lifecycle script is activated. See
[package guidance](../packaging/README.Debian) for build dependencies and trust.
Extraction/execute verification is not a host installation or Kali VM test.

## Baseline and false positives

1. Run representative normal traffic in observe mode.
2. Inspect RWX/W→X and custom-stack events individually.
3. For JIT workloads keep default anonymous RX policy. No-JIT is opt-in; legacy
   RWX use still triggers policy signals and requires explicit investigation.
4. Use narrowly scoped trust ranges only when the runtime's addresses are known.
5. Test any enforcement policy against startup, reload, failure and shutdown.

Do not equate a CRITICAL event with proven malicious intent. Do not tune by
silencing all unknown memory. An excluded arena is an intentional blind spot.
Trust-span rounding uses ordinary 4096-byte x86-64 base pages. Huge-page mmap
requests are not exempted; existing hugetlb mapping sizes are not inferred from
maps metadata. Do not use protection trust exemptions for huge-page arenas.

Successful native `sigaltstack` registrations observed from launch enroll exact
per-thread stack extents for placement checks only. They never trust executable
code. Preexisting/fork-inherited stacks and general coroutines can still trigger
the optional heuristic; `--no-stack-pivot` is a workload-specific baseline choice.

`--correlation-window N` accepts 1..=1000000 syscall entries (default 64), with
an additional fixed 30-second monotonic expiry. This is bounded context, not
input taint tracking. Failed/zero input cannot create completed-input evidence;
failed protection attempts may still produce request alerts. Failed protection
calls may partially mutate maps, so invalidation remains conservative on exit.
`--max-history N` accepts 0..=10000 retired rows (default 128); live rows and
aggregate counters are preserved, and recycled process IDs receive fresh rows.

## Evidence and exit codes

New JSONL files request owner-only mode 0600, subject to a more restrictive caller
umask. Existing permissions are preserved; audit shared logs/directories explicitly.
Forwarded target stdout/stderr may contain arbitrary terminal controls: use an
isolated capture rather than treating sensor field sanitization as output safety.

Files passed to `--json` are appended, not truncated. Protect the containing
directory, rotate logs externally, and avoid sharing raw process metadata publicly.
With `run --json -`, target stdout is routed to stderr to preserve the sensor's
machine-readable stream. Attach/scan cannot reroute an already-running target's
file descriptors; collect its normal output separately.

`--min` filters both text and JSON events. It does not disable checks or alter
enforcement/verdicts. Use an appropriate floor if the log must include audit events.

| Sensor code | Meaning |
|---|---|
| 0 | No HIGH/CRITICAL event observed |
| 1 | HIGH event observed |
| 2 | Usage, tracing, required-map coverage or event-output failure |
| 3 | CRITICAL event observed |

The root target's exit/signal is reported separately. A clean target exit 42 does
not change the sensor code to 42. On evidence-output failure, code 2 indicates
an incomplete event stream even if detection also found CRITICAL activity.
Required map-refresh failure similarly takes operational precedence: stale maps
are not used for enforcement, and recovery does not erase earlier coverage loss.
Coverage notices are rate-limited; their JSONL count is not the number of failed
inspections. `--min` may hide notices but cannot turn the run into code 0.

Event JSON uses schema 2 with the sensor version. `pid` is a syscall TID, not a
stable process/host/run identifier. Use fresh per-run logs and external context
when joining data. The [strict triage helper](workflows.md) validates bounded
completed streams; its success means valid input, not a clean target or complete
coverage.

## Shutdown and rollback

Disable `--block`/`--kill` first if legitimate traffic is disrupted. Restore the
last validated binary and configuration; trust ranges and executable layouts may
change between builds. No database migration or persistent daemon configuration
is installed by this repository.

Launch tracing sets EXITKILL, so an unexpected tracer death kills its owned tracees.
Observe-only attach/scan should leave borrowed processes alive. With enforcement
enabled, failed blocking/killing triggers fail-closed cleanup: borrowed tracees may
also be killed rather than resumed at a rejected syscall. This is an availability
trade-off, not observe-mode behavior. Always test shutdown behavior for
your workload before rollout. Do not assume tracing is behaviorally transparent:
timing and signal delivery change, and job-control stop semantics require special
care. Launched TRACEME targets do not support transparent group-stop handling.
Wraith now reports an operational error and terminates its owned tree instead of
silently bypassing the stop; `run` must not be used where preserving shell
job-control semantics is required.
Seized attach targets use LISTEN for group stops, but that path still needs a
dedicated stop/resume regression beyond the current attach coverage.
Background/service use is recommended over interactive, job-controlled targets.

## Known operational limits

- Per-syscall stop/resume overhead; not suitable for indiscriminate busy-host tracing.
- Group-stop/job-control behavior and unusual signal policies need dedicated validation.
- Run the public library in a dedicated tracer process, or keep creation/driving
  on one dedicated OS thread. Linux `__WNOTHREAD` isolates waits from other threads'
  children; tests cover concurrent tracers and an unrelated child's preserved exit.
  Arbitrary untraced children created by the same tracer thread remain unsupported.
  Do not move an active tracer between OS threads.
- Retired dashboard history is bounded, but live target populations are not evicted;
  isolate workload resource use separately. Wraith is not a fork-bomb sandbox.
- Map refresh retry is not an atomic snapshot of concurrently mutating threads.
- No fleet agent, service manager integration, remote collector, or rotation daemon.

## Local release archive

After strict verification, `bash scripts/package_release.sh` builds an archive and
validated checksums under `target/dist/`. It contains the sensor binary and docs,
not the simulator binaries. The GNU/Linux binary uses the build host's glibc;
locally built WSL artifacts are not a universal Linux distribution binary. CI uses
Ubuntu 22.04 for a defined release baseline. No release is published automatically.

Run [strict verification](verification.md) and keep its environment recorded.
