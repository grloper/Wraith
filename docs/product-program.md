# Wraith development program

This is a maintained engineering program, not a declaration that the repository
is finalized, enterprise-ready, or worth a particular sum. Development versions
remain pre-1.0; event-schema revisions are technical contracts, not product rebrands.

## Product focus

**Primary job:** help Linux security researchers and developers reproduce and
explain suspicious syscall origins in a selected process tree.

The initial adoption path is an isolated investigation/fuzz-triage lab. A useful
pilot reduces reproduction/setup time, preserves interpretable evidence, and
identifies where configured checks lost coverage. Production service observation
requires separate workload, kernel, availability and policy qualification. The
sensor is not a sandbox, antivirus, network scanner, or complete endpoint agent.
See the [tool comparison](tool-comparison.md) rather than a replacement claim.

## Engineering lanes and gates

| Lane | Delivery criterion | Independent evidence |
|---|---|---|
| Detection correctness | No intervention using discarded cache after required-refresh failure; successful bounded address-span context; stack enrollment does not grant code trust | Regressions for refresh failure, failed/zero outcomes, unrelated address spans, expiry and alternate stacks |
| Lifecycle and resources | Fresh state on exec/PID reuse; retained history bounded without evicting live targets | Controlled process/thread/exec/fork tests and aggregate-counter assertions |
| Operator readiness | Real owned-child preflight; coverage/output failures cannot look clean | `doctor`, structured diagnostics and operational exit-code tests |
| Distribution | Conventional amd64 package, real ELF dependencies, no privilege/service activation | Inspect/extract/execute tests, checksums and deterministic fixed-input rebuild |
| Investigation workflow | Strict bounded JSONL parsing, usable summary, no command interpretation | Malformed/duplicate/oversize/schema tests and real sensor-stream checks |
| Performance and benign controls | Raw baseline/traced samples with exact host/binary/configuration provenance | Owned HTTP/SQLite workloads and available native-runtime controls; unavailable environments reported |

Implementation and review are separate roles on the Linear-synced proof-gated
board. Advisors can propose missions; a CLI exit code or optimistic review is not
proof that a feature works. Acceptance commands run again independently before
closure. Source-writing lanes own distinct files; shared compilation and final
formatting wait for a stable integration boundary.

## Qualification before broader deployment

1. **Reproduction gate:** positive injection controls and legal negative controls
   run on the same binary and policy. A benign HIGH event is investigated, not
   quietly relabeled to make a false-positive statistic look good.
2. **Coverage gate:** failure to obtain a required mapping decision is visible.
   An empty/filtered JSON stream is not evidence of complete monitoring.
3. **Availability gate:** borrowed-process teardown, stop/resume, nonleader exec,
   restart/error paths and enforcement failure are tested on supported kernels.
   Known job-control and global-wait ownership limits remain explicit.
4. **Distribution gate:** validate installation/removal in disposable Debian/Kali
   VMs and dependency resolution before claiming that exact configuration works.
   A self-built `.deb` is not official distro inclusion or a signed repository.
5. **Performance gate:** publish real service latency/throughput and native Linux
   samples before promoting broader service monitoring. WSL results remain WSL
   results; five timing samples do not establish a population tail distribution.
6. **Pilot gate:** verify actual operator utility and maintenance capacity with
   consenting users. Stars, logos and hypothetical valuations are not substitutes.

## Lower-overhead backend: a separate research track

`ptrace` stops/resumes every syscall. Algorithmic improvements do not remove that
transport cost. The historical syscall-loop benchmark already demonstrates why
whole-host low-overhead claims are inappropriate.

A future eBPF observer must specify native `pt_regs`/syscall ABI capture, supported
hooks/kernels, target identity and exec lifecycle, event-buffer loss counters,
map/protection synchronization and source privacy. Test actual kernel loading and
deliberate buffer loss, not just a mock record decoder. Observation is not
synchronous enforcement; hook-specific prevention is designed separately.

The inspected development WSL kernel exposed BTF, but the current user had no
effective capabilities and clang/bpftool/bpftrace were unavailable. No live eBPF
backend, zero-loss stream, or arbitrary performance multiplier is claimed. Build
and privileged tests belong in an explicitly prepared disposable Linux lab/CI
configuration, not a silent host security-policy change.

## Useful success metrics

- Time to reproduce a selected suspicious-origin case and produce a readable report.
- HIGH/CRITICAL counts on named benign configurations, with explanations and limitations.
- Operational/coverage failures surfaced rather than mistaken for clean runs.
- Median and raw workload timings; retained-state bounds under fork churn.
- Supported, reproducibly tested package/kernel/runtime combinations.
- Maintainer response and regression turnaround for concrete user reports.

No million-dollar valuation or “1000× better” result follows from this plan. The
credible route is measured utility, reliable delivery and maintained trust.
