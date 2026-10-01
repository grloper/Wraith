# Verification evidence

## Maintained investigation foundations (development snapshot)

The current Rust source passes **130 tests** on stable and MSRV **1.74.0**, with
zero ignored tests in strict ptrace mode: 87 library, 5 binary-unit, 4 CLI,
4 doctor, 23 integration, 1 job-control, 2 file-permission and 4 policy-control tests.
Stable Clippy with warnings denied passes. Standalone helpers pass 33 report tests
(on Linux and Windows) and 22 workload tests. Line/branch coverage remains unmeasured.

Concrete RED→GREEN evidence includes stale-map enforcement under injected reader
failure, retired PID reuse and 513-row growth, actual heap-backed signal-stack
pivots (16 HIGH placements across eight signals → zero), failed/zero input and
successful-return span/expiry controls, partial `mprotect` ENOMEM effects, terminal
control injection, and rate-limited coverage notices. OS-thread wait regressions
first reproduced ECHILD/unrelated-child reaping and bounded concurrent-tracer
failure; `__WNOTHREAD` preserves independently owned outcomes without claiming
same-thread arbitrary-child safety.

The owned-child preflight had three intended failures before implementation;
policy knobs had four. New-file privacy reproduced mode 0666 under permissive
child umask, then 0600 with existing 0640 permissions preserved. Unrelated
in-flight compile failures were not counted as those behavior REDs.

Independent static review found inherited-target-directory stale packaging and
relative-sensor hash/execute identity mismatch. Actual same-version ELF canaries
failed both Debian and archive freshness checks before actual Cargo artifact paths
were selected. Package verification inspects before extraction, executes the
trusted self-built binary, validates positive/negative controls and reproduces
identical `.deb` bytes for fixed inputs/epoch. It does not install the package,
prove Kali compatibility, or certify cross-compiler reproducibility.

The first real Java control completed successfully while two handled SIGSEGV
delivery stops were incorrectly HIGH crash events. Global signal-outcome tests
reproduced that defect before the fix: delivery is INFO, and HIGH crash requires
confirmed terminal status. Fatal controls cover SEGV/ILL/BUS/ABRT/FPE and a worker
thread, with one terminal event per group and process-local core dumps disabled.
This is not a Java trust exclusion or a root-cause attestation.

Final five-pair [WSL service samples](benchmark-workloads-wsl.json) measured HTTP20
median 125.537→421.720 ms (3.359×) and SQLite200 564.563→1696.223 ms (3.004×).
Imports/startup/shutdown are included, with alternating order and no warmup.
The empirical five-sample p95 is the maximum sample, not a population tail estimate.
All ten traced workload runs completed with sensor/target 0 and no emitted events
or reported operational loss. [Runtime controls](runtime-controls-wsl.json):
Python clean; Node unavailable; Java target 0/sensor 1 with four HIGH RWX requests,
no emitted crash/CRITICAL records. Two INFO delivery events remain counted
internally but filtered by the default JSON reporting threshold. This is not zero
false positives or proof of complete coverage.

Captured sensor SHA256:
`6f038dbda437287511b7da0d65c9d85d21d37066aba6860d3e78b6f83a89939b`.
The artifacts retain raw samples/events, runner/source fingerprints, dirty capture
HEAD and before/after consistency checks. A source snapshot is not compiler
attestation. The historical 140.338× getpid result below is a different workload,
not a claimed before/after optimization.

Eight scoped missions were independently rerun and approved by a non-author
verifier: CORE, OPS, PACKAGE, EVENT-TRIAGE, WORKLOAD-EVIDENCE, WAIT-ISOLATION,
SIGNAL-OUTCOMES and PRIVATE-LOGS. Every machine acceptance check passed again;
audit head at that boundary: `c258de0676c50c99`. The independent artifact validator
also recomputed workload medians/outcomes and matched every source-input, runner
and sensor hash. Release qualification is a separate ninth gate, not inferred
from advisory output or these notes.

### Current delivery self-assessment

Accuracy **4/5**: real failures, current raw data and independent proofs, but map
snapshots are not atomic and native fleets remain unqualified. Completeness
**3/5** against the flagship ambition: focused investigation is substantially
improved; a low-overhead backend, official distro inclusion and production rollout
are future gated work. Clarity **4/5**: the quickstart routes detailed limitations
to guides, but there are several distinct counters/statuses. Actionability **4/5**:
usable local packages/workflows, with native VM install qualification still needed.
Conciseness **4/5**: meaningful regression detail is longer than a release summary.
Overall **3.8/5**. Highest-impact next work: native workload/kernel validation,
measured lower-overhead observation research, then disposable Debian/Kali install
qualification. The user should judge this as a maintained flagship foundation,
not a completed EDR, guaranteed valuation, or arbitrary performance multiplier.

## Baseline

The original revision `93a1473` passed 49 library tests, 5 CLI unit tests and
10 real-process integration tests on WSL2 Ubuntu, Linux x86-64 kernel
`5.15.167.4-microsoft-standard-WSL2`. Baseline Clippy initially could not run
because the component was absent; it was installed before release verification.

## Regression method

Core changes were driven by failing tests for named anonymous mapping classification,
non-executable kernel-label handling, full-span trust, trusted-origin chain isolation,
anonymous RX JIT policy, uncertain-map enforcement and memory lifecycle invalidation.
Tracer changes include a confirmed failing exec-replacement reproducer, worker-thread
exec, existing-worker attachment, actual entry-phase checks, detached-drop cleanup,
x32 rejection, and explicit unsupported launched group-stop handling. CLI regressions
cover JSON stream contamination, sink failures, target outcome visibility and conflicting
enforcement modes.

Commands:

```bash
WRAITH_REQUIRE_PTRACE=1 cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
bash scripts/verify.sh
bash demo.sh
python3 scripts/record_demo.py
python3 scripts/benchmark.py --iterations 20000 --samples 5
```

The six-case demo passed on WSL2 and the actual session was captured as
`docs/demo.svg` and `docs/demo.cast`. CLI RED executed all four new contract tests
and all failed for their intended assertions; the same target subsequently passed
all four. Commits `6910952` and `a07f620` preserve that RED/GREEN sequence.

The local getpid benchmark used 20,000 iterations and five samples. Median wall time:
**15.28 ms baseline vs 2,143.86 ms traced (140.34×)**. This intentionally syscall-heavy
WSL workload exposes ptrace cost; it is not a native-Linux service benchmark or a
claim of reduced overhead. [Raw samples](benchmark-wsl.json) are included. Quiet-path
name formatting and binary-search maps reduce user-space work, but do not remove
kernel stop/resume overhead.

Final local gates passed on both stable Rust and the declared MSRV, Rust 1.74.0:
**97 tests** (71 library, 5 CLI unit, 4 CLI subprocess, 16 real-process integration,
1 launched-job-control), with zero ignored tests in strict mode. Formatting and
Clippy with warnings denied passed on both toolchains. The repeated kill regression
includes 64 alternating single/worker-thread targets inside one integration test.

`bash scripts/verify.sh`, the six-case demo, offline docs checks, local sensor archive
checksum validation and full `cargo package --locked --allow-dirty` verification all
passed. Source-package verification rebuilt the packaged crate, not just its manifest.
Independent proof-gated review completed: `WRAITH-CORE-V2`, `WRAITH-DEMO-V2`
and `WRAITH-RELEASE-V2` were each rerun and approved by a separate verifier who
made no source edits. Their checks cover strict tests, Clippy, asserted demos,
docs, full release verification and rebuilt Cargo packaging. Board audit reported
an **intact 39-event chain**, head `4ffd6dba51ae0891`.

Original ticket checks used PowerShell quoting that the Windows board executor
interpreted as cmd.exe syntax. Those three records remain blocked with the
execution error preserved; quote-free V2 checks supersede them. No failed check
was relabeled as a pass or manually closed.

## Visual identity follow-up

The new [spectral identity](brand.md) uses generated source art, locally composed
typography and a lightweight GIF. The asset contract first failed on missing
banner files, then passed with static/GIF/social assets and reduced-motion markup.
The final GIF independently decoded as **47 frames, 46 distinct frames, 5.77 seconds,
289,626 bytes**. It is concept artwork, not a fabricated runtime demo.

Five standard-library Python regressions validate the real bundle, invalid PNG,
truncated GIF trailer/control blocks and removal of reduced-motion markup. They
now run alongside the unchanged **97 Rust tests** in `scripts/verify.sh`.
Local Chromium previews validated desktop/mobile aspect ratio, no horizontal
overflow, static selection under reduced motion and GIF selection otherwise.
These previews are local approximations; hosted GitHub behavior is checked after
publication rather than inferred from them. A separate verifier reran all three
`WRAITH-BRAND` acceptance commands and approved it (hash `2e1fda4e8881dd94`),
without authoring any implementation changes. That approval covers local assets
and release gates, not the subsequent Git push or hosted rendering.

The brand update was then pushed normally to `origin/main` at `c43a521`, with the
remote SHA matched to local HEAD. Hosted Chromium checks on the actual GitHub
repository confirmed the GIF loads by default, the PNG is selected under reduced
motion, and the mobile image retains its 3:1 aspect ratio. The [hosted CI run](https://github.com/grloper/Wraith/actions/runs/36801849681)
for that commit completed successfully, including the stable/MSRV matrix.
No GitHub release tag or external promotional post was created.

## RED/GREEN index

| Guarantee | Regression target | Observed RED → GREEN |
|---|---|---|
| Named-anonymous classification, trust-chain isolation, RX JIT and map uncertainty | `cargo test --lib` | 7 initial intended failures → passing library suite |
| Mmap hints and later writable protection regions | `cargo test --lib` | 2 intended failures → passing |
| `pkey_mprotect` and padded map parsing | `cargo test --lib` | 4 intended failures → passing |
| Effective page-rounded trust / conservative hugetlb mmap policy | `cargo test --lib` | 1 intended failure for each → passing |
| Default W→X WARN vs explicit strict policy | `cargo test --lib` | 1 intended failure → passing |
| Exec replacement and x32 refusal | library / real-process integration | SIGTRAP termination and accepted x32 RED → passing |
| JSON/output/outcome CLI contracts | `cargo test --test cli` | 4 failures → 4 passing |
| Launched job stop is not silently bypassed | `cargo test --test job_control` | clean exit 0 RED → explicit operational error GREEN |
| Kill drains queued stops while targets die | repeated single/worker kill integration | ESRCH at iteration 5 RED → all 64 iterations passing |

The kill race was also encountered during full release verification; it was not
ignored as a flaky test. The fix restricts death-race error tolerance to an
already-successful enforcement kill and leaves ordinary tracing errors intact.
Core/tracer RED evidence is preserved here because tests and fixes were developed
in shared working-tree scopes; the CLI/job-stop RED checkpoints are separate commits.

## Evidence boundaries

- WSL2 is one Linux environment, not a native fleet compatibility certification.
- This kernel does not support named-anonymous VMA naming in the live probe;
  the parser/policy regression tests exercise the newer-kernel map formats.
- No population-wide false-positive rate has been established.
- Line/branch coverage has not been measured; no 80% coverage claim is made.
- The original hardening delivery was local-only; the subsequent brand update was
  pushed to main and verified by hosted CI as described above. No versioned public
  release has been created.
- Release artifacts remain locally verified until the maintainer tags and validates them.
- Operator-visible job-control, unusual shared-mm and embedded-wait limitations remain
  documented in [operations](operations.md) and [the roadmap](roadmap.md).

## Delivery self-assessment

Accuracy **4/5**: real regression/build evidence, but native-fleet compatibility and
coverage percentages remain unmeasured. Completeness **3/5** against the broad request:
this is hardened focused monitoring, not a completed low-overhead EDR; publicity is a
prepared launch kit, not automatic external posting. Clarity **4/5**: explicit threat
model, with more operator detail than a quickstart needs. Actionability **4/5**: runnable
scripts and archive; GitHub settings/public release remain maintainer actions.
Conciseness **4/5**: README routes details to focused guides, but the evidence index
is necessarily longer. Overall **3.8/5**.

Highest-impact follow-ups: native-Linux runtime controls and benchmarks; successful,
allocation-scoped correlation; job-control/wait isolation and fault-injected cleanup.
These require substantive engineering, not documentation-only fixes. The user should
judge this as a verified hardening/release-preparation pass, not a guarantee of stars
or universally false-positive-free production protection.
