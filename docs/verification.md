# Verification evidence

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
