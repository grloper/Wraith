# Contributing to Wraith

Useful contributions are reproducible, scoped and honest about their evidence.

## Local setup

Use Linux x86-64 (WSL2 is suitable), Rust 1.74+, Python 3 and a C compiler for
integration fixtures. Work on a branch; keep `Cargo.lock` committed.

```bash
cargo build --locked
bash scripts/verify.sh
bash demo.sh
```

`WRAITH_REQUIRE_PTRACE=1` makes unavailable tracing fail the test suite. Without
strict mode, restricted environments may skip some ptrace tests; a green result
there is not end-to-end evidence. Never change system-wide Yama policy just to
make tests pass. Prefer child-process tracing in a dedicated development VM.

## Optional local hook

After reviewing `.githooks/pre-commit`, opt in on Linux:

```bash
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

The hook runs the same strict checks as CI; installation is not automatic. On
Windows, run verification through WSL instead of pretending native tracing works.

## A good pull request

1. Describe one observable failure or improvement.
2. Add a regression first; show that it fails for the intended reason.
3. Apply the smallest fix and show the regression passing.
4. Run formatting, Clippy, full tests and the local demo.
5. Explain compatibility, benign-workload effects and remaining blind spots.

Do not claim an attack is detected solely because a HIGH event appeared. Assert
the origin, severity and actual side effect for enforcement. New trust policies
need tests for **both** tolerated legitimate execution and untrusted execution.
New syscall rules need arguments, boundary values and failed-call behavior.

Never include real credentials, customer memory, private process arguments or
weaponized samples in fixtures. Use self-contained local simulations. Do not
post vulnerabilities in public issues; see [SECURITY.md](SECURITY.md).

## Where to start

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Research and design trade-offs](docs/research.md)
- [Scoped roadmap](docs/roadmap.md)

A false-positive report should include the Wraith version, kernel, invocation,
minimal benign reproducer and redacted events. A performance report should include
baseline and traced timings, sample count, workload and hardware—not only a ratio.

## CI maintainer identity

The Debian package gate requires a real maintainer contact. CI reads the
repository variables `DEBEMAIL` (required) and `DEBFULLNAME` (defaults to
`grloper`), set under Settings > Secrets and variables > Actions > Variables.
For local runs, export `DEBEMAIL` and `DEBFULLNAME` before `scripts/verify.sh`.
