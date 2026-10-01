# Launch kit

These are drafts for the maintainer to publish. No external posts, paid ads,
release tags or star requests have been sent automatically.

## One-line hook

**Injected code can change its bytes. It still has to execute somewhere.**

## GitHub description

Linux x86-64 syscall provenance sensor in Rust: inspect suspicious executable
memory, correlate runtime signals, and reproduce detection with local demos.

Suggested topics: `rust`, `linux`, `ptrace`, `runtime-security`, `syscall`,
`security-research`, `exploit-detection`, `observability`.

## Short announcement

I built Wraith, a dependency-light Rust sensor that asks where a Linux syscall
came from—not whether a payload matches a signature. It monitors a selected
process tree, reports JSONL evidence, and offers opt-in syscall blocking.

The repo includes a runnable benign-vs-injected-code demo, worker-thread coverage,
and explicit JIT/ROP limitations. It is not a full EDR or a zero-false-positive
claim. I'd especially value benign-runtime reproducers and real workload overhead
measurements: https://github.com/grloper/Wraith

## 60-second walkthrough

1. **0–10s:** introduce the spectral identity, then explain syscall provenance;
   the animated hero is concept artwork, not live telemetry.
2. **10–25s:** run the benign control; show no detections.
3. **25–40s:** run the local RWX simulator; explain origin plus correlation.
4. **40–50s:** show `--block` returning `-ENOSYS` while the fixture survives.
5. **50–60s:** state JIT/ROP and ptrace-cost limitations; invite reproducers.

Use `bash demo.sh` and `python3 scripts/record_demo.py`. The portfolio-ready
[PNG preview](social-preview.png) uses the new generated spectral artwork;
regenerate with `python3 scripts/render_brand.py` only if Pillow is already
installed (optional, not a sensor dependency). See [art direction and accessibility](brand.md). Publish the actual recording,
not a staged dashboard as if it were a live capture. A simulator demonstrates
observable behavior, not a CVE exploitation success rate.

## Resume wording

> Built a Linux x86-64 runtime security sensor in Rust using ptrace and syscall
> provenance; implemented bounded successful-outcome correlation, explicit coverage
> loss, per-thread stack/lifecycle handling and opt-in enforcement. Added private
> JSONL evidence, strict bounded triage, Debian packaging, real-process regressions
> and independently reviewed workload measurements.

Only add measured test counts, performance improvements or coverage percentages
from the revision you actually shipped. Do not claim kernel-module/eBPF work:
that backend is not implemented. Explain the signal-versus-proof trade-off in interviews.

## Responsible community outreach

Start with one technical write-up covering a concrete bug and its regression.
Share in communities that permit project posts, disclose authorship, answer
technical questions, and request critique rather than stars. Do not mass-post,
use fake testimonials, manipulate engagement or imply adoption that has not happened.

## Before announcing

- Run strict Linux verification and the demo on the intended release revision.
- Review [operator risks](operations.md) and [the threat model](threat-model.md).
- Confirm GitHub private security reporting and branch protections are enabled.
- Review release artifacts/checksums before manually creating a version tag.
- Link real CI evidence; distinguish local WSL verification from hosted CI.
