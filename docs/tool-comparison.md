# Where Wraith fits in Linux security

Wraith is a **target-process syscall-origin sensor** for Linux x86-64 investigations.
It does not discover network assets, scan files for malware, attest file-backed code,
or provide a fleet-wide EDR. Different tools answer different questions; there is
no evidence here that Wraith is generally faster, safer or more valuable than them.

## Primary-source comparison

| Tool | Main question / mechanism | Relationship to Wraith |
|---|---|---|
| [Nmap](https://www.kali.org/tools/nmap/) | Which network hosts/services are exposed? Network probes and replies. | Network exposure inventory is separate from runtime origin evidence in an authorized target reproduction. |
| [ClamAV](https://www.kali.org/tools/clamav/) | Does content match malware detections? File/content scanning. | Inspect explicitly collected artifacts. [Configured on-access prevention](https://docs.clamav.net/manual/OnAccess.html) exists; do not claim antivirus tools never prevent execution/access. |
| [YARA](https://www.kali.org/tools/yara/) | Does a file or process memory match a rule? [Content matching](https://yara.readthedocs.io/en/latest/commandline.html). | Correlate content matches with runtime evidence; rule matching alone is not Wraith's syscall-origin policy. |
| [strace](https://strace.io/) | Which syscalls/signals occur, with which arguments/results? ptrace debugging. | Compare separate reproductions. The [ptrace restrictions](https://man7.org/linux/man-pages/man2/ptrace.2.html) preclude promising simultaneous independent attachment to one thread. |
| [auditd](https://github.com/linux-audit/audit-userspace) | What auditable host operations happened? Linux audit subsystem. | Supplies broader host context, not a general origin-aware blocking policy. |
| [osquery](https://osquery.readthedocs.io/en/stable/) | What does the OS inventory/event data show? SQL tables and configurable subscribers. | [Process auditing](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/) can add user/package/process context. Not universal prevention. |
| [Falco](https://falco.org/docs/concepts/event-sources/kernel/) | Which runtime events match behavioral rules? Kernel events through documented drivers/eBPF. | Broad detection can guide a focused reproduction. Its [security policy](https://github.com/falcosecurity/falco/security/policy) distinguishes detection/notification from enforcement. |
| [Tetragon](https://tetragon.io/docs/concepts/enforcement/) | Which runtime operations should be observed or constrained? eBPF policies/kernel hooks. | Supports return overrides and signals under hook/policy constraints. It is incorrect to claim eBPF security tools categorically cannot enforce. |
| [Tracee](https://aquasecurity.github.io/tracee/latest/) | Which runtime activity/behavior is suspicious? eBPF collection and detections. | Broader activity and context complement focused provenance investigation; no universal blocking guarantee or performance equivalence is established here. |

Nmap, ClamAV and YARA have official Kali tool pages. Kali package trackers document
[strace](https://pkg.kali.org/pkg/strace) and [audit](https://pkg.kali.org/pkg/audit).
Catalog/repository presence does **not** prove a tool is preinstalled in every image.
This research did not confirm official Kali availability of osquery, Falco,
Tetragon or Tracee; they are listed as external Linux alternatives, not asserted
Kali packages. No competitor was installed or benchmarked by this comparison.

## Practical differentiation

The useful question is: **“Where did this target's syscall instruction execute,
and what memory/protection evidence accompanied it?”** A small owned-process
investigation can reproduce that evidence without deploying a whole-host agent.
That is a narrower proposition than antivirus, vulnerability discovery or EDR.

Promising uses are minimized fuzz-case reproduction, JIT/custom-stack baseline
investigation, and explainable suspicious-memory triage in a disposable lab VM.
Wraith is instrumentation, not the isolation boundary. See [workflows](workflows.md)
for preserving sensor status and validating evidence instead of treating an empty
JSON stream as a clean bill of health.

## A .deb is not official Kali inclusion

A locally built Debian binary package is a distribution mechanism. Kali's
[submission guide](https://www.kali.org/docs/tools/submitting-tools/) and
[tool-selection policy](https://www.kali.org/docs/policy/penetration-testing-tools-policy/)
require maintainer review, licensing/dependency information and differentiation.
Debian has its own [new-package process](https://www.debian.org/doc/manuals/developers-reference/ch05.en).

The package needs a supported architecture/kernel, compatible ELF dependencies,
permissions documentation, maintained tests and releases. Installation/extraction
on WSL Ubuntu is not a Kali VM compatibility test, official archive acceptance,
a signed repository, or a supply-chain certification. No such claim is made.
