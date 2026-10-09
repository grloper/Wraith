# Security policy

Wraith inspects untrusted processes and can optionally interrupt them. Treat the
sensor, its trust ranges and its event destination as part of your security boundary.

## Reporting

Do not disclose an unpatched bypass, memory-safety issue or destructive enforcement
bug in a public issue. Report it privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a vulnerability**
([direct link](https://github.com/grloper/Wraith/security/advisories/new)). This
creates a private security advisory visible only to you and the maintainers.

If that page is unavailable, open a public issue that asks for a private channel and
contains no exploit details. No response-time or bounty guarantee is offered.

Include the affected revision, Linux kernel, minimal safe reproducer, expected
behavior, actual behavior and proposed regression. Do not send secrets or live
customer data. Only test systems you own or are authorized to assess.

## Support and limitations

This is a pre-1.0 Linux x86-64 project; security fixes target the current main branch.
There is no LTS branch or enterprise support commitment. Read the
[threat model](docs/threat-model.md) and [operator guide](docs/operations.md).

Observe-only is the default. A CRITICAL verdict is a policy decision, not forensic
proof. Use enforcement only after validating a representative legitimate workload.
Do not run with unrestricted root privileges merely for convenience; attaching
requires ownership, applicable Yama permission, or appropriately scoped tracing
capabilities. Store JSONL evidence with permissions suitable for process metadata.
