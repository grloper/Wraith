## What changed

Explain the observable behavior and why it matters.

## Evidence

- [ ] Regression fails before the fix for the intended reason
- [ ] `bash scripts/verify.sh` passes on Linux x86-64 with real ptrace
- [ ] `bash demo.sh` passes when detection/enforcement changes
- [ ] Benign behavior and trust boundaries are tested
- [ ] Threat model/operator docs updated where applicable

Include commands, environment and actual results. Mark anything not run explicitly.

## Risk and compatibility

Describe API/CLI changes, false-positive trade-offs, enforcement effects and rollback.
