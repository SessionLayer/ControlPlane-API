# F-ci-1: Audit-gate finding parser tolerates malformed front-matter (fail-open)
- Severity: info
- Status: Accepted-Risk
- Area: ci

## Summary
`scripts/gate.sh` extracts Severity/Status by stripping to letters and exact-matching. A finding file
with a decorated line (e.g. `Status: Open (blocked on X)`) would not match `open` and would be
silently skipped rather than counted as an open medium+ finding.

## Impact
Dormant: all finding files in this repo are authored in the exact documented front-matter format, and
the format is a fixed convention a parent hook also depends on. A hand-written file with an off-format
severity/status line could bypass the gate.

## Remediation
Accepted for now — the front-matter format is the prompt-specified contract and is honoured by every
finding here. A future hardening can anchor the regex to the allowed enum and treat a non-matching
Severity/Status line as a hard parse error (fail-closed), consistent with the platform's fail-closed
ethos.

## Evidence
- `scripts/gate.sh` findings-check loop.
