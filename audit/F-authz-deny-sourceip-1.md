# F-authz-deny-sourceip-1: A source-scoped deny was suppressed when the source IP was unknown/out-of-range (fail-open)
- Severity: high
- Status: Verified-Fixed
- Area: authz

## Summary
`DenyOverridesPolicyEngine.applies()` gated ALL rules through the source-IP reducer, so a `deny` rule carrying a
`source_ip_condition` was dropped when the source IP was unknown/blank/out-of-range — a deny-overrides bypass and a
FR-AUTH-15 violation (source IP became positive evidence, removing a block). Flagged by two independent reviewers.

## Fix
The source-IP reducer now gates ALLOWs only; a deny applies on identity AND node-label regardless of source (deny must
fail closed, Design §8.4). Regression test `sourceScopedDenyAppliesRegardlessOfSource` (null / out-of-range / in-range
source all keep the deny).
