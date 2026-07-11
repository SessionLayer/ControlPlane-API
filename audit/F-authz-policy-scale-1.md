# F-authz-policy-scale-1: Full grant/lock/role/binding load per decision (O(n))
- Severity: low
- Status: Accepted-Risk
- Area: authz

## Summary
The evaluator loads the full dp_rule/access_lock (and role/binding) sets on every decision.

## Justification
Inherent to "the decision is a pure function of the grant SET" (the order-independence/determinism property, FR-AUTHZ-3).
Correct now; the mitigation is an epoch-keyed in-memory snapshot cache (policy_epoch is already read) — a scale-session
optimization, not a correctness defect.
