# F-authz-cap-granular-deny-1: No per-capability deny primitive (AND-of-denies is by omission)
- Severity: low
- Status: Accepted-Risk
- Area: authz

## Summary
The model cannot forbid a single capability while allowing the session; capability removal is by omission
(default-deny-per-capability).

## Justification
Deliberate design. The DecisionContext wire contract is a flat capability set (no per-login/per-capability deny), and
after F-authz-cap-bleed-1 a capability is granted only if a grant FOR THE CHOSEN LOGIN permits it — the denied-by-all-
omission reading of FR-AUTHZ-6 "AND-of-denies". A capability-subtraction primitive is a possible future addition, not
required by FR-AUTHZ-6.
