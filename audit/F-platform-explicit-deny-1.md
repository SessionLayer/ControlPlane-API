# F-platform-explicit-deny-1: Platform RBAC is additive-only (no deny bindings)
- Severity: low
- Status: Accepted-Risk
- Area: platform

## Summary
The platform engine cannot express an explicit deny binding (K8s-RBAC style, additive-only).

## Justification
Satisfies FR-PADM (default-deny + granular permissions + scope). Explicit deny bindings are a future
segregation-of-duty feature, not required by FR-PADM-1/3.
