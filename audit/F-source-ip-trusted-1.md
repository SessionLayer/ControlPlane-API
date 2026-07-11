# F-source-ip-trusted-1: Resolved identity/groups/source-ip are Gateway-asserted
- Severity: info
- Status: Accepted-Risk
- Area: authz

## Summary
The Authorize request carries a resolved identity/groups/source-ip supplied by the (mTLS-authenticated) Gateway.

## Justification
Per SESSION §1.2, S5 takes a resolved identity as input (test-supplied); S6 makes it authenticated (OIDC/OTP/pins,
FR-AUTH-8) and should derive source IP from a trusted transport signal (PROXY protocol v2, FR-AUTH-14). The Gateway is
the authenticated PEP and a lockable principal (S4). Documented S6 hand-off (RESULT §10).
