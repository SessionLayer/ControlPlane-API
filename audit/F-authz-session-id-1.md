# F-authz-session-id-1: Gateway-supplied session_id is the ssh_session primary key
- Severity: low
- Status: Accepted-Risk
- Area: authz

## Summary
The caller-allocated session_id becomes the ssh_session PK; a collision (retry/malicious) fails the INSERT.

## Justification
By design (the decision context + token bind to the Gateway-allocated session id for correlation). A collision is
fail-closed (INSERT conflict → rollback → deny; the orphan single-use token expires unused in 120s). An existsById
pre-check would add a TOCTOU race without benefit.
