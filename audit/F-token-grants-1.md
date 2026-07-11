# F-token-grants-1: Token tables granted DELETE unnecessarily
- Severity: low
- Status: Verified-Fixed
- Area: db

## Summary
V14 granted `SELECT, INSERT, UPDATE, DELETE` on the single-use token tables to `cp_runtime`, but the
tables are single-use via UPDATE only — cp_runtime never DELETEs a token row.

## Impact
Excess privilege on the runtime role (least-privilege gap, mirrors the V12 write-once discipline).

## Remediation
V15 REVOKEs DELETE on `gateway_enrollment_token` and `session_signing_token` from `cp_runtime`.

## Evidence
`V15__mtls_fingerprint_pin_and_grants.sql` (REVOKE block).
