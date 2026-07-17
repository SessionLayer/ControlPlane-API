# F-audit-ip-inet-abbrev-1: source-IP validator accepts abbreviated IPv4 that Postgres ::inet rejects, losing the deny audit row

- Severity: low
- Status: Verified-Fixed
- Area: audit

## Summary

`Cidrs.isAddress` (used by the S20 `auditableIp` guard) accepted abbreviated /
integer / leading-zero IPv4 that `InetAddress` parses inet_aton-style but the
`source_ip` column CHECK (`runtime.is_ip_or_cidr` == `::inet`) REJECTS —
empirically `"16909060"`, `"1.2.3"`, `"127.1"`, `"010.0.0.1"`. The allow path was
already safe (the raw token/session writers carry the same CHECK and run BEFORE
the audit insert in the same transaction, failing there first). But on the DENY
path `auditableIp` returned the bogus non-null value → the best-effort decision-log
INSERT violated the CHECK → the failure was swallowed by `onErrorResume` → the
deny audit ROW WAS LOST (an FR-AUD-7 gap for crafted, Gateway-asserted input).

## Fix

The audit path now uses a dedicated strict, non-resolving validator
(`AuditSourceIp.isCanonicalLiteral`) that matches `::inet` exactly: a canonical
dotted-quad IPv4 (four `0-255` octets, no leading zeros, no integer/abbreviated
forms) or a valid IPv6 literal (parsed via `InetAddress.ofLiteral`, no DNS). A
value `::inet` would reject is dropped to NULL on the column (kept verbatim in the
`detail` jsonb, which has no CHECK, for forensics), so the audit INSERT always
succeeds and the row is never lost. `Cidrs` (the FR-AUTH-15 reducer) is
deliberately NOT tightened, so canonical Gateway IPs and existing token/activation
writers are unaffected.

## Verification

`AuditSourceIpTest` (27 cases) pins the accept/reject boundary against the exact
`::inet` forms. `AuthorizeIT.denyWithNonInetSourceIpStillWritesTheDecisionRow`
drives a real Authorize deny with `source_ip="16909060"` and asserts the denied
decision row IS written with `source_ip = NULL` (dropped) and the raw value
retained in `detail` — proving the row is no longer lost.
