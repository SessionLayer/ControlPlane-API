# F-audit-ip-eventloop-1: blocking DNS on the reactive event loop via the source-IP validator

- Severity: medium
- Status: Verified-Fixed
- Area: audit

## Summary

`Cidrs.address` (the FR-AUTH-15 source-IP reducer's parser, and — via the S20
`auditableIp` guard — every `Authorize`) used `InetAddress.getByName`.
`Cidrs.isNumericLiteral` admits `[0-9a-fA-F.:]`, so hex-ish non-literals
(`"dead.beef"`, `"cafe"`) passed the guard but are not valid IP literals →
`getByName` performed a BLOCKING OS/DNS lookup on the calling R2DBC/Netty worker
thread. With the audit backfill this ran on every allow/deny/break-glass decision,
synchronously inside the reactive `flatMap`. Because `source_ip` is
Gateway-asserted, a misbehaving/compromised Gateway could induce event-loop
starvation (same class as the already-fixed F-crypto-eventloop-1).

## Fix

`Cidrs.address` now uses `InetAddress.ofLiteral` (JDK 22+), which parses an IP
literal with NO name lookup and throws `IllegalArgumentException` in
sub-millisecond time for a non-literal. Valid literals parse unchanged, so the
FR-AUTH-15 reducer's semantics are preserved; only the blocking-DNS-on-junk
behaviour is removed. The audit path additionally moved to a dedicated
non-resolving validator (`AuditSourceIp`, see F-audit-ip-inet-abbrev-1), so it no
longer touches `Cidrs` at all.

## Verification

`CidrsTest`, `SelectorsTest`, and `PolicyEnginePropertyTest` stay green (they use
valid literals + non-hex hostnames, so no test encoded `getByName`'s DNS
leniency). `AuditSourceIpTest` proves the audit validator is non-resolving.
