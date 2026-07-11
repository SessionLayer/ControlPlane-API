# F-tls-version-1: TLS-1.2-only refusal was unasserted
- Severity: low
- Status: Verified-Fixed
- Area: mtls

## Summary
`MtlsServerContext` sets `protocols("TLSv1.3")` (TLS 1.3 only) but there was no negative test proving
a TLS-1.2 client is refused.

## Impact
Test gap — a regression that widened the accepted TLS versions could go uncaught.

## Remediation
Added `MtlsPlaneIT.tls12ClientIsRefused`: a TLS-1.2-only client fails the handshake even on the
bootstrap RPC (`UNAVAILABLE`/`INTERNAL`).

## Evidence
`MtlsTestSupport.tls12ClientContext`; `MtlsPlaneIT.tls12ClientIsRefused`.
