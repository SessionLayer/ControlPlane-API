# F-coldstart-doc-1: Stale cold-start ordering comment; cloud mtls seam unwired
- Severity: info
- Status: Verified-Fixed
- Area: docs

## Summary
The `CaConfiguration` cold-start comment claimed the ApplicationRunner is the first code to open an
R2DBC connection; the `GrpcMtlsServer` SmartLifecycle now opens R2DBC first (in `start()`). The
cloud internal-mTLS-CA backend seam is intentionally unwired this session (S4 scope: local KEK only).

## Impact
Documentation accuracy only; the invariant (first connection is post-Flyway, no eager pool
connections) still holds.

## Remediation
Corrected the ordering comment (I1). The cloud mtls-CA backend remains an intentionally-unwired seam
(local backend only in S4); it is exercised by unit tests and documented in the CA javadoc.

## Evidence
`CaConfiguration` cold-start ordering note.
