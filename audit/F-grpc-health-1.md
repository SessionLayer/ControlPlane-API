# F-grpc-health-1: gRPC-plane liveness not reflected in readiness
- Severity: low
- Status: Verified-Fixed
- Area: ops

## Summary
A live JVM whose self-managed mTLS gRPC listener was down would still read healthy — the gRPC plane
had no health/readiness contributor.

## Impact
Operability: an LB could route to a CP whose gRPC listener is not accepting connections.

## Remediation
Added `GrpcMtlsServerHealthIndicator`: UP when disabled or listening, OUT_OF_SERVICE when
enabled-but-not-running (including during the graceful-shutdown drain). Detail is not exposed
(`show-details=never`). (A failed start already crashes the boot fail-closed.)

## Evidence
`mtls/GrpcMtlsServerHealthIndicator.java`.
