# F-exposure-1: Handshake gRPC plane runs plaintext without authentication (Session One)
- Severity: low
- Status: Accepted-Risk
- Area: exposure

## Summary
The CP↔Gateway `Handshake` plane runs over PLAINTEXT gRPC with no channel authentication this
session. mTLS channel auth + per-RPC session-bound authorization are Session Four scope (Design §15,
FR-BOOT-3).

## Impact
An on-host caller can invoke `Handshake.Negotiate` unauthenticated. The RPC is a pure, stateless
version-negotiation function carrying no secrets and echoing only data already public via
`/v1/version`, so the exposure is diagnostic-only. The server is bound to loopback (see F-grpc-1),
limiting reach to the same host.

## Remediation
Accepted for Session One (dev-only smoke). Session Four replaces the plaintext channel with mTLS and
adds per-RPC session-bound authorization; the plaintext dev port is removed then.

## Evidence
- `contracts/proto/.../handshake.proto` SECURITY note; `HandshakeService.java` class javadoc;
  `application.properties` gRPC block (loopback bind, plaintext).
