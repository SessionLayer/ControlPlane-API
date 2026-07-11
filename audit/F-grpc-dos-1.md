# F-grpc-dos-1: No server-side DoS bounds on the self-managed mTLS gRPC server
- Severity: medium
- Status: Verified-Fixed
- Area: grpc

## Summary
The self-managed grpc-netty server set no `maxConcurrentCallsPerConnection`, `maxInboundMessageSize`,
`maxInboundMetadataSize`, keepalive-ping or connection age/idle limits, and used the default
executor. With the (former) pre-token CSR PoP verify, an unauthenticated peer could flood
`EnrollGateway` with valid CSRs and drive unbounded CPU/threads.

## Impact
Resource exhaustion / DoS of the CP↔Gateway plane by an unauthenticated peer.

## Remediation
`NettyServerBuilder` now sets small message/metadata caps (64 KiB / 16 KiB — the plane carries only
tiny control messages), `maxConcurrentCallsPerConnection`, `permitKeepAliveTime` +
`permitKeepAliveWithoutCalls(false)`, `maxConnectionAge(+Grace)`/`maxConnectionIdle`, and a bounded
handler executor; the CPU-bound crypto additionally runs on `Schedulers.boundedElastic` (F-crypto-eventloop-1).
The F-enroll-oracle-1 token-first reorder removes the pre-auth CSR-verify amplification. TLS handshake
timeout + config are retained. All bounds are configurable under `sessionlayer.mtls.server.*`.

## Evidence
`GrpcMtlsServer.start()`; `MtlsProperties.Server` (new bound fields).
