# F-grpc-timeout-1: mTLS RPC handlers had no server deadline or cancel propagation
- Severity: medium
- Status: Verified-Fixed
- Area: grpc

## Summary
The gRPC handlers subscribed the reactive services with no `.timeout()` and no cancel handler. A DB
failover / saturated R2DBC pool hung every mTLS RPC indefinitely, and a client cancel leaked the
in-flight subscription.

## Impact
Availability: a slow/failed datastore hangs all identity/signing RPCs; cancelled calls leak work.

## Remediation
A shared `ReactiveBridge.forward` applies a configurable server-side deadline
(`sessionlayer.mtls.rpc-timeout`, default 15s) mapping timeout to `DEADLINE_EXCEEDED`, and registers
`ServerCallStreamObserver.setOnCancelHandler` to dispose the subscription on client cancel.

## Evidence
`grpc/ReactiveBridge.java`; `GatewayIdentityService`, `SessionSigningService`; `GrpcErrors` maps
`TimeoutException` → `DEADLINE_EXCEEDED`.
