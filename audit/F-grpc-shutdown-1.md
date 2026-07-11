# F-grpc-shutdown-1: No force-close after drain; REST graceful shutdown off
- Severity: medium
- Status: Verified-Fixed
- Area: grpc

## Summary
`GrpcMtlsServer.stop()` did `shutdown()` + `awaitTermination(10s)` but never `shutdownNow()`, so RPCs
still in flight past the deadline were neither drained nor force-closed; the REST server had no
graceful-shutdown configured, and readiness did not flip before the drain.

## Impact
Shutdown could hang on stuck in-flight calls; connections could be cut mid-drain without the LB being
told to stop routing.

## Remediation
`stop()` flips `running`→false first (readiness → OUT_OF_SERVICE via F-grpc-health-1), drains for a
configurable `drainTimeout`, then `shutdownNow()` + a short second await, and shuts the handler pool.
`application.properties` adds `server.shutdown=graceful` + `spring.lifecycle.timeout-per-shutdown-phase`.

## Evidence
`GrpcMtlsServer.stop()`; `MtlsProperties.Server.drainTimeout`; `application.properties`.
