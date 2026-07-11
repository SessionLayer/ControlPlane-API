# F-crypto-eventloop-1: CPU crypto ran on the R2DBC/Reactor event loop
- Severity: medium
- Status: Verified-Fixed
- Area: perf

## Summary
KEK-unwrap and X.509 / OpenSSH certificate signing ran inline on the reactive event loop, violating
the CLAUDE.md no-blocking-on-event-loop rule; under load these CPU-bound steps stall the event loop
and every reactive RPC.

## Impact
Event-loop starvation / latency amplification under concurrent enroll/renew/sign.

## Remediation
The signing/issuance steps are offloaded with `Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())`
in enroll, renew, and sign; the gRPC handler pool is also bounded (F-grpc-dos-1).

## Evidence
`GatewayEnrollmentService.issue`, `GatewayRenewalService.renewFor`, `SessionCertificateService.sign`.
