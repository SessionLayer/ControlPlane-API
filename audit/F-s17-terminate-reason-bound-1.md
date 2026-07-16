# F-s17-terminate-reason-bound-1: session-terminate reason bypassed the Lock deny-list size bound

- Severity: low
- Status: Verified-Fixed
- Area: config-api / lock-feed

## Summary
`POST /v1/sessions/{id}/terminate` persists its `reason` as an `AccessLock` reason, which the LockCodec puts
on the wire `Lock` (lock.proto field 5) and pushes to EVERY Gateway in the fleet-wide LockSnapshot. The
incident-lock path (`LockController.createLock`) bounds the reason via `LockIngestValidation.checkReason`
(`MAX_REASON_LENGTH = 4096`) precisely to stop a snapshot from inflating past a Gateway's gRPC/resync limits
(a self-DoS on the safety-critical deny channel). The terminate path skipped that bound — `TerminateSessionRequest.reason`
had no `maxLength`, so it was bounded only by the ~256KB codec limit (64× the intended cap). A privileged
`lock:write` operator could inflate the deny-list snapshot far more cheaply than the direct lock path allows.
(Red-team T3; LOW — needs `lock:write`, Gateways self-heal + expire locally, TTL-bounded.)

## Fix (Verified-Fixed)
1. Contract: `TerminateSessionRequest.reason` gains `maxLength: 4096` (a `400` at bean validation).
2. Defense-in-depth: `SessionManagementService.terminate` rejects a reason > 4096 chars pre-commit (`422`),
   matching `LockIngestValidation`'s bound behind the contract.

## Note (pre-existing, out of scope)
The red-team also observed the Lock `reason` is not stripped of control chars (a CRLF-log-injection vector into
whatever the Gateway logs) on BOTH the terminate path AND the pre-existing `LockController.createLock` (S10).
This is a platform-wide Lock-reason concern predating S17 (the reason is operator-log-only, never shown to the
SSH user); a shared log-sanitization fix belongs with the Lock ingest path, not this session's config surface.
