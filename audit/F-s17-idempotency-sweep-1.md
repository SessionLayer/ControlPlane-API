# F-s17-idempotency-sweep-1: idempotency-key store was unbounded (no sweeper)

- Severity: medium
- Status: Verified-Fixed
- Area: reliability / config-api

## Summary
`runtime.idempotency_key` gained a row per mutating request with an `Idempotency-Key`; nothing deleted them
(the upsert reclaims a row only on same-key reuse after expiry ≈ never). The V22 migration comment claimed a
"background sweep" that did not exist — months of traffic → unbounded table/index bloat, autovacuum + disk
pressure, degrading quietly (a 3am failure mode).

## Fix (Verified-Fixed)
Added `DELETE FROM runtime.idempotency_key WHERE expires_at < now()` to `AuthMaintenanceService.PRUNES`
(runs on startup + hourly, best-effort, never fatal). The store is now genuinely bounded by its TTL and the
V22 comment is accurate.
