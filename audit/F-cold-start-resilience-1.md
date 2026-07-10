# F-cold-start-resilience-1: cold-start boot resilience + rotation incoming-uniqueness
- Severity: high
- Status: Verified-Fixed
- Area: reliability

## Summary
Reliability review found operability hazards in cold start and rotation:
- **R-COLD-1/HIGH:** `pg_advisory_xact_lock` + `.block()` had no timeout. A wedged peer holding
  the lock (or a stalled connection) would block boot indefinitely — the ApplicationRunner runs
  before `ApplicationReadyEvent`, so the pod would sit liveness-UP/readiness-DOWN forever with no
  self-heal.
- **R-COLD-2/MEDIUM:** the advisory lock was taken on every boot before the idempotency check,
  so all restarts serialized needlessly.
- **R-ROT-2/MEDIUM:** no uniqueness guard on `incoming` per kind — two concurrent/retried
  `beginRotation` calls create two `incoming` CAs; `promote` picks one arbitrarily and leaves the
  other trusted (incoming is in the trusted set) forever, with no lifecycle to remove it.

## Remediation (Verified-Fixed)
- `caColdStartRunner` blocks with a bounded timeout (`sessionlayer.coldstart.timeout-seconds`,
  default 60) so a stuck cold start CRASHES the boot (orchestrator-healable) rather than hanging.
- `provisionAll` is double-checked: a cheap lock-free existence probe first, and the advisory
  lock is taken (with `SET LOCAL lock_timeout = '15s'`) only when provisioning is actually needed.
- `V13` adds `uq_ca_config_incoming_per_kind` (partial unique on `rotation_state='incoming'`),
  mirroring the active-per-kind index, so a rotation cannot start twice.

## Dedicated gate
`ColdStartIT` (startup provisioning, idempotent re-run does no lock work, concurrent race-safe),
`CaLifecycleIT` (rotation overlap-then-drain keeps trust continuous). Verified on live PG17.
