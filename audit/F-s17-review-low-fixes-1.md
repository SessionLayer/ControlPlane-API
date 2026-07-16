# F-s17-review-low-fixes-1: three LOW T3 fixes (rotate atomicity, idempotency best-effort, terminate TTL)

- Severity: low
- Status: Verified-Fixed
- Area: config-api / reliability

## Summary + Fix (all Verified-Fixed)
1. **CA rotate audit not atomic** — `CaConfigService.rotate` audited in a THIRD transaction after
   `beginRotation`/`promote` each committed in their own; a rotation could stand unaudited. Fixed: the
   begin/promote/find-active/audit chain now runs in one `tx.transactional(...)` (the inner CaRotationService
   txs join it, REQUIRED) + a `DataIntegrityViolationException → 409` for a concurrent-rotation race.
2. **Idempotency store failure → 500 for a committed mutation** — `IdempotencyService` now wraps the record
   store in `onErrorResume` (log + continue): the record is best-effort (a retry re-executes rather than
   replays), so a store failure never fails an already-successful mutation.
3. **Session-terminate lock TTL too short (60s)** — a Gateway disconnected for the whole window missed the
   teardown on resync. Now configurable (`sessionlayer.session.terminate-lock-ttl`, default 5m) — long enough
   to survive a brief reconnect, short enough to release the identity afterwards.
