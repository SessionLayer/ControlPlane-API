# F-jit-review-lows-1: JIT/break-glass low-severity review items (consolidated)
- Severity: low
- Status: Verified-Fixed
- Area: jit

## Summary
The consolidated low-severity findings from the S13 review panel, all fixed in one pass. (Low items do
not gate; recorded for completeness.)

## L5 — node-existence oracle on JIT submit (Verified-Fixed)
`submit` returned two distinct messages ("unknown target node" vs "no JIT policy governs this target")
and has no permission gate, letting an authenticated caller enumerate node existence. Both now return
ONE generic client message ("target is not available for JIT access"); the specific reason is kept
server-side in a `jit.requested` outcome=denied audit note (`unknown_node` / `no_policy`).

## L6 — sweep batch abort (Verified-Fixed)
`expireOverdue` tolerated only `OptimisticLockingFailureException`; any other per-row error aborted the
whole sweep. Each row is now wrapped in `onErrorResume(Throwable → log the id + contribute 0)` so one
bad row never aborts the batch.

## L7 — revoke idempotency (Verified-Fixed)
`revoke` had no `@Version`-race handling → a concurrent revoke gave one caller an unmapped 500. It now
`onErrorResume(OptimisticLockingFailureException → re-read)`: if already REVOKED it returns the row
idempotently, else `NOT_REVOCABLE`.

## L8 — missing audit on rejection paths (Verified-Fixed)
The `ALREADY_ACTED` and `NOT_PENDING` approve/deny rejections were not audited (unlike self-approval /
not-an-approver). All four rejection paths now emit a `jit.approve` outcome=denied audit (FR-AUD-7
consistency).

## L9 — scheduler pool starvation (Verified-Fixed)
`JitExpiryScheduler` blocked the default size-1 scheduling pool (shared with audit-partition /
auth-maintenance) and capped the sweep at 30s (aborting a large sweep every cycle). Added
`spring.task.scheduling.pool.size=2` and removed the 30s `.block()` timeout so a large sweep runs to
completion.

## L10 — grant-TTL fail-open on a GC'd policy (Verified-Fixed)
`grantTtlFromPolicy` re-read the policy at approval and fell back to the MAX cluster ceiling when the
policy had been deleted — the BROADEST grant. The effective `max_ttl` is now SNAPSHOTTED at submit
(new `jit_request.policy_max_ttl_seconds` column via V20 ALTER, consistent with the already-snapshotted
chain) and used at approval; a mid-flight policy edit/delete can neither widen nor fail-open the grant.

## L11 — findUsableGrant nondeterminism (Verified-Fixed)
`findUsableGrant` used `.next()` on an unordered flux (arbitrary grant). It now `.sort(...)` by earliest
`grant_expires_at` for a deterministic choice. (The `matchingPolicy` first-by-name shadowing and the
HA N×-sweep are noted as S14 scale items in RESULT — no code change.)

## F4 (hardening) — break-glass strict recording keyed on access model (Verified-Fixed)
`RecordingRegistrationService` now re-asserts a usable customer key for a break-glass session keyed on
`access_model==breakglass` directly (re-validating via `CustomerPublicKeys.isValid`), not on the dead
`publicKey==null` guard, so a future best-effort recording path can never regress break-glass
strictness. Redundant today (recording is always fail-closed to the key) by design.
