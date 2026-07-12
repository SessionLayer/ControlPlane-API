# F-jit-revoke-lock-1: JIT revoke emitted a permanent node-wide + identity-wide Lock (fleet outage)
- Severity: high
- Status: Verified-Fixed
- Area: jit

## Summary
`JitLifecycleService.revoke` wrote an `access_lock` whose target selector was
`{identities:[requester], node_ids:[targetNode]}` with `ttl=null`/`expiresAt=null`. `LockMatching`
OR-matches facets, so the lock denied (a) the requester on EVERY node AND (b) EVERY user on the
target node — permanently. One revoke of a single JIT grant caused a fleet-wide (for that identity)
and node-wide (for everyone) access outage that never auto-cleared.

## Impact
Availability, HIGH. An operator revoking one JIT grant would silently lock out every other user of the
target node until an admin manually located and deleted the lock. No security bypass (deny is the safe
direction), but a self-inflicted outage primitive.

## Fix
`revokeSelector` now emits `{identities:[requester]}` ONLY — the node facet is dropped. The lock is
given a BOUNDED TTL from the new `sessionlayer.jit.revoke-lock-ttl` (default 120s): its only job is to
tear down the LIVE session (S10), after which it auto-clears; the terminal REVOKED state is what blocks
re-authorization. Regression test `JitLifecycleIT.revokeWritesABoundedIdentityScopedLockThatDoesNotBlockOtherUsers`
asserts, via `LockMatching.matches`, that the lock denies the revoked identity but NOT a different user
on the same node, that it carries no `node_ids` facet, and that it is time-bounded.

## Residual (accepted)
The lock briefly (the propagation window) tears down the revoked identity's OTHER live sessions too.
Precise single-session targeting would require a session-id facet on `LockTarget` — a future contract
enhancement. The teardown window is short and the blast radius is one identity, not the node/fleet.
