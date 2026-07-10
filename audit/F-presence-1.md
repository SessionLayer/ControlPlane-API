# F-presence-1: presence ownership nonce had no monotonic guard
- Severity: medium
- Status: Verified-Fixed
- Area: presence

## Summary
`presence.nonce` is the anti-stale-ownership fencing token (§10.2/§10.3, FR-HA-2/FR-HA-5), but nothing
prevented a write that *lowered* it — the `@Version` lock guards a lost update, not a stale-value write. The
directly analogous generation counter got both `@Version` and a DB monotonic trigger; presence got neither.
Flagged independently by all three of red-team, reliability (M1), and divergence (F-DM-1).

## Impact
In HA, a stale/duplicated Gateway that read `nonce=6`, lost ownership to `nonce=7`, then wrote its cached
`nonce=6` could re-steal a node — a split-brain routing hazard; routing (fail-closed on stale nonce, §10.3) is
then fed a stale owner → misrouted / hung SSH handshakes.

## Remediation
Added a `BEFORE UPDATE` trigger `runtime.enforce_presence_nonce_monotonic()` rejecting `NEW.nonce < OLD.nonce`,
mirroring the generation-counter guard.

## Evidence
- `V4__triggers.sql` (`presence_nonce_monotonic`); `GenerationCounterIT.presenceNonceIsMonotonic`.
</content>
