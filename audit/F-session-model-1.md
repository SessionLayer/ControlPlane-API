# F-session-model-1: session model missing break-glass linkage, live-session index, and end-reason
- Severity: low
- Status: Verified-Fixed
- Area: data-model

## Summary
Three related session-model gaps (divergence F-DM-3/F-DM-7, reliability M3): (1) `ssh_session` linked to
`jit_request` but had no `breakglass_activation_id` — asymmetric elevated-access modeling, and a break-glass
review (FR-ACC-6) could not enumerate the sessions an activation authorized; (2) "act on still-open sessions"
(quarantine-kill / graceful drain / concurrency counting — FR-NODE-3/FR-HA-7/FR-SESS-3) seq-scanned session
history (no `WHERE ended_at IS NULL` index); (3) no `end_reason` — how/why a session ended was unrecordable
except in free-text audit.

## Impact
Break-glass review is harder than JIT review; incident-time quarantine/drain queries slow as history grows;
terminal reason lost for forensics — all retrofits into the busiest runtime table if deferred.

## Remediation
- Added `ssh_session.breakglass_activation_id` FK → `breakglass_activation` (ON DELETE SET NULL), symmetric
  with `jit_request_id`, + index.
- Added partial index `idx_session_live ON ssh_session (node_id) WHERE ended_at IS NULL`.
- Added `ssh_session.end_reason text`.

## Evidence
- `V3__runtime_schema.sql`, `V5__indexes.sql`; `RuntimeRepositoryCrudIT.breakglassActivationCrud` asserts the link.
</content>
