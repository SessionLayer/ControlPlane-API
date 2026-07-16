# F-s17-audit-beforeafter-1: Config mutations did not audit before/after state (FR-PADM-3)

- Severity: high
- Status: Verified-Fixed
- Area: audit / config-api

## Summary
FR-PADM-3 requires every platform action be audited "with actor/before-after/timestamp". The S17 config
CRUD services audited only `{action, name}` — no before/after value — so an update/delete recorded THAT it
happened but not WHAT changed. Combined with hard-delete + no config history, a prior/deleted config was
unrecoverable AND unauditable.

## Fix (Verified-Fixed)
`AuditWriter.recordChange(actor, subject, action, detail, before, after)` serializes before/after into the
audit `detail` jsonb (create → after only; delete → before only; update → both), reusing the same
hash-chained, transactional insert. Every config service's create/update/delete now calls it — before is the
loaded existing entity (update) or the found row (delete), after is the saved entity. Values are secret-free
(config exposes references, never key material). See F-s17-role-cascade-audit-1 for the role-delete cascade.
