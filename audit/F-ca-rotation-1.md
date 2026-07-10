# F-ca-rotation-1: ca_config UNIQUE(ca_kind) blocked the FR-CA-7 rotation overlap
- Severity: medium
- Status: Verified-Fixed
- Area: ca

## Summary
`config.ca_config.ca_kind` was `UNIQUE`, allowing exactly one row per CA kind (divergence F-DM-2). FR-CA-7
requires CA rotation *without fleet downtime* — the outgoing + incoming CA keys must be trusted simultaneously
during the overlap (Teleport models this as `active_keys` + `additional_trusted_keys`). The unique constraint
made that impossible and forced an atomic key swap (a downtime window).

## Impact
S3 would hit the constraint when implementing zero-downtime rotation and have to drop a UNIQUE (a schema
contract change). Baking in the atomic-swap shape is a lesson-not-yet-paid-for.

## Remediation
- Dropped `UNIQUE(ca_kind)`; added `name text NOT NULL UNIQUE` (stable key) and `rotation_state`
  (`incoming|active|outgoing|expired`, default `active`).
- Added a **partial unique index** `uq_ca_config_active_per_kind ON ca_config (ca_kind) WHERE
  rotation_state='active'` — a kind may have several rows during overlap, exactly one active. S3 owns the
  rotation state machine.
- Repository: `findByCaKind` returns `Flux`; added `findByCaKindAndRotationState` (the active one) + `findByName`.

## Evidence
- `V2__config_schema.sql` (`ca_config`), `V5__indexes.sql` (`uq_ca_config_active_per_kind`).
- `ConfigRepositoryCrudIT.caConfigRotationOverlapOneActivePerKind`.
</content>
