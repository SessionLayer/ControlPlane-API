# F-audit-chain-1: audit_event hash chain had no deterministic total order
- Severity: medium
- Status: Verified-Fixed
- Area: audit

## Summary
The S9 hash chain will link `audit_event` rows by content (`prev_hash`/`record_hash`), but the table ordered
only by UUIDv7 `id` — which is time-*ordered* but not a gapless total order: intra-millisecond ties are random
and concurrent HA CP writers can both read the same head and fork the chain (red-team M3, divergence F-DM-6).

## Impact
S9 would either serialize all audit writes application-side or retrofit a sequence into an append-only,
already-populated hottest table — exactly the rewrite the reserved-columns approach was meant to avoid.

## Remediation
Added **`seq bigint GENERATED ALWAYS AS IDENTITY`** + a UNIQUE index — a DB-assigned monotonic ordinal giving
the chain a single well-defined predecessor and gap/fork detection. `GENERATED ALWAYS` so the app can never
set it; it is intentionally **not mapped** by the ORM (omitted from INSERT, Postgres assigns it). Free to add
now while the table is empty.

## Evidence
- `V3__runtime_schema.sql` (`audit_event.seq`), `V5__indexes.sql` (`uq_audit_seq`).
- `MigrationIntegrityIT` (schema shape); DB probe confirmed seq monotonic + distinct.
</content>
