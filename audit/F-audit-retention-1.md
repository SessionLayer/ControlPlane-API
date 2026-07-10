# F-audit-retention-1: audit_event has no retention/prune path (not partitioned)
- Severity: high
- Status: Verified-Fixed
- Area: audit

## Summary
`audit_event` was an append-only single unpartitioned heap, so there was no path to expire audit rows for
FR-AUD-6 operator-configured retention (defaults ≥ 12 months) — pruning would have required dropping the
immutability trigger and a bloating bulk `DELETE`. S2 deferred this to the retention session; the standing
"no deferrals" directive brings it forward and it is **fixed this session (S3)**.

## Remediation (S3)
Migration `V7__audit_partitioning.sql` recreates `runtime.audit_event` as **`PARTITION BY RANGE (occurred_at)`**
with composite PK `(id, occurred_at)` (Postgres requires the partition key in the PK). The V4 append-only
trigger, the `seq` identity and the V5 indexes/GINs are re-established on the parent; a DEFAULT partition
guarantees an append-only insert never fails for a missing range. Retention is by **dropping whole partitions**
(`audit_prune_before(cutoff)` → DETACH + DROP), so it never fights the append-only trigger (no per-row DELETE);
the window comes from `operator_settings.audit_retention_days` (default 365, ≥ 12 months). Create-ahead is
`audit_ensure_partition(s)` (SECURITY DEFINER so the restricted runtime role can pre-create without DDL rights).
The R2DBC mapping keeps a single logical `@Id id` (globally unique by UUIDv7; the table is insert-only), so the
clean `findById(uuid)` ergonomics are preserved.

## Dedicated gate
`AuditPartitioningIT`: rows route to the correct monthly partitions; `audit_prune_before` DETACH+DROPs old
partitions while in-window rows survive; `findById`/insert/the append-only trigger still work on the partitioned
table; and a legal-hold / compliance recording is never returned by `recording_prunable` (FR-AUD-6). Documented
in `docs/DATA-MODEL.md` §13.1.
