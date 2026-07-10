# F-audit-retention-1: audit_event has no retention/prune path (not partitioned)
- Severity: high
- Status: Deferred
- Area: audit

## Summary
`audit_event` is append-only (DELETE/TRUNCATE trigger-blocked) and a single unpartitioned heap, so there is no
path to ever expire audit rows for FR-AUD-6 operator-configured retention (defaults ≥12 months) — pruning
would require dropping the immutability trigger and a bloating bulk `DELETE` (reliability H1). The agent notes
range-partitioning is far cheaper to adopt while the table is empty.

## Decision: DEFERRED to the retention/recording session (S9-area), with rationale
This is a legitimate design consideration but **not a defect in S2's deliverable**, and is deliberately
out of scope this session:
1. **No operational risk now** — the table is empty; there are no writers until later sessions; retention is
   not an S2 feature. Nothing can fill or overflow it in S2.
2. **Retention is FR-AUD-6**, an operator-configured feature owned by the recording/retention session, which
   also introduces `retention_until`/`legal_hold` (see F-model-deferrals-1). Partitioning belongs with that work.
3. **Partitioning is not a free win** — a `PARTITION BY RANGE (occurred_at)` table forces the partition key
   into every unique constraint, so the PK becomes composite `(id, occurred_at)`, degrading the clean
   `findById(uuid)` R2DBC ergonomics that every later session builds on. That trade-off deserves a deliberate
   decision, not a reflexive one.
4. It is cleanly addable later via expand/contract (a partitioned table + data migration, or pg_partman) when
   retention is actually implemented — the append-only + clean-UUID-PK design is preserved for the interim.

Prominently flagged for the retention session in RESULT.md §10. Because the status is Deferred (not Open), it
does not block the ROUND_FINAL gate.
</content>
