# F-audit-default-recovery-1: DEFAULT audit partition traps recovery if create-ahead lapses
- Severity: medium
- Status: Accepted-Risk
- Area: audit

## Summary
Reliability (R-AUD-2/R-AUD-4) notes: if create-ahead ever lapses and audit rows land in the
DEFAULT partition for month M, a later `audit_ensure_partition(M)` cannot create M's partition
(Postgres scans the default under ACCESS EXCLUSIVE and errors if any row belongs to M), and
`audit_prune_before`'s DETACH is non-concurrent (brief ACCESS EXCLUSIVE on the parent).

## Why Accepted-Risk (per §2.1 — bounded residual + operator runbook)
The append-only insert path never fails (the DEFAULT catches any range — the load-bearing
guarantee), and the new scheduled create-ahead (`AuditPartitionMaintenance`, F-audit-create-ahead-1)
keeps the DEFAULT empty in normal operation, so the trap is only reachable after the maintenance job
has been down for months. The full recovery (detach default → create the dated partition → move the
stragglers → re-attach) and running prune off-peak / with `DETACH ... CONCURRENTLY` are **operational
procedures**, not a code defect this session; wiring `DETACH CONCURRENTLY` + an alert on
`audit_event_default` row-count > 0 belongs with the retention/recording session (S9) that owns the
prune cadence.

## Residual + follow-up (operator / S9)
Runbook: alert when future-partition count drops below a threshold or DEFAULT has rows; document the
detach/recreate/move recovery; switch prune to `DETACH PARTITION ... CONCURRENTLY`. Documented in
RESULT §11.
