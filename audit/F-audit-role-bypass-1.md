# F-audit-role-bypass-1: restricted role could erase/damage crown-jewel data via SECURITY DEFINER + PUBLIC EXECUTE
- Severity: high
- Status: Verified-Fixed
- Area: audit

## Summary
Two independent reviews (security F2/F3, reliability R-AUD-3) found the writer-role
hardening (F-append-only-1) had a hole: Postgres grants `EXECUTE` to `PUBLIC` by default,
and V11 additionally granted `cp_runtime` EXECUTE on `audit_prune_before` — a SECURITY
DEFINER function that `DETACH`+`DROP`s audit partitions. Partition DROP is DDL, which the
append-only trigger cannot stop, so a compromised app credential (the exact adversary the
hardening exists for) could run `SELECT runtime.audit_prune_before(now())` and **erase
whole audit months**. Relatedly (F4), `ALTER DEFAULT PRIVILEGES` gave `cp_runtime` full
CRUD on `ca_key_material` (crown-jewel wrapped CA key) — DELETE/UPDATE would cause a CA
outage or (with F-ca-kek-1) key substitution. F7: `audit_ensure_partitions` had no
`num_months` cap (catalog-bloat DoS).

## Remediation (Verified-Fixed)
- `V11`: `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA runtime, config FROM PUBLIC`, then GRANT
  EXECUTE to `cp_runtime` only on the safe functions (`is_ip_or_cidr`, `recording_prunable`,
  and the non-destructive create-ahead `audit_ensure_partition(s)`). `audit_prune_before`
  (partition DROP) is **deliberately not granted** — retention is an owner/maintenance
  operation. `ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` locks
  future functions by default.
- `V12`: `REVOKE UPDATE, DELETE, TRUNCATE ON runtime.ca_key_material FROM cp_runtime` + GRANT
  INSERT/SELECT + a write-once trigger (rotation writes a new row; a row is never mutated).
- `V7`: `audit_ensure_partitions` rejects `num_months` outside `[0, 60]`.

## Dedicated gate
`WriterRoleIT`: `cp_runtime` is refused `audit_prune_before` and `ca_key_material`
UPDATE/DELETE, but create-ahead succeeds. `AuditPartitioningIT` now runs prune via an OWNER
connection. Verified on a live PG17 run.
