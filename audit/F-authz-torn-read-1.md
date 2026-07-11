# F-authz-torn-read-1: Grants and locks read without a consistent snapshot
- Severity: low
- Status: Verified-Fixed
- Area: authz

## Summary
Grants and locks were read via concurrent `Mono.zip` (no snapshot ordering), so a concurrently-committed deny/lock could
be missed while an allow from the same edit was honored (a §8.4 read-layer fail-open at scale).

## Fix
Grants are read first, then locks, so the lock set is observed at a snapshot no earlier than the grants — deny stays
dominant (a lock committed before the grant read is always seen).
