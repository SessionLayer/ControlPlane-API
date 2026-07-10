# F-audit-search-1: FR-AUD-8 "search by node label" had no column or index
- Severity: medium
- Status: Verified-Fixed
- Area: audit

## Summary
FR-AUD-8 requires auditors to search by node **label**. `audit_event` stored `node_id` but no labels; labels
lived only in mutable `node.resolved_labels`. Because `audit_event` is immortal and nodes can be relabeled or
removed, a label-scoped historical audit search was not just un-indexed — it was impossible (reliability M4).

## Impact
A common auditor query ("all access to prod-db-labeled nodes last quarter") could not be answered from the
audit trail.

## Remediation
Added `audit_event.node_labels jsonb` (a label snapshot captured at write time, `CHECK jsonb_typeof='object'`)
+ a GIN index `idx_audit_node_labels`, matching the existing capabilities-snapshot treatment. The writer (S9 /
Gateway) populates it.

## Evidence
- `V3__runtime_schema.sql` (`audit_event.node_labels`), `V5__indexes.sql` (`idx_audit_node_labels`).
- `AppendOnlyAuditIT.sampleEvent` round-trips `node_labels`; entity `AuditEvent` maps it.
</content>
