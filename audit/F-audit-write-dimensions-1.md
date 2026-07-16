# F-audit-write-dimensions-1: Five FR-AUD-8/9 search dimensions are read-side-complete but unpopulated by the current write path

- Severity: medium
- Status: Accepted-Risk
- Area: audit

The S18 audit search + RBAC-scope filter fully support all FR-AUD-8 dimensions — the `audit_event` columns (`source_ip`, `access_model`, `capabilities`, `node_labels`, `correlation_id`), their indexes, the `AuditSearchSql` predicates, and the `AuditScopeMatcher` all exist and are proven end-to-end by ITs that seed rows carrying those columns. **But no current writer populates them:** the S9 append signature `record(actor, subject, action, outcome, sessionId, nodeId, detail)` sets only actor/subject/action/outcome/session_id/node_id/occurred_at, so in production those five columns are NULL. Consequences (noted by the divergence review): (a) a filter on an unwired dimension returns a silent-empty page — a false-negative in an audit tool; (b) a node-label-SCOPED `audit:read` grant matches zero rows (labels are always null), so label-scoping is currently inert (user- and time-scoping DO work — actor/subject/occurred_at are populated); (c) the FR-AUD-9 approve→connect→run→replay path stitches only by `session_id` (in-session events), not `correlation_id`.

**Justification (not a defer):** the READ contract is complete, correct, and stable — this is purely upstream data population, and S18 is scoped to the read side (the write side / recorder is S9/Gateway, explicitly unchanged per SESSION §0). Enriching the CP audit-write path is a bounded change that does not alter this read contract.

**Follow-up (committed, next session):** add an enriched append overload and snapshot `source_ip`/`access_model`/`capabilities`/`node_labels` on the session-establishment audit written by the connect/authorize path (`ConnectAuthorizationService`), and thread a `correlation_id` across the approve→session boundary — which makes label-scoping and the correlated-path example fully functional. Documented in the `AuditEventController` javadoc; RESULT §7 states the FR-AUD-8/9 claim honestly.
