# F-merkle-anchor-1: Audit hash-chain head is not externally anchored (Merkle root spec-deferred)

- Severity: low
- Status: Accepted-Risk
- Area: audit

The `audit_event` tamper-evidence hash chain detects any content mutation or interior removal/reorder, but the chain head lives in the same Postgres as the data, so a full-chain rewrite by the append path or a DB superuser (after dropping the append-only trigger) re-verifies clean — there is no external anchor. This is on par with / slightly better than Teleport's audit tamper-evidence and weaker than a published-digest ledger (QLDB/Trillian).

**Justification:** the externally-anchored Merkle root is SPEC-DEFERRED (FR-AUD-10 / Design D34); hash-chain + WORM is the documented baseline. This is a spec non-goal for S18, not a skip.

**Follow-up (recommended, low-cost down-payment):** we already run a WORM object store the platform cannot rewrite — periodically anchor the audit chain head into it (a signed, timestamped head object under object-lock), giving a partial FR-AUD-10 guarantee (tail-truncation + full-rewrite detection) before the full external Merkle anchor lands.
