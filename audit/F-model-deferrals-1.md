# F-model-deferrals-1: divergence "note-for-later-session" model gaps
- Severity: low
- Status: Verified-Fixed
- Area: data-model

## Summary
The S2 divergence review surfaced model elements that §12A implies but that S2 recorded for a later session.
The standing "no deferrals" directive brings them forward; the schema is **added this session (S3)** (additive
migrations + entities + repos + round-trip/constraint/schema-presence tests). Where a shape is intentionally
flexible it is kept jsonb and the decision is documented (a decision, not a defer).

## Remediation (S3)
- **F-DM-9 operator-settings / bootstrap** → `config.operator_settings` singleton (`V6`): KEK ref, default CA
  backend, retention/WORM/OTP/session-limit defaults, FR-BOOT-2 bootstrap self-disable flag. Cold start reads it.
- **F-DM-5 policy_epoch source** → `config.policy_epoch` singleton (`V10`), monotonic (decrease trigger-rejected).
- **F-DM-8 session limits + concurrency** → `config.session_limit_policy` (`V10`) + `runtime.session_lease`
  (`V9`, per-identity concurrency lease; semaphore is S7).
- **F-DM-10/11 recording retention/status/digest** → `recording_ref.retention_until`/`legal_hold`/`status`/
  `format`/`content_digest` (`V8`) + `recording_prunable` helper (compliance/legal-hold never prunable).
- **F-DM-12 service-account credential** → `runtime.service_account_credential` (`V9`); hash/reference only.
- **F-DM-13 device-flow entity** → `runtime.device_flow` (`V9`); hashes + 1:1 connection binding (§15).
- **F-DM-14 enrollment host-key storage** → `runtime.node_host_key` (`V9`, FR-CONN-5, never TOFU); public material.
- **F-DM-15 status-transition reason/actor** → `status_reason`/`status_changed_by`/`status_changed_at` on
  `node`/`agent_identity`/`gateway_identity`, `decided_by`/`decision_reason` on `jit_request` (`V10`).
- **F-DM-16 JIT `approvals` shape** → kept jsonb (documented `{approver,level,decision,reason,at}`; approver-queue
  index + self-approval invariant remain S11) — a deliberate decision (DATA-MODEL §13.4).

## Confirmed correct-as-is (no change)
- **F-DM-17** — `dp_rule` has no priority/order column: deliberate (Design §6.1 order-independent deny-overrides).
- **F-DM-18** — capability sets as `text[]`, selectors as `jsonb`: matches the read-whole-row reference camp.

## Dedicated gate
`ModelGapSchemaIT`: a schema-presence assertion fails if any expected new table/column is missing, and each new
table/column round-trips + enforces its key constraints (singleton uniqueness, policy-epoch monotonicity, content
guards). Documented in `docs/DATA-MODEL.md` §13.3.
