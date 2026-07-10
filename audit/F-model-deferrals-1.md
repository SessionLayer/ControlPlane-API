# F-model-deferrals-1: divergence "note-for-later-session" model gaps (explicit deferrals)
- Severity: low
- Status: Deferred
- Area: data-model

## Summary
The divergence review (vs Teleport/Boundary/StrongDM) surfaced model elements that §12A implies but that are
correctly owned by a later session, not S2. Recorded here so each divergence is a **decision, not an
accident**. All are Deferred (not Open); each has a target session and is listed in RESULT.md §10.

- **F-DM-5 — `policy_epoch` source of truth** (→ S5): `ssh_session`/`audit_event` snapshot the epoch, but no
  config-side counter/sequence produces it. S5 defines the authoritative epoch (global vs per-selector).
- **F-DM-8 — per-session limits + HA concurrency semaphore** (→ S7): FR-SESS-3 max-duration/idle/concurrency
  have no home column, and a cluster-wide concurrency cap needs a lease/semaphore primitive.
- **F-DM-9 — operator settings / cluster-config entity + first-admin bootstrap flag** (→ S3/S6): `settings:write`
  guards a resource that doesn't exist yet (retention/WORM defaults, OTP TTL, FR-BOOT-2 bootstrap-self-disable flag).
- **F-DM-10/11 — recording retention/legal-hold + status/format/digest** (→ S9): `recording_ref` has `worm_mode`
  but no `retain_until`/`legal_hold` (FR-AUD-6) nor `status`/`format`/`digest` (finalized-vs-truncated, NFR-6).
- **F-DM-12 — runtime service-account credential table** (→ S6): `service_account` is the definition;
  issued-credential rotation/revocation state (FR-AUTH-12) needs a runtime table (hash + revoked).
- **F-DM-13 — device-flow runtime entity** (→ S6): §13/FR-API-2 list `device-flow`; RFC 8628 state + the 1:1
  device_code↔connection anti-phishing binding (§5.2/§15) need persisting.
- **F-DM-14 — enrollment-time verified host key/cert storage** (→ node-lifecycle session): FR-CONN-5 "never
  TOFU" needs a persisted per-node host identity; `node.name` must not be overloaded for it.
- **F-DM-15 — revocation/quarantine reason/actor/timestamp** (→ later): identity/node status transitions carry
  no `*_reason`/`*_by`; currently recoverable only from `audit_event` (documented as acceptable).
- **F-DM-16 — JIT `approvals` element shape + approver-queue index** (→ S11): document the
  `{approver,level,decision,reason,at}` shape and reserve a GIN index or child table if the approver-queue hot.

## Confirmed correct-as-is (no change)
- **F-DM-17** — `dp_rule` has no priority/order column: deliberate (Design §6.1 order-independent deny-overrides).
- **F-DM-18** — capability sets as `text[]`, selectors as `jsonb`: matches the reference read-whole-row camp;
  S5 pins the multi-value label model.
</content>
