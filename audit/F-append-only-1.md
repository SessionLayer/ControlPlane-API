# F-append-only-1: audit_event immutability guarantee was overstated vs a compromised DB owner/superuser
- Severity: medium
- Status: Verified-Fixed
- Area: audit

## Summary
`docs/DATA-MODEL.md` §7 claimed audit-event immutability "does not depend on application discipline or a
writer role." Red-team (M1) + security-review (L2) showed that is false against the exact adversary the
control is for: the runtime connects as the table **owner** (dev/Testcontainers even as superuser), and an
owner can `ALTER TABLE … DISABLE TRIGGER`/`DROP`, while a superuser can `SET session_replication_role =
replica` to silence origin triggers — both reproduced against PG17. The trigger genuinely stops the honest /
ORM / normal-DML path (verified: `save()`-on-existing, `deleteById`, `TRUNCATE` all rejected), but not a
malicious owner.

## Impact
An operator trusting the wording would not add the role split, leaving audit tamperable by anyone holding the
over-privileged runtime DB credential — undermining the FR-AUD-9 / §15 "a compromised CP/admin can't alter a
recording" guarantee.

## Remediation
Doc corrected to **scope the guarantee precisely**: the trigger stops the honest/ORM path; the full guarantee
requires the runtime to connect as a **non-owner, non-superuser role granted only INSERT/SELECT** on
`runtime.audit_event`, plus reconciler-scoped schema grants for the config/runtime boundary — the S15/S16
deployment-hardening layer, now documented as an explicit follow-up (DATA-MODEL §7, RESULT §10). The
structural boundary + the trigger are delivered this session; the role split is scheduled for when the API
surface + reconciler land. `V4` triggers are `CREATE OR REPLACE` and cover UPDATE/DELETE/TRUNCATE.

## Evidence
- `docs/DATA-MODEL.md` §7 rewritten with the scope caveat + "do not run the runtime as owner/superuser".
- `AppendOnlyAuditIT` proves the ORM-path rejections (update/delete/truncate).
</content>
