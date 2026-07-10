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
S2 delivered the structural boundary + the trigger and documented the role split as a follow-up. The standing
"no deferrals" directive brings the **role split forward — delivered this session (S3)**: migration
`V11__writer_role.sql` creates a **non-owner, non-superuser `cp_runtime` role** with CRUD on `config.*`/`runtime.*`
**except** `runtime.audit_event` (INSERT/SELECT only — parent + every partition), no CREATE/ownership/ALTER/DROP/
DISABLE TRIGGER, and reconciler-scoped grants. The **R2DBC runtime now connects as `cp_runtime`**
(`spring.r2dbc.username`) while **Flyway migrates as the owner** (`spring.flyway.user`). The append-only + schema
boundary now hold against a compromised app credential, not just the honest/ORM path. `V4` triggers remain the
role-independent DB guarantee (they stop even the table owner on a plain DML path).

## Evidence
- `WriterRoleIT`: as `cp_runtime`, DROP/ALTER, `ALTER TABLE ... DISABLE TRIGGER`, and UPDATE/DELETE of
  `audit_event` (parent + partition) are all refused; INSERT audit + normal CRUD elsewhere succeed.
- `AppendOnlyAuditIT`: the append-only trigger is proven via an **owner connection** (the restricted role is
  refused by privilege first), so both layers of the two-layer defense are demonstrated.
- `docs/DATA-MODEL.md` §13.2 documents the role, the grants, and the r2dbc-runtime / jdbc-flyway split.
</content>
