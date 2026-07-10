# F-db-password-1: cp_runtime password is one-shot (placeholder), no in-app rotation, dev default
- Severity: medium
- Status: Accepted-Risk
- Area: reliability

## Summary
Security (F5) + reliability (R-WR-1/R-WR-2): the `cp_runtime` login password is set once by V11
from the Flyway placeholder (`ALTER ROLE ... PASSWORD '${cpRuntimePassword}'`) and must equal
`spring.r2dbc.password`; changing the placeholder later does not rotate it (V11 won't re-run); the
literal could be logged by `log_statement=ddl`; and the dev default `cp_runtime` ships in the config
with no fail-closed guard (unlike the KEK).

## Why Accepted-Risk (per §2.1 — bounded residual + operator procedure)
The blast radius is small by construction: `cp_runtime` is the **restricted** role delivered this
session — INSERT/SELECT-only on `audit_event`, no DDL, no `audit_prune_before`, no `ca_key_material`
UPDATE/DELETE — so a leaked/weak DB password cannot erase audit, alter schema, or damage CA material.
Unlike the KEK (which protects the CA key at rest), the DB password is an authentication credential
whose damage is capped by the grants. Setting/rotating a DB role password is inherently an out-of-band
operator action (an `ALTER ROLE` + a rolling `spring.r2dbc.password` update); a checksummed migration
literal is the wrong place for it. Fixing this "in app" (e.g. a startup fail-closed on the dev password)
would break local dev the same way the KEK guard does, for a much smaller residual.

## Residual + follow-up (operator)
Documented in `application.properties` + RESULT §11: set both the placeholder and `spring.r2dbc.password`
to the same real secret (alphanumeric, no quote/backslash) before first boot; rotate via owner
`ALTER ROLE` + rolling pod restart; the placeholder is first-migration-only.
