# F-s17-reads-behind-write-1: config reads are gated behind write permissions (no read-only least-privilege)

- Severity: medium
- Status: Accepted-Risk
- Area: rbac / config-api

## Summary
Reading several config collections requires the WRITE permission: node/capability/jit reads need
`settings:write`, `cas` reads need `ca:manage`, `service-accounts` reads need `user:manage`, break-glass reads
need `breakglass:manage`. So an auditor cannot be granted read-only visibility of that config without also
gaining write. Reference APIs (Teleport/Boundary/K8s) have per-resource read verbs.

## Justification (Accepted-Risk)
This is a DELIBERATE consequence of the S17 decision to gate every resource within FR-PADM-1's **closed
16-permission vocabulary** and add NO new permissions (the SESSION's open-value choice). `rbac:read` and
`audit:read` cover the RBAC/session/audit reads; the remaining config families have no dedicated `*:read`
verb, so read maps to the management permission. Adding fine-grained `*:read` verbs is a vocabulary expansion
(a `platform_role.permissions` CHECK migration + bootstrap-role update) that is out of this session's scope
and is cleanly additive. **Recommended for a future session:** introduce `settings:read`/`ca:read`/
`user:read`/`breakglass:read` and re-gate the reads. No security bypass — the current gating is strictly MORE
restrictive (write implies read), never less.
