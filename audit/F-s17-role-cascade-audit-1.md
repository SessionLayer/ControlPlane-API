# F-s17-role-cascade-audit-1: role delete cascaded bindings silently (unaudited)

- Severity: medium
- Status: Verified-Fixed
- Area: audit / rbac

## Summary
`role_binding.role_id` is `ON DELETE CASCADE` (V2), so `DELETE /v1/roles/{id}` silently revokes every binding
referencing the role while only the parent `role.delete` was audited (empty detail) — the cascade (a real
authorization change) left no trail.

## Fix (Verified-Fixed)
`RoleConfigService.delete` now loads the role AND its bindings (`RoleBindingRepository.findByRoleId`) before
deleting, and records the role before-state plus the cascaded binding ids (`detail.cascaded_bindings`) in the
audit — so the cascade is fully auditable (FR-PADM-3).
