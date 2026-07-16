# F-audit-scope-bypass-1: Degenerate role_binding scope let a scoped audit:read auditor read out-of-scope events by id (search/get divergence)

- Severity: medium
- Status: Verified-Fixed
- Area: security

`AuditSearchSql` (search) required a NON-EMPTY effective AND-list, but `PlatformScopes.covers` (the single-event GET matcher) only required that some recognized facet KEY be present and treated a present-but-degenerate facet as UNRESTRICTED. So a scope like `{"node_labels":{}}` (which a UI clearing a label field could emit) matched NOTHING in search yet covered EVERYTHING on `GET /v1/audit-events/{id}` — a scoped auditor saw an empty, correct-looking search UI but could read ANY audit event (identities, actions, session/node ids, config before/after) by iterating ids. Silent, invisible in the search surface.

**Fix (Verified-Fixed, f83a520):** `PlatformScopes.covers` now requires at least one EFFECTIVE recognized facet and fails closed on a present-but-degenerate/unrecognized-only scope — mirroring `AuditSearchSql` exactly, so search and get can never diverge. Defense in depth: `PlatformScopes.isValid` + `RoleBindingConfigService` reject a degenerate scope at write time (422), so it can never be stored. Regression tests in `PlatformScopesTest` + `AuditEventSearchIT` (search returns nothing AND get returns 404, they agree).
