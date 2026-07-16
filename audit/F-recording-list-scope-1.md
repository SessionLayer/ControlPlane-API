# F-recording-list-scope-1: Recording list/get use the unscoped gate (a scoped-only auditor cannot discover its in-scope recordings)

- Severity: low
- Status: Accepted-Risk
- Area: security

`GET /v1/recordings` (list) and `GET /{id}` gate on the UNSCOPED `recording:replay` (`PlatformAccess.withPermission`, null scope), so only an unscoped `recording:replay` holder passes; a caller holding only a SCOPED `recording:replay` (a first-class FR-PADM-2 persona) is 403'd on list/get and has no API path to enumerate the recordings within their own scope (they can still replay a specific in-scope id). This is strictly more restrictive (no data leak) but inconsistent with the audit search, which IS scope-filtered.

**Justification:** fail-closed and safe (a scoped-only holder sees less, never more); the frozen contract documents list/get as `recording:replay`-gated. Scope-filtered discovery is a usability enhancement, not a security requirement.

**Follow-up:** make list/get scope-FILTERED (reuse the audit search's `resolveScopeGrant` result-filter model over the recording's node-labels/user/time) so a scoped auditor sees its in-scope subset.
