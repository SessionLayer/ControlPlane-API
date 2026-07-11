# F-lock-group-facet-1: A lock could not target an SSO/OIDC group
- Severity: low
- Status: Verified-Fixed
- Area: authz

## Summary
§8.3 lists group-like lock attributes and identity selectors match by group, but a lock could only target
identity/node/principal/node_label.

## Fix
Added a `group` lock facet (matched against the request groups, threaded into `LockSubject`). Test `lockCanTargetAGroup`.
Role-target locks remain a future facet (see F-lock-ingest-validation-1 / lock-create session).
