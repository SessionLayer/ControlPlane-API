# F-platform-scope-failopen-1: PlatformScopes.covers() failed open on a typo-d/non-object scope
- Severity: medium
- Status: Verified-Fixed
- Area: platform

## Summary
A `role_binding.scope` whose facet keys were unrecognized (typo) or whose JSON type was not an object silently widened
the binding to unrestricted, granting a scoped `recording:replay/export` globally.

## Fix
`covers()` now requires an object with at least one recognized facet, else it covers nothing (fail closed), mirroring
`LockMatching`. Unit test `PlatformScopesTest`.
