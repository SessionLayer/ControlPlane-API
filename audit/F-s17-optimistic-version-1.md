# F-s17-optimistic-version-1: optional update `version` allowed a silent lost update

- Severity: medium
- Status: Verified-Fixed
- Area: config-api

## Summary
`version` on every `UpdateXRequest` was optional; `requireVersion` no-opped when null, and a PUT is a full
replacement — so two version-less concurrent edits silently lost one (last-writer-wins, no 409). Reference
admin APIs (Boundary, K8s resourceVersion) require the version on update.

## Fix (Verified-Fixed)
Made `version` REQUIRED on all nine `UpdateXRequest` schemas (frozen contract). A PUT omitting it is now a
`400` at bean validation; a mismatch is a `409`; a match proceeds — proper optimistic concurrency, no silent
lost update. The CRUD ITs already round-trip the version, so they pass unchanged.
