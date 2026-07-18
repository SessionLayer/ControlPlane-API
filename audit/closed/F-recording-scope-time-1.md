# F-recording-scope-time-1: recording:replay/export time-scope checked against wall-clock, not session time (over-broad within the window)
- Severity: medium
- Status: Verified-Fixed
- Area: recording

## Context (S23 red-team panel A4)

`RecordingAccessService.authorizeAndIssue` built the replay/export authorization
scope with `new PlatformScope(labels, session.identity(), Instant.now())` — the time
facet was evaluated against the wall-clock at request time. For the SAME stored
`role_binding` time scope, `audit:read` filters by event time (`occurred_at`,
`AuditSearchSql`) — which events — but `recording:replay/export` gated by "when the
auditor clicks". An auditor granted "replay scoped to the incident window" could,
*during* that window, replay a recording of a session from ANY date (node-label/user
still checked, but date wasn't). Over-permissive in the allow direction and
inconsistent with audit-search for the identical scope object (FR-PADM-2; the S18
scope-consistency intent).

## Root-cause fix

Evaluate the time facet against the session's time, matching audit-search's
`occurred_at`: `new PlatformScope(labels, session.identity(), session.startedAt())`.

## Regression test

`RecordingStoreSeamTest.replayScopeTimeIsTheSessionTimeNotWallClock` — captures the
`PlatformScope` passed to `PlatformAuthorization.authorize` for a session started 90
days ago and asserts `scope.at()` equals the session start, not ~now.
