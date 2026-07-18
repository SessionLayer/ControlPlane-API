# F-recording-prune-confirm-1: retention/governance delete marked pruned BEFORE confirming the object delete → false erasure + orphaned bytes
- Severity: medium
- Status: Verified-Fixed
- Area: recording

## Context (S23 red-team panel A4)

Both delete paths (`RecordingRetentionService.pruneOne` / `governanceDelete`)
atomically CLAIM the row (`pruned_at = now`, chosen to close the S18 legal-hold
TOCTOU — correct) and THEN call `recordingStore.deleteObject`. If the object delete
threw (transient 5xx / network / creds), the outer handler logged "retrying next
cycle" — but `recording_prunable` now excludes the row (`pruned_at IS NOT NULL`) and
`governanceDelete` returns a 204 no-op on retry, so the object delete was **never**
re-attempted: the encrypted bytes persisted while metadata/UI/audit asserted the
recording was erased. False GDPR-erasure attestation (FR-AUD-6) + a permanent
storage leak; no audit row on the failed attempt (only a log line).

## Root-cause fix

Keep the claim (hold-safety) but do not treat `pruned_at` as "erased" until the
object delete is confirmed: on a `deleteObject` error, a compensating `UNCLAIM`
UPDATE clears `pruned_at`/`delete_mode`/`deleted_by` so `recording_prunable`
re-selects the row next cycle (the re-claim re-asserts hold/compliance, so a hold
placed meanwhile still protects), the failed attempt is audited (`outcome=error`,
`reason=object_delete_failed`), and the error is re-raised so `governanceDelete` can
never return a false 204. (`RecordingRetentionService`: `UNCLAIM` + `unclaim(...)`
wired into both delete paths.)

## Regression test

`RecordingStoreSeamTest.aFailedObjectDeleteRollsBackTheClaimAndAuditsTheFailure` — a
`RecordingStore` double whose `deleteObject` fails: `governanceDelete` surfaces the
error (no false success), audits the failure with `outcome=error`, and issues the
compensating UNCLAIM (a second `db.sql`) so the row is re-selectable.
