# F-worm-objectlock-verify-1: pre-existing WORM bucket object-lock config was trusted, never verified
- Severity: low
- Status: Verified-Fixed
- Area: recording

## Context (S23 red-team panel A4)

`WormObjectStore.ensureBucketBlocking` created a bucket with object-lock enabled but
for an EXISTING (operator-created) bucket "assumed correctly configured". A bucket
without object-lock/versioning would silently downgrade WORM immutability. The
security property already fails **closed** per-upload (an object-lock-header PUT to a
non-lock bucket is rejected by S3 → recording marked failed), so it was never
silently-unprotected — but the misconfiguration surfaced per-upload at Tier-0 rather
than at startup.

## Root-cause fix

`verifyObjectLockEnabled(bucket)` on the existing-bucket path: `GetObjectLockConfiguration`
→ if the config is definitively missing (`ObjectLockConfigurationNotFoundError`) or
`objectLockEnabled != ENABLED`, throw at startup (fail fast); any other error (a read
permission gap / a store that can't answer) warns loudly but proceeds, since the
per-upload lock header remains the hard fail-closed control (never weaken startup by
refusing on an unrelated failure).

## Verification

The added happy-path (`objectLockEnabled == ENABLED`) runs in the existing WORM ITs
against the real lock-enabled MinIO bucket (`RecordingIT`, `WormReadinessIncludeIT`),
so the added call is exercised in CI and does not break the working path. The
fail-fast throw branch fires only on a genuinely misconfigured bucket (covered by
analysis); the load-bearing control (per-upload object-lock header, fail-closed) is
unchanged and already tested.
