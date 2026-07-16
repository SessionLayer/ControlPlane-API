# F-recording-versioned-erase-1: Governance/retention delete wrote only a delete marker — the WORM-locked object version persisted (GDPR erasure illusory)

- Severity: high
- Status: Verified-Fixed
- Area: security

Object-lock implies a versioned bucket, so `deleteObject(key)` (no versionId) only wrote a delete marker; the governance-locked VERSION persisted and was retrievable via GetObjectVersion, so "erasure" (GDPR / retention) was illusory and storage was never reclaimed. The IT only asserted `headObject` throws (delete-marker invisibility), giving false confidence.

**Fix (Verified-Fixed, ddff505):** `WormObjectStore.deleteObject` now enumerates `listObjectVersions` for the exact key and deletes EVERY version + delete marker with `bypassGovernanceRetention(true)` (governance only; compliance still refused). The recording ITs now assert `listObjectVersions` is EMPTY (versions AND markers) after both governance delete and retention prune.
