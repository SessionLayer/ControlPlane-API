# F-machine-token-audit: Failed machine-token authentications were not audited (FR-AUD-7 gap)

- Severity: medium
- Status: Verified-Fixed
- Area: audit

Only successful mints were audited; all deny paths (invalid_client, replay, rate_limited, ...) threw without a record — the exact events for detecting credential brute-force. **Fixed:** auditDenied() records a `denied` machine.token.issue event on every failure path.
