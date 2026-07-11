# F-signer-refresh-1: Decision-context signer leaf never refreshed (24h/CA-rotation time bomb)
- Severity: medium
- Status: Verified-Fixed
- Area: signer

## Summary
The signer leaf was minted once per boot and cached for process life; it would expire at 24h uptime and go stale after
a CA rotation, causing a fleet-wide connect outage once S10 verifies it.

## Fix
`DecisionContextSigner` re-mints refresh-ahead (in the leaf final third), which also picks up a rotated internal mTLS
CA; a brief concurrent re-mint just yields an extra valid leaf (last write wins).
