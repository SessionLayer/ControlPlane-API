# F-audit-create-ahead-1: no create-ahead automation → partition cliff + cloud capability lie
- Severity: high
- Status: Verified-Fixed
- Area: audit

## Summary
- **R-AUD-1/HIGH:** the migration seeded a fixed 19-month partition window once; nothing
  created partitions on an ongoing basis, so ~13 months post-deploy new audit rows would
  silently land in the DEFAULT partition (which retention never reclaims) — a slow bloat with
  no alert.
- **F-cacloud-1/MEDIUM:** the cloud backends (KMS/KeyVault/Vault) advertised P-384/P-521 in the
  capability check but hardcode SHA-256/ES256, so a validated `ca_config{backend=aws_kms,
  algorithm=ecdsa-p384}` would be unsignable — the FR-CA-4 "rejected at validation, never a
  signing-time surprise" promise was violated for cloud + non-P256.

## Remediation (Verified-Fixed)
- `AuditPartitionMaintenance` (@Scheduled + on startup, gated by
  `sessionlayer.audit.partition-maintenance.enabled`, default on) keeps a rolling 6-month window
  of future partitions via the bounded create-ahead `audit_ensure_partitions` (create-only; the
  runtime role may not prune), so the DEFAULT stays empty in practice.
- `CaBackendCapabilities.forBackend` now advertises P-256 only for the cloud backends (local
  keeps all three ECDSA curves, since it derives the digest from the curve). Widen when the cloud
  backends derive the digest/algorithm from the curve.

## Dedicated gate
`AuditPartitioningIT` (create-ahead + routing + prune), `CaBackendCapabilitiesTest`
(`onlyLocalAdvertisesTheWiderCurves`). The DEFAULT-partition recovery dance is a documented
operator runbook (see F-audit-default-recovery-1).
