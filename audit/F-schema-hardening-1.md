# F-schema-hardening-1: assorted low-severity schema-quality fixes
- Severity: low
- Status: Verified-Fixed
- Area: schema

## Summary
A batch of low-severity correctness / operability / usability findings from the four reviews, all remediated:

- **Redundant index** (reliability L1): `idx_role_binding_role` was shadowed by the composite
  `UNIQUE(role_id, subject_kind, subject)` (role_id-leading) → dropped.
- **Non-re-runnable DDL** (reliability L3): `is_cidr` function + the four triggers used bare `CREATE`,
  contradicting the "re-runnable" doc claim → all now `CREATE OR REPLACE [TRIGGER|FUNCTION]`.
- **CIDR validator too strict** (red-team LOW): `::cidr` rejected operator-common host-bit forms like
  `192.168.1.5/24` → renamed `runtime.is_cidr` → `runtime.is_ip_or_cidr` and switched to lenient `::inet`.
- **Agentless node without address** (reliability L5): added `CHECK (connector_kind='agent' OR address IS NOT
  NULL)` (§9.2 agentless dials its address).
- **Unbounded JIT `approvals` array** (security L3): added `CHECK (jsonb_array_length(approvals) <= 16)`.
- **Un-validated audit `source_ip`** (security L7): added `CHECK (source_ip IS NULL OR
  runtime.is_ip_or_cidr(source_ip))` so a malformed value can't error the FR-AUD-8 search cast later.
- **Credential validity ordering** (security L5): added `CHECK (not_after > issued_at)` on both identity tables.

## Impact
Individually minor (write amplification, repair ergonomics, surprising rejections, self-inflicted search DoS);
all cheap to fix while the schema is open.

## Remediation
See V2/V3/V4/V5 edits above; covered by `ConstraintsIT` (agentless address, malformed cidr) and
`AppendOnlyAuditIT.malformedSourceIpRejected` + `DataModelSmokeIT` (host-bit CIDR accepted).
</content>
