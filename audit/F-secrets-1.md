# F-secrets-1: reference-only columns had no content guard against key-material-at-rest
- Severity: medium
- Status: Verified-Fixed
- Area: secrets

## Summary
The §2.5 "no secrets at rest" guardrail rested only on column *names* and a name-only structural test.
`ca_config.key_reference`, `service_account.key_reference`, `recording_ref.encryption_key_ref`,
`agent_identity`/`gateway_identity.mtls_identity_ref`, `node_policy.host_pin_ref`/`host_ca_ref` were
unconstrained `text` — nothing stopped a later session (e.g. the local-CA backend, FR-CA-8) from writing an
actual PEM private key *into* a correctly-named reference column (security-review M1).

## Impact
The crown-jewel CA private key or an agent private key could silently land at rest in Postgres / replicas /
backups with no test failing.

## Remediation
Belt-and-suspenders **content-guard CHECKs** on the reference columns: the crown-jewel columns
(`ca_config.key_reference`, `recording_ref.encryption_key_ref`) reject `%PRIVATE KEY%` and `%BEGIN %`; the
others reject `%PRIVATE KEY%`. The structural name-based test remains. Documented in DATA-MODEL §12 that the
hash/reference *contract* itself is still enforced by the writing session's application code.

## Evidence
- `V2__config_schema.sql`, `V3__runtime_schema.sql` (content-guard CHECKs).
- `ConstraintsIT.privateKeyMaterialInReferenceRejected`; `AppendOnlyAuditIT.secretBearingTablesStoreHashesOrReferencesOnly`.
</content>
