# F-snapshot-1: decision snapshots stored config ids but not config names (opaque history after GC)
- Severity: medium
- Status: Verified-Fixed
- Area: data-model

## Summary
The decision-snapshot pattern correctly snapshotted `node_name`/`gateway_name`, but the config *decision*
references were id-only: `ssh_session.matched_rule_id`, `jit_request.jit_policy_id`,
`breakglass_activation.breakglass_policy_id` had no name (divergence F-DM-4). The doctrine is "audit survives
config GC" — but after a rule/policy is deleted, a surviving opaque UUID is not legible history.

## Impact
An auditor could not tell *which named rule/policy* authorized a session after the producing config was
Git-reconciled away — inconsistent with the node/gateway name snapshots right beside it, undermining the whole
snapshot rationale.

## Remediation
Snapshot the name alongside the id: added `ssh_session.matched_rule_name`, `jit_request.jit_policy_name`,
`breakglass_activation.breakglass_policy_name`. Also added `ssh_session.grant_expiry` (FR-CHAN-1's computed
grant_expiry was previously unrecorded).

## Evidence
- `V3__runtime_schema.sql`; entities `SshSession`/`JitRequest`/`BreakglassActivation` + factories.
- `RuntimeRepositoryCrudIT` asserts `matchedRuleName`, `grantExpiry`, `breakglassPolicyName`.
</content>
