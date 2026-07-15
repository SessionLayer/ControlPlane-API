# F-agent-clone-autolock-1: Generation-mismatch must lock BOTH copies, push, alert, and never auto-clear
- Severity: high
- Status: Verified-Fixed
- Area: agent

## Summary
S4 treated a Gateway renewal generation-mismatch as flag-only (audit + refuse; the fan-out was deferred
to S10). For S12 the Agent renewal path implements the full §8.2 clone-detection primitive: a cloned
credential forks the generation counter, so the copy that is "behind" declares a stale generation and
must be detected and neutralized — not merely refused.

## Impact
Without the full response, a cloned Agent credential (copied off a compromised node) could keep operating
after the fork was noticed, and a mismatch would not tear down live sessions on the affected node.

## Remediation
`AgentRenewalService` on a generation mismatch (and on a lost `@Version` renewal race, which for a
single persist-before-adopt Agent is itself a clone signal): in ONE transaction it flips
`agent_identity.status='locked'` (reason "generation mismatch (possible credential clone)",
`status_changed_by='system:clone-detection'`), inserts a strict, **no-TTL** `access_lock` targeting the
node (`node_ids:[node_id]` — extended in S14 to also carry `identities:[agent_id]` so the lock reaches
the agent as a peer, see F-agent-clone-autolock-2), and audits `agent.renew.generation_mismatch`; AFTER commit it pushes the
lock via the S10 `LockFeedHub` (live sessions on the node tear down) and raises a distinct high-severity
security alert (`AgentSecurityAlerts` → `agent.identity.clone_detected` + a loud ERROR log), then refuses
`FAILED_PRECONDITION`. Because the fingerprint pin tolerates {current, prev}, both the stale copy and the
fork reach the generation check and both are locked. The lock has no TTL and the status flip is terminal:
it **never auto-clears** (operator re-provision). A repeat mismatch by an already-locked identity does not
create a duplicate lock (the auto-lock only fires while the identity is still `active`).

## Evidence
`AgentRenewalService.autoLock` (tx: status flip + lock insert + audit; post-commit publish + alert);
`AgentSecurityAlerts` + `AuditLogAgentSecurityAlertSink`; unit `AgentRenewalServiceTest`
(locked-copy status + strict/null-TTL lock + `node_ids` selector + `publishAdded` + `cloneDetected`
+ FAILED_PRECONDITION); IT `AgentJoinLifecycleIT.generationMismatchAutoLocksNodeAndAlerts` (DB status
locked + covering access_lock + `agent.identity.clone_detected` audit + a subsequent correct-generation
renew still refused).
