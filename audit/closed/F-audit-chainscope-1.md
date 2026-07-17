# F-audit-chainscope-1: correlated chain unreconstructable for a node-label-scoped auditor

- Severity: low
- Status: Verified-Fixed
- Area: audit

## Summary

After the S20 write-path backfill, only the connect decision event
(`ConnectAuthorizationService.emitAllow`) stamped `node_labels`. The other
in-session + approval producers left it NULL: JIT lifecycle transitions
(`JitLifecycleService.auditTransition`), break-glass activation, recording
begin/upload/finalize/sftp (`RecordingRegistrationService`), recording
replay/export (`RecordingAccessService`), and session terminate
(`SessionManagementService`). A node-label-scoped `audit:read` grant filters with
`node_labels @> :scope`; `NULL @> '{...}'` is false, so a scoped auditor's
`GET /v1/audit-events?correlationId=X` returned ONLY the connect event — the
approval, recording replay/export, and termination were silently dropped. That
falsifies the FR-AUD-9 "one correlation_id reconstructs the whole
approve→connect→run→replay chain" guarantee precisely for the scoped-auditor
population Part B exists to serve (unrestricted auditors got the full chain, so
the original tests passed). Fail-closed (no disclosure), but a silently-empty
filter (CWE-778).

## Fix

Every in-session + approval producer now stamps the node's label snapshot on its
audit event: a one-node-read resolver (`nodes.findById(nodeId) → resolvedLabels`)
in JIT/recording-registration/session-management (RecordingAccessService reuses
the labels it already resolves for the authz scope check; break-glass uses the
node already in hand). Empty labels persist as NULL (matching the immortal null
history).

## Verification

`JitAuthorizeIT.oneCorrelationIdReconstructsApproveConnectAndInSessionEvents`
adds an `env=prod`-scoped search by correlationId and asserts it returns the whole
chain (`jit.requested`, `jit.approved`, `authz.decision`, `session.terminate`) —
not just the connect. `RecordingReplayIT` asserts the replay event carries the
node-label snapshot, and `RecordingStoreSeamTest` asserts the recording-access
producer stamps it.
