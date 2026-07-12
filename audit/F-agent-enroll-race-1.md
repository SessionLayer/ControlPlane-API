# F-agent-enroll-race-1: Concurrent tokenless enroll of the same node leaked a gRPC INTERNAL
- Severity: low
- Status: Verified-Fixed
- Area: agent

## Summary
`AgentEnrollmentService.enroll` checks `refuseIfActive(nodeId)` before issuing, but the check and the
insert are not atomic. For the TokenJoin method the single-use token consume serializes concurrent
enrolls, but OidcJoin and MtlsJoin have no such serialization: two concurrent valid-proof enrolls of the
same *new* node could both pass the active-identity check and then both attempt to insert an `active`
`agent_identity`, racing the `uq_agent_identity_active_per_node` partial unique index. The loser's insert
raised a `DataIntegrityViolationException` that was not mapped, so it surfaced as a generic gRPC
`INTERNAL` instead of a fail-closed refusal (a weak information leak + a non-idiomatic error).

## Impact
Low: only a valid-proof holder for that node can trigger it (the proof is verified before node/identity
writes), and the winner is correctly enrolled; the loser merely got the wrong status code. No double
active identity is ever created (the unique index holds).

## Remediation
The active-identity insert now maps `DataIntegrityViolationException` to a generic
`AgentJoinException(PERMISSION_DENIED, "enrollment refused")` — the same fail-closed shape as the
already-enrolled path — so a lost race is indistinguishable from a normal already-enrolled refusal.

## Evidence
`AgentEnrollmentService.issue` onErrorMap on `agentIdentities.save`; the node-create race is likewise
handled (`resolveNode` re-reads on `DataIntegrityViolationException`). The one-active-per-node invariant
is proven by `ConstraintsIT` (V5 partial unique index).
