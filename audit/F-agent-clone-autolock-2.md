# F-agent-clone-autolock-2: Clone auto-lock targeted only the node UUID, so it could not match an agent PEER
- Severity: medium
- Status: Verified-Fixed
- Area: agent

## Summary
The S12 clone-detection auto-lock ([[F-agent-clone-autolock-1]]) created its `access_lock` with a
selector naming only the node: `{"node_ids": ["<node uuid>"]}` (`AgentRenewalService.autoLock`).

S14 gives the Gateway an agent-facing transport and makes it enforce Locks against a connected **agent
peer** — at control-channel registration and at every dial-back redemption. But an agent's mTLS
certificate carries only its node NAME (dNSName SAN, stamped from `node.name`) and its agent identity
(URI SAN `sessionlayer://agent/<id>`). It never carries the node UUID, and the Gateway has no way to
resolve a UUID for a merely-registered agent that has no session. A `node_ids`-only selector therefore
**cannot match an agent peer**, so the most security-critical Lock we have — the response to a detected
credential clone — did not fire at agent registration.

## Impact
**Not an access bypass.** The session path still denies correctly: the handler matches the Lock against
the signed decision context, which carries the real node UUID, so a locked node grants no SSH and no
dial-back token is ever minted for it. The defect is that the cloned agent's control channel stayed
registered and the stated doctrine ("a locked agent identity is refused at registration") silently did
not hold — a fail-open gap in defence-in-depth, and a latent one: any future Gateway path that gates on
peer identity alone would have inherited it.

## Remediation
`AgentRenewalService.cloneLockSelector(nodeId, agentId)` now emits BOTH facets:
`{"node_ids": ["<node uuid>"], "identities": ["<agent uuid>"]}`. The Gateway already matches an agent
peer on `identities == agent_id`, so registration/dial-back refusal works with no certificate change, no
new proto field, and no contract change (`LockCodec` already carries `identities` onto the wire, so the
existing `LockFeedHub` push and the snapshot both deliver it).

It cannot over-block: on the session path the `identities` facet is matched against the **human** subject
identity, which is never an agent UUID. The node-scoped half is retained, so session-path enforcement and
live-session teardown are unchanged.

Swept the other two `AccessLock.create` call sites and left both alone, deliberately:
`JitLifecycleService.revokeSelector` targets `identities:[request.requester()]` — the *human* requester,
correct for revoking that human's JIT grant; and `LockController` takes an operator-supplied selector via
REST, which must not be silently rewritten. `node:quarantine` is a platform permission driving a
`node.status` transition and creates no `access_lock` at all, so there is no other node-scoped lock path.

## Evidence
`AgentRenewalService.cloneLockSelector`; unit `AgentRenewalServiceTest.generationMismatchAutoLocksAndAlerts`
(asserts the selector carries the node id AND the agent identity); IT
`AgentJoinLifecycleIT.generationMismatchAutoLocksNodeAndAlerts` (asserts the persisted clone lock's
selector contains exactly `node_ids=[node]` and `identities=[agent]`).
