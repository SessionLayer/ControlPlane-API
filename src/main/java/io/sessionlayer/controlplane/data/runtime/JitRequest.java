package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * RUNTIME · {@code runtime.jit_request} (FR-ACC-2). The JIT state machine with
 * two clocks (approval window + grant TTL). {@code jitPolicyId} and
 * {@code approvalChain} are snapshots of the policy at request time (no FK), so
 * later config edits don't rewrite history. Self-approval (approver ≠
 * requester, FR-ACC-4) is a hard invariant enforced by S11 logic over
 * {@code approvals}.
 */
@Table(schema = "runtime", name = "jit_request")
public record JitRequest(@Id UUID id, String requester, UUID targetNodeId, String targetNodeName,
		JsonNode targetSelector, String principal, List<String> capabilities, String reason, String state,
		UUID jitPolicyId, String jitPolicyName, JsonNode approvalChain, JsonNode approvals, Instant approvalDeadline,
		Instant grantExpiresAt, Instant requestedAt, Instant decidedAt, String decidedBy, String decisionReason,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static JitRequest create(String requester, UUID targetNodeId, String targetNodeName, JsonNode targetSelector,
			String principal, List<String> capabilities, String reason, String state, UUID jitPolicyId,
			String jitPolicyName, JsonNode approvalChain, JsonNode approvals, Instant approvalDeadline,
			Instant grantExpiresAt, Instant requestedAt) {
		// decidedBy/decisionReason (F-DM-15) default null; set when APPROVED/DENIED.
		return new JitRequest(Uuids.v7(), requester, targetNodeId, targetNodeName, targetSelector, principal,
				capabilities, reason, state, jitPolicyId, jitPolicyName, approvalChain, approvals, approvalDeadline,
				grantExpiresAt, requestedAt, null, null, null, null, null, null);
	}
}
