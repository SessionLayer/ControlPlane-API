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
 * requester, FR-ACC-4) is a hard invariant enforced by the JIT approval logic
 * over {@code approvals}. The transition methods below are the only sanctioned
 * state changes; each is audited by {@code JitLifecycleService}.
 */
@Table(schema = "runtime", name = "jit_request")
public record JitRequest(@Id UUID id, String requester, UUID targetNodeId, String targetNodeName,
		JsonNode targetSelector, String principal, List<String> capabilities, String reason, String state,
		UUID jitPolicyId, String jitPolicyName, JsonNode approvalChain, JsonNode approvals, Instant approvalDeadline,
		Instant grantExpiresAt, Instant requestedAt, Instant decidedAt, String decidedBy, String decisionReason,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static final String REQUESTED = "REQUESTED";
	public static final String PENDING_APPROVAL = "PENDING_APPROVAL";
	public static final String APPROVED = "APPROVED";
	public static final String DENIED = "DENIED";
	public static final String EXPIRED = "EXPIRED";
	public static final String ACTIVE = "ACTIVE";
	public static final String REVOKED = "REVOKED";

	public static JitRequest create(String requester, UUID targetNodeId, String targetNodeName, JsonNode targetSelector,
			String principal, List<String> capabilities, String reason, String state, UUID jitPolicyId,
			String jitPolicyName, JsonNode approvalChain, JsonNode approvals, Instant approvalDeadline,
			Instant grantExpiresAt, Instant requestedAt) {
		// decidedBy/decisionReason (F-DM-15) default null; set when APPROVED/DENIED.
		return new JitRequest(Uuids.v7(), requester, targetNodeId, targetNodeName, targetSelector, principal,
				capabilities, reason, state, jitPolicyId, jitPolicyName, approvalChain, approvals, approvalDeadline,
				grantExpiresAt, requestedAt, null, null, null, null, null, null);
	}

	/** A partial approval advanced one level: same state, appended approvals. */
	public JitRequest withApprovals(JsonNode updatedApprovals) {
		return new JitRequest(id, requester, targetNodeId, targetNodeName, targetSelector, principal, capabilities,
				reason, state, jitPolicyId, jitPolicyName, approvalChain, updatedApprovals, approvalDeadline,
				grantExpiresAt, requestedAt, decidedAt, decidedBy, decisionReason, version, createdAt, updatedAt);
	}

	/** Final approval: state APPROVED, grant clock starts, decision recorded. */
	public JitRequest approved(JsonNode updatedApprovals, Instant grantExpiry, String decider, Instant at) {
		return new JitRequest(id, requester, targetNodeId, targetNodeName, targetSelector, principal, capabilities,
				reason, APPROVED, jitPolicyId, jitPolicyName, approvalChain, updatedApprovals, approvalDeadline,
				grantExpiry, requestedAt, at, decider, "approved", version, createdAt, updatedAt);
	}

	/** Terminal DENIED. */
	public JitRequest denied(JsonNode updatedApprovals, String decider, String reasonText, Instant at) {
		return new JitRequest(id, requester, targetNodeId, targetNodeName, targetSelector, principal, capabilities,
				reason, DENIED, jitPolicyId, jitPolicyName, approvalChain, updatedApprovals, approvalDeadline,
				grantExpiresAt, requestedAt, at, decider, reasonText, version, createdAt, updatedAt);
	}

	/** First use of an APPROVED grant flips it to ACTIVE (still the same clock). */
	public JitRequest activated() {
		return new JitRequest(id, requester, targetNodeId, targetNodeName, targetSelector, principal, capabilities,
				reason, ACTIVE, jitPolicyId, jitPolicyName, approvalChain, approvals, approvalDeadline, grantExpiresAt,
				requestedAt, decidedAt, decidedBy, decisionReason, version, createdAt, updatedAt);
	}

	/** Terminal EXPIRED (either clock elapsed). */
	public JitRequest expired(Instant at) {
		return new JitRequest(id, requester, targetNodeId, targetNodeName, targetSelector, principal, capabilities,
				reason, EXPIRED, jitPolicyId, jitPolicyName, approvalChain, approvals, approvalDeadline, grantExpiresAt,
				requestedAt, at, "system:expiry", "expired", version, createdAt, updatedAt);
	}

	/** Terminal REVOKED (an admin pulled an APPROVED/ACTIVE grant). */
	public JitRequest revoked(String actor, String reasonText, Instant at) {
		return new JitRequest(id, requester, targetNodeId, targetNodeName, targetSelector, principal, capabilities,
				reason, REVOKED, jitPolicyId, jitPolicyName, approvalChain, approvals, approvalDeadline, grantExpiresAt,
				requestedAt, at, actor, reasonText, version, createdAt, updatedAt);
	}

	/** An APPROVED/ACTIVE grant whose grant clock has not elapsed is usable. */
	public boolean usableAt(Instant now) {
		return (APPROVED.equals(state) || ACTIVE.equals(state)) && grantExpiresAt != null
				&& grantExpiresAt.isAfter(now);
	}
}
