package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * The domain view of the connect-time decision context (FR-CHAN-1) before it is
 * serialized + signed. {@code grantExpiry = min(standing/JIT grant TTL,
 * access-cred TTL ceiling)}; {@code policyEpoch} is the CP monotonic epoch the
 * decision was taken under; {@code decisionTtl} bounds how long the Gateway may
 * serve per-channel checks from a cached copy (S10).
 *
 * <p>
 * {@code identity}/{@code identityGroups}/{@code nodeLabels} are SIGNED into
 * the context (S10) so the Gateway can match identity/group/node-label locks
 * against TRUSTED data on the per-channel hot path — never data it was merely
 * told. {@code nodeLabels} are {@code "key=value"} strings kept in a
 * deterministic order so the signed bytes are stable.
 *
 * <p>
 * {@code accessModel} ({@code "standing"}/{@code "jit"}/{@code "breakglass"},
 * S13) is signed so the Gateway selects the per-model mid-session-expiry
 * behaviour and forces strict recording for break-glass. Only a non-standing
 * model is emitted onto the wire (STANDING is left UNSPECIFIED), so a standing
 * decision's signed bytes stay byte-identical to the pre-S13 encoding and an
 * N-1 Gateway reads the absent field as the safe STANDING default.
 */
public record DecisionContext(UUID nodeId, String nodeName, List<String> allowedLogins, List<String> capabilities,
		String principal, Instant grantExpiry, long policyEpoch, Duration decisionTtl, UUID gatewayId, UUID sessionId,
		String sourceAddress, Instant issuedAt, String identity, List<String> identityGroups, List<String> nodeLabels,
		String accessModel) {

	public DecisionContext {
		allowedLogins = List.copyOf(allowedLogins);
		capabilities = List.copyOf(capabilities);
		identityGroups = List.copyOf(identityGroups);
		nodeLabels = List.copyOf(nodeLabels);
	}
}
