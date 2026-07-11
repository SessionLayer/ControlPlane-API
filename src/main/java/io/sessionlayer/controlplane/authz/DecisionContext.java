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
 */
public record DecisionContext(UUID nodeId, String nodeName, List<String> allowedLogins, List<String> capabilities,
		String principal, Instant grantExpiry, long policyEpoch, Duration decisionTtl, UUID gatewayId, UUID sessionId,
		String sourceAddress, Instant issuedAt) {

	public DecisionContext {
		allowedLogins = List.copyOf(allowedLogins);
		capabilities = List.copyOf(capabilities);
	}
}
