package io.sessionlayer.controlplane.agent;

import java.util.List;
import java.util.UUID;

/**
 * The result of enrolling or renewing an Agent mTLS identity: the issued leaf
 * certificate (DER), the CA chain (DER; issuing CA first), the stable agent id,
 * the resolved node id it is bound to (FR-JOIN-6), the generation counter, and
 * the validity window (epoch seconds). The gRPC handler maps this straight onto
 * {@code EnrollAgentResponse} / {@code RenewAgentIdentityResponse}. Mirrors
 * {@code IssuedIdentity} with {@code nodeId} added. Contains public material
 * only — never a private key (D2).
 */
public record IssuedAgentIdentity(byte[] certificate, List<byte[]> caChain, UUID agentId, UUID nodeId, long generation,
		long notBeforeEpochSeconds, long notAfterEpochSeconds) {
}
