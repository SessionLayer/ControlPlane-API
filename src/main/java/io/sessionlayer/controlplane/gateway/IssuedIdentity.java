package io.sessionlayer.controlplane.gateway;

import java.util.List;
import java.util.UUID;

/**
 * The result of enrolling or renewing a Gateway mTLS identity: the issued leaf
 * certificate (DER), the CA chain (DER; issuing CA first), the stable gateway
 * id, the generation counter, and the validity window (epoch seconds). The gRPC
 * handler maps this straight onto {@code EnrollGatewayResponse} /
 * {@code RenewGatewayIdentityResponse}. Contains public material only — never a
 * private key (D2).
 */
public record IssuedIdentity(byte[] certificate, List<byte[]> caChain, UUID gatewayId, long generation,
		long notBeforeEpochSeconds, long notAfterEpochSeconds) {
}
