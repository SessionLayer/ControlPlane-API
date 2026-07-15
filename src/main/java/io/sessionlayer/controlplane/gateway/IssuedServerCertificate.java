package io.sessionlayer.controlplane.gateway;

import java.util.List;

/**
 * The result of issuing a Gateway's agent-facing TLS <b>server</b> certificate
 * (S14): the serverAuth leaf (DER), the CA chain (DER; issuing CA first), the
 * name the CP stamped as the dNSName SAN, and the validity window (epoch
 * seconds). Deliberately carries <b>no generation counter</b> — this is not an
 * identity, it is a TLS credential derived from one, so it is revoked by
 * locking the {@code gateway_identity} rather than by rotating a counter.
 * Public material only — never a private key (D2).
 */
public record IssuedServerCertificate(byte[] certificate, List<byte[]> caChain, String gatewayName,
		long notBeforeEpochSeconds, long notAfterEpochSeconds) {
}
