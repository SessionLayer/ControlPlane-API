package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Cert-encoding helpers shared by the Agent enroll/renew services (mirrors the
 * gateway ones).
 */
final class AgentCertificates {

	private AgentCertificates() {
	}

	static IssuedAgentIdentity toIssued(X509Certificate leaf, X509CaBackend backend, UUID agentId, UUID nodeId,
			long generation, Instant notBefore, Instant notAfter) {
		return new IssuedAgentIdentity(der(leaf), List.of(der(backend.caCertificate())), agentId, nodeId, generation,
				notBefore.getEpochSecond(), notAfter.getEpochSecond());
	}

	static byte[] der(X509Certificate certificate) {
		try {
			return certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException("failed to encode issued certificate", e);
		}
	}

	/** A positive serial derived from the (random-tailed) UUIDv7. */
	static BigInteger serial(UUID id) {
		ByteBuffer buffer = ByteBuffer.allocate(16);
		buffer.putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits());
		BigInteger serial = new BigInteger(1, buffer.array());
		return serial.signum() == 0 ? BigInteger.ONE : serial;
	}
}
