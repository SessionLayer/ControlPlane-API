package io.sessionlayer.controlplane.gateway;

/**
 * The result of {@code SignSessionCertificate}: the signed OpenSSH inner-leg
 * certificate as both an authorized-keys line and the raw wire blob, its key id
 * ({@code session_id+identity}), and the validity window (epoch seconds). Cert
 * only — never a private key (D2/FR-CA-3).
 */
public record SignedInnerCert(String certificateLine, byte[] certificateBlob, String keyId, long validAfterEpochSeconds,
		long validBeforeEpochSeconds) {
}
