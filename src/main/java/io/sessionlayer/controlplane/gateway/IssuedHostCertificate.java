package io.sessionlayer.controlplane.gateway;

/**
 * A signed Gateway OUTER host certificate (S16, FR-ADDR-1): the
 * {@code authorized_keys}-style line and the raw OpenSSH wire blob, plus the
 * validity window. Cert only — the Gateway generated the host keypair locally
 * and the CP never receives its private half (D2/§9.3).
 */
public record IssuedHostCertificate(String certificateLine, byte[] certificateBlob, long validAfterEpochSeconds,
		long validBeforeEpochSeconds) {
}
