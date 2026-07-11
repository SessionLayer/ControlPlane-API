package io.sessionlayer.controlplane.mtls;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

/**
 * SHA-256 certificate fingerprints (lowercase hex) for identity bookkeeping.
 */
public final class CertificateFingerprints {

	private CertificateFingerprints() {
	}

	/**
	 * The SHA-256 fingerprint of a certificate's DER encoding, as lowercase hex.
	 */
	public static String sha256Hex(X509Certificate certificate) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
			return HexFormat.of().formatHex(digest);
		} catch (Exception e) {
			throw new IllegalStateException("failed to fingerprint certificate", e);
		}
	}
}
