package io.sessionlayer.controlplane.ca.mtls;

import java.math.BigInteger;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

/**
 * The variable fields of an internal-mTLS-CA leaf certificate: the public key to
 * certify (the private half never reaches the CP — D2/§15), the subject CN, the
 * SANs, the leaf {@link LeafPurpose role} (which fixes the EKU), the serial and
 * the validity window. The CA-independent inputs to
 * {@link X509CaBackend#issueLeaf(LeafCertificateSpec)}, so a cloud backend seam
 * signs exactly the same to-be-signed structure as the local backend.
 *
 * @param subjectPublicKey
 *            the public key being certified (never a private key)
 * @param subjectCommonName
 *            the leaf subject CN (the Gateway name, or the CP server identity)
 * @param dnsSans
 *            DNS SubjectAlternativeNames (may be empty)
 * @param uriSans
 *            URI SubjectAlternativeNames — the Gateway identity URI
 *            ({@code sessionlayer://gateway/<id>}) the AuthInterceptor resolves
 * @param purpose
 *            server vs client (fixes the EKU)
 * @param serial
 *            the certificate serial (positive)
 * @param notBefore
 *            not-valid-before (backdated for skew)
 * @param notAfter
 *            not-valid-after
 */
public record LeafCertificateSpec(PublicKey subjectPublicKey, String subjectCommonName, List<String> dnsSans,
		List<String> uriSans, LeafPurpose purpose, BigInteger serial, Instant notBefore, Instant notAfter) {

	public LeafCertificateSpec {
		if (subjectPublicKey == null) {
			throw new IllegalArgumentException("subjectPublicKey is required");
		}
		if (subjectCommonName == null || subjectCommonName.isBlank()) {
			throw new IllegalArgumentException("subjectCommonName is required");
		}
		if (purpose == null) {
			throw new IllegalArgumentException("purpose is required");
		}
		if (serial == null || serial.signum() <= 0) {
			throw new IllegalArgumentException("serial must be positive");
		}
		if (notBefore == null || notAfter == null || !notAfter.isAfter(notBefore)) {
			throw new IllegalArgumentException("notAfter must be after notBefore");
		}
		dnsSans = (dnsSans == null) ? List.of() : List.copyOf(dnsSans);
		uriSans = (uriSans == null) ? List.of() : List.copyOf(uriSans);
	}
}
