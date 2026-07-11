package io.sessionlayer.controlplane.authz;

import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * The reference verifier for a signed decision context — the CP round-trip test
 * uses it now; S10's Gateway ports the identical steps to Rust. Verification is
 * fail-closed: any failure returns {@code false}. A verifier
 * <ol>
 * <li>validates the signer leaf chains to the internal mTLS CA (the anchor the
 * Gateway already pins) and is currently valid;</li>
 * <li>confirms the leaf carries the {@link DecisionContextSigning#SIGNER_URI}
 * marker (so a plain server/client leaf cannot masquerade as the signer);</li>
 * <li>verifies the ECDSA signature over
 * {@code DOMAIN_PREFIX || signedContext}.</li>
 * </ol>
 */
public final class DecisionContextVerifier {

	private static final int SAN_URI = 6;

	/** EKU id-kp-codeSigning (the decision-context signer's purpose). */
	private static final String CODE_SIGNING_EKU = "1.3.6.1.5.5.7.3.3";

	private DecisionContextVerifier() {
	}

	public static boolean verify(X509Certificate caCertificate, byte[] signerCertDer, byte[] signedContext,
			byte[] signature) {
		try {
			X509Certificate signer = parse(signerCertDer);
			// Defense in depth: the SAN marker is not the sole factor. Require the
			// codeSigning EKU and reject any CA/keyCertSign cert, so even a mis-issued leaf
			// that somehow carried the marker cannot masquerade as the signer.
			if (!chainsTo(caCertificate, signer) || !hasSignerMarker(signer) || !isCodeSigner(signer)) {
				return false;
			}
			Signature verifier = Signature.getInstance(DecisionContextSigning.SIGNATURE_ALGORITHM);
			verifier.initVerify(signer.getPublicKey());
			verifier.update(DecisionContextSigning.DOMAIN_PREFIX);
			verifier.update(signedContext);
			return verifier.verify(signature);
		} catch (Exception failClosed) {
			return false;
		}
	}

	private static boolean chainsTo(X509Certificate caCertificate, X509Certificate signer) {
		try {
			// PKIX path validation anchored on the internal mTLS CA: enforces the
			// signature, validity window and basic constraints WITHOUT imposing a TLS EKU
			// (the signer is a codeSigning leaf, not a TLS endpoint). Revocation is off —
			// the leaf is short-lived + re-minted per boot; S10 adds the lock/CRL layer.
			CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(signer));
			PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(caCertificate, null)));
			params.setRevocationEnabled(false);
			CertPathValidator.getInstance("PKIX").validate(path, params);
			return true;
		} catch (Exception invalid) {
			return false;
		}
	}

	private static boolean isCodeSigner(X509Certificate signer) throws Exception {
		if (signer.getBasicConstraints() != -1) {
			return false; // a CA cert must never sign decision contexts
		}
		var ekus = signer.getExtendedKeyUsage();
		return ekus != null && ekus.contains(CODE_SIGNING_EKU);
	}

	private static boolean hasSignerMarker(X509Certificate signer) throws Exception {
		var sans = signer.getSubjectAlternativeNames();
		if (sans == null) {
			return false;
		}
		for (List<?> san : sans) {
			if (san.size() >= 2 && san.get(0) instanceof Integer type && type == SAN_URI
					&& DecisionContextSigning.SIGNER_URI.equals(san.get(1))) {
				return true;
			}
		}
		return false;
	}

	private static X509Certificate parse(byte[] der) throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new java.io.ByteArrayInputStream(der));
	}
}
