package io.sessionlayer.controlplane.recording;

import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * Validates the operator-configured customer recording key (FR-AUD-2, §15). The
 * stored bytes MUST be a well-formed X.509 SubjectPublicKeyInfo for the sealing
 * algorithm — an EC P-256 point for ECIES, an RSA key for RSA-OAEP — and MUST
 * be a PUBLIC key. Anything else (garbage, a truncated blob, or a private key
 * mistakenly pasted in) fails validation so {@code BeginRecording} refuses to
 * hand the Gateway a key it can't seal to (fail closed, never store keystrokes
 * under an unusable key).
 */
public final class CustomerPublicKeys {

	private static final String EC_OID = X9ObjectIdentifiers.id_ecPublicKey.getId();
	private static final String RSA_OID = PKCSObjectIdentifiers.rsaEncryption.getId();

	private CustomerPublicKeys() {
	}

	/**
	 * True iff {@code der} is a valid SPKI public key matching
	 * {@code sealAlgorithm}.
	 */
	public static boolean isValid(byte[] der, String sealAlgorithm) {
		if (der == null || der.length == 0) {
			return false;
		}
		try {
			// getInstance over the parsed sequence rejects a PKCS#8 private key (different
			// ASN.1 shape) and any non-SPKI blob before we ever touch a KeyFactory.
			SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(der));
			String oid = spki.getAlgorithm().getAlgorithm().getId();
			X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
			if ("rsa_oaep_sha256".equals(sealAlgorithm)) {
				return RSA_OID.equals(oid) && KeyFactory.getInstance("RSA").generatePublic(spec) != null;
			}
			// ECIES P-256 default: require an EC key on the P-256 (256-bit) field.
			if (!EC_OID.equals(oid)) {
				return false;
			}
			return KeyFactory.getInstance("EC").generatePublic(spec) instanceof ECPublicKey ec
					&& ec.getParams().getCurve().getField().getFieldSize() == 256;
		} catch (Exception notAPublicKey) {
			return false;
		}
	}
}
