package io.sessionlayer.controlplane.ca.backend.aws;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.SignerCapabilities;
import io.sessionlayer.controlplane.ca.backend.SignerBackend;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;

/**
 * AWS KMS CA backend (D7): the CA private key never leaves KMS. It hashes the
 * to-be-signed certificate bytes to a SHA-256 digest, has KMS sign the digest,
 * and normalizes the returned <b>DER</b> signature to OpenSSH {@code (r, s)}
 * (FR-SIGN-2) via the same {@link EcdsaSignatures#fromDer} path the local
 * backend uses. The signing itself is delegated to the injectable
 * {@link KmsSigner} seam.
 */
public final class KmsCaBackend implements SignerBackend {

	private final CaKeyType keyType;
	private final KmsSigner kms;

	public KmsCaBackend(CaKeyType keyType, KmsSigner kms) {
		this.keyType = keyType;
		this.kms = kms;
	}

	@Override
	public CaKeyType keyType() {
		return keyType;
	}

	@Override
	public ECPublicKey publicKey() {
		return kms.publicKey();
	}

	@Override
	public SignerCapabilities capabilities() {
		return SignerCapabilities.of(keyType);
	}

	@Override
	public EcdsaSignatures.RS sign(byte[] toBeSigned) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(toBeSigned);
			return EcdsaSignatures.fromDer(kms.signDigestDer(digest));
		} catch (RuntimeException e) {
			throw e; // fail closed (already a runtime failure from the seam)
		} catch (Exception e) {
			throw new IllegalStateException("KMS CA signing failed", e);
		}
	}
}
