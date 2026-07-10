package io.sessionlayer.controlplane.ca.backend.local;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.SignerCapabilities;
import io.sessionlayer.controlplane.ca.backend.SignerBackend;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * The local (in-process) CA backend (FR-CA-8): it signs with an in-memory ECDSA
 * private key that was decrypted transiently from its KEK-wrapped form. Java's
 * {@code SHA*withECDSA} produces a DER signature, which is normalized to
 * {@code (r, s)} — the same normalization path as AWS KMS, so the shared code
 * is exercised by the local backend too.
 *
 * <p>
 * <b>Production SHOULD use KMS/KeyVault/Vault</b> so the private key is never
 * in-process; the local backend emits that warning at startup (see
 * {@code LocalCaProvisioner}). The private key is a JCA {@link PrivateKey} that
 * cannot itself be zeroized, so the resident-key exposure is inherent to a
 * local signer and is exactly why a KMS backend is preferred.
 */
public final class LocalCaBackend implements SignerBackend {

	private final CaKeyType keyType;
	private final PrivateKey privateKey;
	private final ECPublicKey publicKey;

	public LocalCaBackend(CaKeyType keyType, PrivateKey privateKey, ECPublicKey publicKey) {
		this.keyType = keyType;
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}

	@Override
	public CaKeyType keyType() {
		return keyType;
	}

	@Override
	public ECPublicKey publicKey() {
		return publicKey;
	}

	@Override
	public SignerCapabilities capabilities() {
		return SignerCapabilities.of(keyType);
	}

	@Override
	public EcdsaSignatures.RS sign(byte[] toBeSigned) {
		try {
			Signature signature = Signature.getInstance(keyType.signatureAlgorithm());
			signature.initSign(privateKey);
			signature.update(toBeSigned);
			return EcdsaSignatures.fromDer(signature.sign());
		} catch (Exception e) {
			// Fail closed (FR-CA-9): never return a wrong/empty signature.
			throw new IllegalStateException("local CA signing failed", e);
		}
	}
}
