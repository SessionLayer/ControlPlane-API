package io.sessionlayer.controlplane.ca.backend.azure;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.SignerCapabilities;
import io.sessionlayer.controlplane.ca.backend.SignerBackend;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;

/**
 * Azure Key Vault CA backend (D7): the CA private key never leaves Key Vault.
 * It hashes the to-be-signed bytes to a SHA-256 digest, has Key Vault sign it,
 * and normalizes the returned <b>P1363</b> {@code r‖s} signature to OpenSSH
 * {@code (r, s)} (FR-SIGN-2) via {@link EcdsaSignatures#fromP1363}. Signing is
 * delegated to the injectable {@link KeyVaultSigner} seam.
 */
public final class AzureKeyVaultCaBackend implements SignerBackend {

	private final CaKeyType keyType;
	private final KeyVaultSigner keyVault;

	public AzureKeyVaultCaBackend(CaKeyType keyType, KeyVaultSigner keyVault) {
		this.keyType = keyType;
		this.keyVault = keyVault;
	}

	@Override
	public CaKeyType keyType() {
		return keyType;
	}

	@Override
	public ECPublicKey publicKey() {
		return keyVault.publicKey();
	}

	@Override
	public SignerCapabilities capabilities() {
		return SignerCapabilities.of(keyType);
	}

	@Override
	public EcdsaSignatures.RS sign(byte[] toBeSigned) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(toBeSigned);
			return EcdsaSignatures.fromP1363(keyVault.signDigestP1363(digest), keyType);
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new IllegalStateException("Azure Key Vault CA signing failed", e);
		}
	}
}
