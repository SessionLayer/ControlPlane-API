package io.sessionlayer.controlplane.ca.backend.azure;

import java.security.interfaces.ECPublicKey;

/**
 * The injectable seam for Azure Key Vault (FR-SIGN-2, D6/D7 — Azure has no
 * Ed25519, so ECDSA P-256 is the portable default). Production binds this to
 * the Key Vault
 * {@code CryptographyClient.sign(SignatureAlgorithm.ES256, digest)}, which
 * returns a <b>P1363</b> ({@code r‖s} fixed-width) signature that
 * {@link AzureKeyVaultCaBackend} normalizes. CI exercises the normalization
 * with a double; a documented manual path binds the SDK.
 */
public interface KeyVaultSigner {

	/** The CA public key resolved from Key Vault. */
	ECPublicKey publicKey();

	/**
	 * Sign a SHA-256 <b>digest</b> with the Key Vault key ({@code ES256}) and
	 * return the P1363 {@code r‖s} signature. MUST throw on failure (fail closed,
	 * FR-CA-9).
	 */
	byte[] signDigestP1363(byte[] sha256Digest);
}
