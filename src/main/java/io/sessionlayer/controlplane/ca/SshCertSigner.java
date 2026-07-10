package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;

/**
 * The SessionLayer certificate signer (FR-SIGN-1/3). Instantiable <b>per CA</b>
 * (user-facing / internal session / host) with independent backends (local /
 * AWS KMS / Azure Key Vault / Vault SSH engine). Exposes the CA public key, the
 * backend capabilities, a full {@code signCertificate}, and a raw-sign
 * primitive.
 *
 * <p>
 * For raw-signer backends (local / KMS / Key Vault) a shared assembler builds
 * the to-be-signed certificate and {@link #rawSign} normalizes the backend
 * signature; the Vault SSH-engine backend overrides {@link #signCertificate}
 * wholesale (it returns a signed cert directly via
 * {@code POST /ssh/sign/:role}).
 *
 * <p>
 * The CP only ever <b>signs a presented public key</b> and returns a
 * certificate; it never mints or stores an inner-leg private key (D2 /
 * FR-CA-3).
 */
public interface SshCertSigner {

	/** The CA key type (fixes the cert format and signature algorithm). */
	CaKeyType keyType();

	/**
	 * The CA public-key blob (SSH wire form) — safe to publish; never private
	 * material.
	 */
	byte[] caPublicKeyBlob();

	/**
	 * The CA public key as a {@code TrustedUserCAKeys}/{@code authorized_keys} line
	 * ({@code "<key-type> <base64> <comment>"}). This is what a node trusts
	 * (FR-CA-2).
	 */
	String caAuthorizedKey(String comment);

	/** What algorithms this signer's backend can produce (FR-CA-4). */
	SignerCapabilities capabilities();

	/**
	 * Assemble and sign a full OpenSSH certificate for the presented public key.
	 */
	OpenSshCertificate signCertificate(CertificateRequest request);

	/**
	 * Sign the given to-be-signed bytes with the CA key, returning the normalized
	 * ECDSA {@code (r, s)} (FR-SIGN-2). Used by the shared assembler for raw-signer
	 * backends; a Vault-style backend that returns a cert directly may not support
	 * it.
	 */
	EcdsaSignatures.RS rawSign(byte[] toBeSigned);
}
