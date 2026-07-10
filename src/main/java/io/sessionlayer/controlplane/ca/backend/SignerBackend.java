package io.sessionlayer.controlplane.ca.backend;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.SignerCapabilities;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.interfaces.ECPublicKey;

/**
 * The injectable raw-signer seam (FR-SIGN-1/2). A backend holds (or references)
 * a CA key and turns to-be-signed bytes into a <b>normalized</b> ECDSA
 * {@code (r, s)} — each backend converts its native signature shape (Java/KMS
 * DER, Azure P1363) to {@code (r, s)} so the shared assembler is
 * backend-agnostic.
 *
 * <p>
 * Implementations MUST fail closed (throw) if they cannot sign — never return a
 * wrong or empty signature (FR-CA-9). The Vault SSH-engine path does not use
 * this seam (it returns a signed cert directly).
 */
public interface SignerBackend {

	/** The CA key type this backend signs with. */
	CaKeyType keyType();

	/** The CA public key (public material only; never a private key). */
	ECPublicKey publicKey();

	/** What algorithms this backend can produce (FR-CA-4). */
	SignerCapabilities capabilities();

	/**
	 * Sign the to-be-signed bytes with the CA key and return the normalized ECDSA
	 * {@code (r, s)}. MUST throw (fail closed) on any signer failure.
	 */
	EcdsaSignatures.RS sign(byte[] toBeSigned);
}
