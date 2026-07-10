package io.sessionlayer.controlplane.ca.backend.vault;

import java.util.List;
import java.util.Map;

/**
 * The injectable seam for the HashiCorp Vault SSH secrets engine (D2/D7, §3.3).
 * There is deliberately <b>only a sign operation</b>: production binds it to
 * {@code POST /v1/ssh/sign/:role}, which returns a <b>signed certificate</b>
 * for a presented public key. There is <b>no</b> {@code issue} method — Vault's
 * {@code /ssh/issue} (which mints and returns a private key) must never be
 * used, so the interface makes it structurally impossible (the CP never
 * receives an inner-leg private key). CI exercises this with a double; a
 * documented manual path binds the Vault HTTP client.
 */
public interface VaultSshEngine {

	/** Parameters for {@code POST /ssh/sign/:role} (no key generation). */
	record SignRequest(String keyId, List<String> validPrincipals, long ttlSeconds, Map<String, String> criticalOptions,
			List<String> extensions) {
	}

	/** The Vault-issued certificate (the {@code signed_key} field). */
	record SignedCertificate(String certificateLine) {
	}

	/**
	 * The engine's configured CA public key ({@code GET /ssh/config/ca}, public
	 * material).
	 */
	String caPublicKeyLine();

	/**
	 * Sign the presented public key via {@code POST /ssh/sign/:role} and return the
	 * signed certificate. MUST throw on failure (fail closed, FR-CA-9).
	 */
	SignedCertificate sign(String role, String publicKeyOpenSshLine, SignRequest request);
}
