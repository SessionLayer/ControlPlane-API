package io.sessionlayer.controlplane.authz;

import java.nio.charset.StandardCharsets;

/**
 * Shared constants for signing and verifying a decision context (S5 produces,
 * S10's Gateway verifies). The domain-separation prefix ensures a
 * decision-context signature can never be mistaken for any other signature the
 * CP keys produce; the URI SAN marks the signer leaf.
 */
public final class DecisionContextSigning {

	/** Fixed domain-separation prefix prepended to the signed bytes. */
	public static final byte[] DOMAIN_PREFIX = "sessionlayer:decision-context:v1\n".getBytes(StandardCharsets.UTF_8);

	/** The URI SAN that marks a leaf as the decision-context signer. */
	public static final String SIGNER_URI = "sessionlayer://decision-context-signer";

	/** ECDSA over SHA-256 (matches the internal mTLS CA, D6). */
	public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

	private DecisionContextSigning() {
	}
}
