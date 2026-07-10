package io.sessionlayer.controlplane.ca;

/**
 * Capability/algorithm validation (FR-CA-4): what each CA backend can produce,
 * checked <b>at validation time</b> so a {@code ca_config} requesting an
 * algorithm the chosen backend cannot sign is rejected before it is ever used
 * (never a signing-time surprise).
 *
 * <p>
 * SessionLayer assembles only OpenSSH ECDSA certificates (P-256 default, D6),
 * so every backend advertises the three NIST ECDSA curves and nothing else — an
 * {@code ed25519} or {@code rsa-*} {@code ca_config} is rejected for any
 * backend this session, and Azure Key Vault having no Ed25519 is subsumed by
 * that.
 */
public final class CaBackendCapabilities {

	private CaBackendCapabilities() {
	}

	/**
	 * Thrown when a backend cannot produce the requested algorithm (FR-CA-4 /
	 * FR-API-5).
	 */
	public static final class AlgorithmNotSupported extends RuntimeException {
		public AlgorithmNotSupported(String backend, String algorithm) {
			super("CA backend '" + backend + "' cannot produce algorithm '" + algorithm
					+ "' (SessionLayer signs ECDSA P-256/P-384/P-521)");
		}
	}

	/** The algorithms a backend can produce. */
	public static SignerCapabilities forBackend(String backend) {
		return switch (backend) {
			case "local", "aws_kms", "azure_keyvault", "vault" ->
				SignerCapabilities.of(CaKeyType.ECDSA_NISTP256, CaKeyType.ECDSA_NISTP384, CaKeyType.ECDSA_NISTP521);
			default -> throw new IllegalArgumentException("unknown CA backend: " + backend);
		};
	}

	/** Reject a backend/algorithm mismatch at validation time (FR-CA-4). */
	public static void validate(String backend, String algorithm) {
		if (!forBackend(backend).supports(algorithm)) {
			throw new AlgorithmNotSupported(backend, algorithm);
		}
	}
}
