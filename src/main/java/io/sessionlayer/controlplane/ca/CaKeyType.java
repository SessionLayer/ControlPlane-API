package io.sessionlayer.controlplane.ca;

/**
 * The CA/certificate key types SessionLayer can assemble and sign. The default
 * is ECDSA P-256 (FR-CA-4 / D6 — portable; Azure Key Vault has no Ed25519). The
 * three NIST ECDSA curves share one wire structure (differing only in the curve
 * name and coordinate width), so all three are supported by the shared ECDSA
 * assembler; the value maps a {@code ca_config.algorithm} string to its OpenSSH
 * key-type name, certificate-format id, curve identifier, JCA parameters and
 * the SHA variant its signature uses.
 */
public enum CaKeyType {

	ECDSA_NISTP256("ecdsa-p256", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com", "nistp256",
			"secp256r1", "SHA256withECDSA", 32), ECDSA_NISTP384("ecdsa-p384", "ecdsa-sha2-nistp384",
					"ecdsa-sha2-nistp384-cert-v01@openssh.com", "nistp384", "secp384r1", "SHA384withECDSA",
					48), ECDSA_NISTP521("ecdsa-p521", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
							"nistp521", "secp521r1", "SHA512withECDSA", 66);

	private final String algorithmId;
	private final String keyTypeName;
	private final String certTypeName;
	private final String curveName;
	private final String jcaCurve;
	private final String signatureAlgorithm;
	private final int coordinateBytes;

	CaKeyType(String algorithmId, String keyTypeName, String certTypeName, String curveName, String jcaCurve,
			String signatureAlgorithm, int coordinateBytes) {
		this.algorithmId = algorithmId;
		this.keyTypeName = keyTypeName;
		this.certTypeName = certTypeName;
		this.curveName = curveName;
		this.jcaCurve = jcaCurve;
		this.signatureAlgorithm = signatureAlgorithm;
		this.coordinateBytes = coordinateBytes;
	}

	/** The {@code ca_config.algorithm} identifier, e.g. {@code ecdsa-p256}. */
	public String algorithmId() {
		return algorithmId;
	}

	/** The OpenSSH plain key-type name, e.g. {@code ecdsa-sha2-nistp256}. */
	public String keyTypeName() {
		return keyTypeName;
	}

	/** The OpenSSH certificate-format id, e.g. {@code ...-cert-v01@openssh.com}. */
	public String certTypeName() {
		return certTypeName;
	}

	/** The SSH curve identifier, e.g. {@code nistp256}. */
	public String curveName() {
		return curveName;
	}

	/** The JCA named-curve, e.g. {@code secp256r1}. */
	public String jcaCurve() {
		return jcaCurve;
	}

	/** The JCA {@code Signature} algorithm, e.g. {@code SHA256withECDSA}. */
	public String signatureAlgorithm() {
		return signatureAlgorithm;
	}

	/** Fixed width in bytes of each EC affine coordinate (r/s and X/Y). */
	public int coordinateBytes() {
		return coordinateBytes;
	}

	/**
	 * Resolve a {@code ca_config.algorithm} id, or throw if not an assemblable
	 * type.
	 */
	public static CaKeyType fromAlgorithmId(String algorithmId) {
		for (CaKeyType t : values()) {
			if (t.algorithmId.equals(algorithmId)) {
				return t;
			}
		}
		throw new IllegalArgumentException("unsupported/unassemblable CA algorithm: " + algorithmId
				+ " (SessionLayer assembles ECDSA P-256/P-384/P-521; default ecdsa-p256)");
	}

	/** Resolve by OpenSSH key-type name (e.g. {@code ecdsa-sha2-nistp256}). */
	public static CaKeyType fromKeyTypeName(String keyTypeName) {
		for (CaKeyType t : values()) {
			if (t.keyTypeName.equals(keyTypeName)) {
				return t;
			}
		}
		throw new IllegalArgumentException("unsupported SSH key type: " + keyTypeName);
	}
}
