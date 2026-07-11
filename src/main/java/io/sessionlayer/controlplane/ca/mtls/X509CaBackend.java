package io.sessionlayer.controlplane.ca.mtls;

import java.security.cert.X509Certificate;

/**
 * The internal mTLS CA signing seam (X.509). Mirrors the SSH cloud-backend
 * seams
 * ({@code KmsCaBackend}/{@code AzureKeyVaultCaBackend}/{@code VaultSshEngine}):
 * a single injectable interface behind which the CA private key lives, so a
 * cloud X.509 backend (KMS/Key Vault CA) can be dropped in without changing the
 * enrollment/renewal/server-cert code.
 *
 * <p>
 * Only {@link LocalX509CaBackend} (KEK-wrapped local key) is implemented for
 * real this session; the cloud seam is unit-tested with a double. Whatever the
 * backend, the CP only ever <b>signs a presented public key</b> and returns a
 * certificate — it never receives or stores a leaf private key (D2/FR-CA-3).
 */
public interface X509CaBackend {

	/** The X.509 CA certificate (trust anchor) this backend issues leaves from. */
	X509Certificate caCertificate();

	/**
	 * Issue a leaf certificate for {@code spec}, signed by the internal CA. The
	 * subject public key is certified as-is; no private key is involved.
	 */
	X509Certificate issueLeaf(LeafCertificateSpec spec);
}
