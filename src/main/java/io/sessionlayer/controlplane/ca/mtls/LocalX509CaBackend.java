package io.sessionlayer.controlplane.ca.mtls;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * The local (in-process) internal-mTLS-CA backend: it signs leaf certificates
 * with an in-memory ECDSA CA private key that was decrypted transiently from
 * its KEK-wrapped form (mirrors {@code LocalCaBackend} for the SSH CAs). The
 * private key is a JCA {@link PrivateKey} that cannot itself be zeroized, so —
 * like the SSH local backend — the resident-key exposure is inherent to a local
 * software signer; production SHOULD use a cloud X.509 backend behind the
 * {@link X509CaBackend} seam so the CA key is never in-process.
 */
public final class LocalX509CaBackend implements X509CaBackend {

	private final X509Certificate caCertificate;
	private final PrivateKey caPrivateKey;

	public LocalX509CaBackend(X509Certificate caCertificate, PrivateKey caPrivateKey) {
		this.caCertificate = caCertificate;
		this.caPrivateKey = caPrivateKey;
	}

	@Override
	public X509Certificate caCertificate() {
		return caCertificate;
	}

	@Override
	public X509Certificate issueLeaf(LeafCertificateSpec spec) {
		return X509Certificates.issueLeaf(caCertificate, caPrivateKey, spec);
	}
}
