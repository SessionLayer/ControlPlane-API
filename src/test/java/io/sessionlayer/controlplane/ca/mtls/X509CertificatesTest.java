package io.sessionlayer.controlplane.ca.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.mtls.MtlsTestSupport;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The internal-CA leaf shape, and in particular the <b>one EKU per leaf</b>
 * invariant {@link LeafPurpose} encodes. This is what forces a Gateway to hold
 * TWO leaves (S14): its clientAuth identity cert cannot serve TLS to an Agent,
 * so its agent-facing listener needs a separate serverAuth leaf.
 */
class X509CertificatesTest {

	private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
	private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
	private static final String CODE_SIGNING = "1.3.6.1.5.5.7.3.3";

	private static final Instant NOT_BEFORE = Instant.now().minus(Duration.ofMinutes(2));
	private static final Instant NOT_AFTER = NOT_BEFORE.plus(Duration.ofHours(24));

	@Test
	void serverPurposeStampsServerAuthAndNothingElse() throws Exception {
		X509Certificate leaf = issue(LeafPurpose.SERVER, List.of("gw-1"), List.of("sessionlayer://gateway/abc"));

		assertThat(leaf.getExtendedKeyUsage()).containsExactly(SERVER_AUTH);
		assertThat(leaf.getExtendedKeyUsage()).doesNotContain(CLIENT_AUTH, CODE_SIGNING);
	}

	@Test
	void clientPurposeStampsClientAuthAndNothingElse() throws Exception {
		X509Certificate leaf = issue(LeafPurpose.CLIENT, List.of("gw-1"), List.of("sessionlayer://gateway/abc"));

		// The reason a Gateway cannot serve TLS with its identity cert: an Agent
		// validating it as a SERVER certificate would (correctly) reject it.
		assertThat(leaf.getExtendedKeyUsage()).containsExactly(CLIENT_AUTH);
		assertThat(leaf.getExtendedKeyUsage()).doesNotContain(SERVER_AUTH);
	}

	@Test
	void contextSignerPurposeStampsCodeSigningAndNeitherTlsEku() throws Exception {
		X509Certificate leaf = issue(LeafPurpose.CONTEXT_SIGNER, List.of(), List.of());

		assertThat(leaf.getExtendedKeyUsage()).containsExactly(CODE_SIGNING);
		assertThat(leaf.getExtendedKeyUsage()).doesNotContain(SERVER_AUTH, CLIENT_AUTH);
	}

	@Test
	void sansComeOnlyFromTheSpec() throws Exception {
		X509Certificate leaf = issue(LeafPurpose.SERVER, List.of("gw-1"), List.of("sessionlayer://gateway/abc"));

		Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
		assertThat(sans).hasSize(2);
		assertThat(sanValues(sans, 2)).containsExactly("gw-1"); // dNSName
		assertThat(sanValues(sans, 6)).containsExactly("sessionlayer://gateway/abc"); // URI
		assertThat(leaf.getSubjectX500Principal().getName()).isEqualTo("CN=gw-1");
	}

	private static List<String> sanValues(Collection<List<?>> sans, int generalNameType) {
		return sans.stream().filter(san -> ((Integer) san.get(0)) == generalNameType).map(san -> (String) san.get(1))
				.toList();
	}

	private static X509Certificate issue(LeafPurpose purpose, List<String> dnsSans, List<String> uriSans) {
		KeyPair caKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate caCertificate = X509Certificates.selfSignCa("internal-ca", caKey.getPublic(),
				caKey.getPrivate(), BigInteger.ONE, NOT_BEFORE, NOT_AFTER);
		KeyPair leafKey = MtlsTestSupport.generateEcKeyPair();
		String subject = dnsSans.isEmpty() ? "cp-signer" : dnsSans.get(0);
		return X509Certificates.issueLeaf(caCertificate, caKey.getPrivate(), new LeafCertificateSpec(
				leafKey.getPublic(), subject, dnsSans, uriSans, purpose, BigInteger.TWO, NOT_BEFORE, NOT_AFTER));
	}
}
