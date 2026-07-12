package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.mtls.MtlsTestSupport;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

/**
 * Unit-proves the MtlsJoin proof gate: a leaf chaining to the configured
 * operator CA, whose identity matches {@code node_name}, with a valid PoP over
 * THIS CSR, is accepted; a wrong-CA leaf, a wrong-node identity, a PoP over a
 * different CSR (replay), a tampered PoP, and a disabled verifier are each
 * refused. Pure crypto — no Spring/DB.
 */
class MtlsJoinVerifierTest {

	private static final Instant NB = Instant.now().minus(1, ChronoUnit.HOURS);
	private static final Instant NA = Instant.now().plus(1, ChronoUnit.HOURS);

	private final KeyPair operatorCaKey = MtlsTestSupport.generateEcKeyPair();
	private final X509Certificate operatorCa = X509Certificates.selfSignCa("operator-ca", operatorCaKey.getPublic(),
			operatorCaKey.getPrivate(), BigInteger.valueOf(1), NB, NA);

	@Test
	void acceptsValidChainIdentityAndPoP() {
		KeyPair leafKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate leaf = operatorLeaf("node-x", leafKey, operatorCa, operatorCaKey);
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");
		byte[] pop = pop(leafKey, csr);

		StepVerifier.create(verifier(operatorCa).verify(der(leaf), pop, "node-x", csr)).verifyComplete();
	}

	@Test
	void refusesLeafFromAnUntrustedCa() {
		KeyPair otherCaKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate otherCa = X509Certificates.selfSignCa("evil-ca", otherCaKey.getPublic(),
				otherCaKey.getPrivate(), BigInteger.valueOf(9), NB, NA);
		KeyPair leafKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate leaf = operatorLeaf("node-x", leafKey, otherCa, otherCaKey);
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");

		StepVerifier.create(verifier(operatorCa).verify(der(leaf), pop(leafKey, csr), "node-x", csr)).verifyError();
	}

	@Test
	void refusesWhenIdentityDoesNotMatchNode() {
		KeyPair leafKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate leaf = operatorLeaf("node-x", leafKey, operatorCa, operatorCaKey);
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-y");

		StepVerifier.create(verifier(operatorCa).verify(der(leaf), pop(leafKey, csr), "node-y", csr)).verifyError();
	}

	@Test
	void refusesPoPBoundToADifferentCsr() {
		KeyPair leafKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate leaf = operatorLeaf("node-x", leafKey, operatorCa, operatorCaKey);
		byte[] csrA = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");
		byte[] csrB = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");
		byte[] popOverA = pop(leafKey, csrA);

		// PoP signed over CSR A cannot enroll CSR B (replay defense).
		StepVerifier.create(verifier(operatorCa).verify(der(leaf), popOverA, "node-x", csrB)).verifyError();
	}

	@Test
	void refusesTamperedPoP() {
		KeyPair leafKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate leaf = operatorLeaf("node-x", leafKey, operatorCa, operatorCaKey);
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");
		byte[] pop = pop(leafKey, csr);
		pop[pop.length - 1] ^= 0x01;

		StepVerifier.create(verifier(operatorCa).verify(der(leaf), pop, "node-x", csr)).verifyError();
	}

	@Test
	void refusesWhenDisabled() {
		AgentJoinProperties props = new AgentJoinProperties();
		props.getMtls().setEnabled(false);
		props.getMtls().setOperatorCaPem(pem(operatorCa));
		KeyPair leafKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate leaf = operatorLeaf("node-x", leafKey, operatorCa, operatorCaKey);
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");

		StepVerifier.create(new MtlsJoinVerifier(props).verify(der(leaf), pop(leafKey, csr), "node-x", csr))
				.verifyError();
	}

	private static MtlsJoinVerifier verifier(X509Certificate operatorCa) {
		AgentJoinProperties props = new AgentJoinProperties();
		props.getMtls().setEnabled(true);
		props.getMtls().setOperatorCaPem(pem(operatorCa));
		return new MtlsJoinVerifier(props);
	}

	private static X509Certificate operatorLeaf(String cn, KeyPair leafKey, X509Certificate ca, KeyPair caKey) {
		return X509Certificates.issueLeaf(ca, caKey.getPrivate(), new LeafCertificateSpec(leafKey.getPublic(), cn,
				List.of(cn), List.of(), LeafPurpose.CLIENT, BigInteger.valueOf(System.nanoTime()), NB, NA));
	}

	private static byte[] pop(KeyPair leafKey, byte[] csr) {
		try {
			Signature sig = Signature.getInstance("SHA256withECDSA");
			sig.initSign(leafKey.getPrivate());
			sig.update(MtlsJoinVerifier.popMessage(csr));
			return sig.sign();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static byte[] der(X509Certificate cert) {
		try {
			return cert.getEncoded();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static String pem(X509Certificate cert) {
		return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der(cert))
				+ "\n-----END CERTIFICATE-----\n";
	}
}
