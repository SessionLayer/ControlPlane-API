package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The signed-decision-context round trip + fail-closed verification (Part B).
 * Proves the reference {@link DecisionContextVerifier} S10 will port to Rust: a
 * valid signature over a signer leaf that chains to the internal mTLS CA and
 * carries the marker verifies; tampering, the wrong CA, or a non-signer leaf
 * all fail closed.
 */
class DecisionContextVerifierTest {

	private static final Instant NOT_BEFORE = Instant.now().minus(5, ChronoUnit.MINUTES);
	private static final Instant NOT_AFTER = Instant.now().plus(1, ChronoUnit.DAYS);

	@Test
	void validSignatureVerifiesAndTamperingFails() throws Exception {
		KeyPair ca = ec();
		X509Certificate caCert = X509Certificates.selfSignCa("test-mtls-ca", ca.getPublic(), ca.getPrivate(),
				BigInteger.valueOf(1), NOT_BEFORE, NOT_AFTER);
		KeyPair signer = ec();
		X509Certificate signerLeaf = X509Certificates.issueLeaf(caCert, ca.getPrivate(),
				new LeafCertificateSpec(signer.getPublic(), "decision-context-signer", List.of(),
						List.of(DecisionContextSigning.SIGNER_URI), LeafPurpose.CONTEXT_SIGNER, BigInteger.valueOf(2),
						NOT_BEFORE, NOT_AFTER));

		byte[] payload = "signed-decision-context-bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] signature = sign(signer.getPrivate(), payload);

		assertThat(DecisionContextVerifier.verify(caCert, signerLeaf.getEncoded(), payload, signature)).isTrue();

		byte[] tampered = payload.clone();
		tampered[0] ^= 0x01;
		assertThat(DecisionContextVerifier.verify(caCert, signerLeaf.getEncoded(), tampered, signature)).isFalse();
	}

	@Test
	void wrongCaFailsClosed() throws Exception {
		KeyPair ca = ec();
		X509Certificate caCert = X509Certificates.selfSignCa("mtls-ca", ca.getPublic(), ca.getPrivate(),
				BigInteger.valueOf(1), NOT_BEFORE, NOT_AFTER);
		KeyPair signer = ec();
		X509Certificate signerLeaf = X509Certificates.issueLeaf(caCert, ca.getPrivate(),
				new LeafCertificateSpec(signer.getPublic(), "decision-context-signer", List.of(),
						List.of(DecisionContextSigning.SIGNER_URI), LeafPurpose.CONTEXT_SIGNER, BigInteger.valueOf(2),
						NOT_BEFORE, NOT_AFTER));
		byte[] payload = "ctx".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] signature = sign(signer.getPrivate(), payload);

		KeyPair otherCa = ec();
		X509Certificate otherCaCert = X509Certificates.selfSignCa("other-ca", otherCa.getPublic(), otherCa.getPrivate(),
				BigInteger.valueOf(9), NOT_BEFORE, NOT_AFTER);
		assertThat(DecisionContextVerifier.verify(otherCaCert, signerLeaf.getEncoded(), payload, signature)).isFalse();
	}

	@Test
	void aNonSignerLeafCannotMasquerade() throws Exception {
		KeyPair ca = ec();
		X509Certificate caCert = X509Certificates.selfSignCa("mtls-ca", ca.getPublic(), ca.getPrivate(),
				BigInteger.valueOf(1), NOT_BEFORE, NOT_AFTER);
		KeyPair signer = ec();
		// A perfectly valid SERVER leaf from the same CA, but without the signer
		// marker.
		X509Certificate serverLeaf = X509Certificates.issueLeaf(caCert, ca.getPrivate(),
				new LeafCertificateSpec(signer.getPublic(), "cp-server", List.of("localhost"), List.of(),
						LeafPurpose.SERVER, BigInteger.valueOf(2), NOT_BEFORE, NOT_AFTER));
		byte[] payload = "ctx".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] signature = sign(signer.getPrivate(), payload);

		assertThat(DecisionContextVerifier.verify(caCert, serverLeaf.getEncoded(), payload, signature)).isFalse();
	}

	@Test
	void aMarkedLeafWithTheWrongEkuIsRejected() throws Exception {
		KeyPair ca = ec();
		X509Certificate caCert = X509Certificates.selfSignCa("mtls-ca", ca.getPublic(), ca.getPrivate(),
				BigInteger.valueOf(1), NOT_BEFORE, NOT_AFTER);
		KeyPair signer = ec();
		// A CLIENT leaf (clientAuth EKU) that even carries the signer SAN marker must
		// be
		// rejected — the verifier requires the codeSigning EKU, not the marker alone.
		X509Certificate clientLeaf = X509Certificates.issueLeaf(caCert, ca.getPrivate(),
				new LeafCertificateSpec(signer.getPublic(), "gw", List.of(), List.of(DecisionContextSigning.SIGNER_URI),
						LeafPurpose.CLIENT, BigInteger.valueOf(2), NOT_BEFORE, NOT_AFTER));
		byte[] payload = "ctx".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] signature = sign(signer.getPrivate(), payload);
		assertThat(DecisionContextVerifier.verify(caCert, clientLeaf.getEncoded(), payload, signature)).isFalse();
	}

	private static byte[] sign(PrivateKey key, byte[] payload) throws Exception {
		Signature signature = Signature.getInstance(DecisionContextSigning.SIGNATURE_ALGORITHM);
		signature.initSign(key);
		signature.update(DecisionContextSigning.DOMAIN_PREFIX);
		signature.update(payload);
		return signature.sign();
	}

	private static KeyPair ec() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		return generator.generateKeyPair();
	}
}
