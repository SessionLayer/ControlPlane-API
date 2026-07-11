package io.sessionlayer.controlplane.ca.cert;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.cert.UserCertificateVerifier.Verdict;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The pure user-certificate verifier (Design §3.1, FR-CA-2). Exercises the
 * unforgiving trust decision in isolation: a trusted ECDSA-CA-signed user cert
 * resolves; a tampered signature, a wrong CA, a host cert, an unknown critical
 * option, and an out-of-window cert each fail closed; and a non-ECDSA certified
 * key (ed25519) is parsed correctly (the CA signature is what is verified, not
 * the certified key).
 */
class UserCertificateVerifierTest {

	private static final Duration SKEW = Duration.ofSeconds(60);
	private final KeyPair caKey = ecKeyPair();
	private final String caLine = SshEcdsaPublicKeys.toAuthorizedKey((ECPublicKey) caKey.getPublic(),
			CaKeyType.ECDSA_NISTP256, "user-ca");
	private final byte[] caBlob = SshEcdsaPublicKeys.encode((ECPublicKey) caKey.getPublic(), CaKeyType.ECDSA_NISTP256);

	@Test
	void trustedInWindowUserCertResolves() {
		byte[] cert = ecdsaCert(CertType.USER, "alice@corp", List.of("deploy", "ops"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), new TreeMap<>());
		Verdict verdict = UserCertificateVerifier.verify(cert, List.of(caLine), "10.0.0.5", Instant.now(), SKEW);
		assertThat(verdict.resolved()).isTrue();
		assertThat(verdict.identity()).isEqualTo("alice@corp");
		assertThat(verdict.principals()).containsExactly("deploy", "ops");
	}

	@Test
	void untrustedCaFailsClosed() {
		byte[] cert = ecdsaCert(CertType.USER, "alice@corp", List.of("deploy"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), new TreeMap<>());
		String otherCa = SshEcdsaPublicKeys.toAuthorizedKey((ECPublicKey) ecKeyPair().getPublic(),
				CaKeyType.ECDSA_NISTP256, "other");
		Verdict verdict = UserCertificateVerifier.verify(cert, List.of(otherCa), "10.0.0.5", Instant.now(), SKEW);
		assertThat(verdict.resolved()).isFalse();
	}

	@Test
	void tamperedSignatureFailsClosed() {
		byte[] cert = ecdsaCert(CertType.USER, "alice@corp", List.of("deploy"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), new TreeMap<>());
		cert[cert.length - 1] ^= 0x01; // flip a signature byte
		assertThat(UserCertificateVerifier.verify(cert, List.of(caLine), "10.0.0.5", Instant.now(), SKEW).resolved())
				.isFalse();
	}

	@Test
	void hostCertFailsClosed() {
		byte[] cert = ecdsaCert(CertType.HOST, "node1", List.of("node1"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), new TreeMap<>());
		assertThat(UserCertificateVerifier.verify(cert, List.of(caLine), "10.0.0.5", Instant.now(), SKEW).resolved())
				.isFalse();
	}

	@Test
	void expiredCertFailsClosed() {
		byte[] cert = ecdsaCert(CertType.USER, "alice@corp", List.of("deploy"), Instant.now().minusSeconds(7200),
				Instant.now().minusSeconds(3600), new TreeMap<>());
		assertThat(UserCertificateVerifier.verify(cert, List.of(caLine), "10.0.0.5", Instant.now(), SKEW).resolved())
				.isFalse();
	}

	@Test
	void unknownCriticalOptionFailsClosed() {
		TreeMap<String, String> critical = new TreeMap<>(CertificateParameters.BYTE_ORDER);
		critical.put("mystery-option", "value");
		byte[] cert = ecdsaCert(CertType.USER, "alice@corp", List.of("deploy"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), critical);
		assertThat(UserCertificateVerifier.verify(cert, List.of(caLine), "10.0.0.5", Instant.now(), SKEW).resolved())
				.isFalse();
	}

	@Test
	void sourceAddressIsEnforcedDenyOnly() {
		TreeMap<String, String> critical = new TreeMap<>(CertificateParameters.BYTE_ORDER);
		critical.put("source-address", "10.20.0.0/16");
		byte[] cert = ecdsaCert(CertType.USER, "alice@corp", List.of("deploy"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), critical);
		assertThat(UserCertificateVerifier.verify(cert, List.of(caLine), "203.0.113.1", Instant.now(), SKEW).resolved())
				.isFalse();
		assertThat(UserCertificateVerifier.verify(cert, List.of(caLine), "10.20.0.9", Instant.now(), SKEW).resolved())
				.isTrue();
	}

	@Test
	void ed25519CertifiedKeyIsParsedAndVerified() {
		// A cert whose certified key is ed25519 (one type-specific field) but signed by
		// our ECDSA user CA — the skip map must land on `serial`, and the ECDSA CA
		// signature is what is verified.
		byte[] tbs = ed25519UserCertTbs("bob@corp", List.of("deploy"));
		byte[] cert = new SshWriter().writeBytes(tbs).writeString(sign(tbs)).toByteArray();
		Verdict verdict = UserCertificateVerifier.verify(cert, List.of(caLine), "10.0.0.5", Instant.now(), SKEW);
		assertThat(verdict.resolved()).isTrue();
		assertThat(verdict.identity()).isEqualTo("bob@corp");
	}

	// ---- cert construction helpers ----------------------------------------

	private byte[] ecdsaCert(CertType type, String keyId, List<String> principals, Instant after, Instant before,
			TreeMap<String, String> critical) {
		OpenSshCertificateAssembler assembler = new OpenSshCertificateAssembler(new SecureRandom());
		KeyPair subject = ecKeyPair();
		byte[] certifiedKeyBody = SshEcdsaPublicKeys.encodeCurveAndPoint((ECPublicKey) subject.getPublic(),
				CaKeyType.ECDSA_NISTP256);
		TreeMap<String, String> sortedCritical = new TreeMap<>(CertificateParameters.BYTE_ORDER);
		sortedCritical.putAll(critical);
		CertificateParameters params = new CertificateParameters(1L, type, keyId, principals, after, before,
				sortedCritical, new TreeSet<>(CertificateParameters.BYTE_ORDER));
		byte[] tbs = assembler.buildToBeSigned(CaKeyType.ECDSA_NISTP256, assembler.newNonce(), certifiedKeyBody, params,
				caBlob);
		return assembler.assembleSigned(tbs, sign(tbs));
	}

	private byte[] ed25519UserCertTbs(String keyId, List<String> principals) {
		byte[] fakeEd25519Pk = new byte[32];
		new SecureRandom().nextBytes(fakeEd25519Pk);
		byte[] nonce = new byte[32];
		new SecureRandom().nextBytes(nonce);
		SshWriter principalsField = new SshWriter();
		principals.forEach(principalsField::writeString);
		return new SshWriter().writeString("ssh-ed25519-cert-v01@openssh.com").writeString(nonce)
				.writeString(fakeEd25519Pk) // the single certified-key type-specific field
				.writeUint64(1L).writeUint32(CertType.USER.value()).writeString(keyId)
				.writeString(principalsField.toByteArray()).writeUint64(Instant.now().minusSeconds(60).getEpochSecond())
				.writeUint64(Instant.now().plusSeconds(600).getEpochSecond()).writeString(new byte[0]) // critical
				.writeString(new byte[0]) // extensions
				.writeString(new byte[0]) // reserved
				.writeString(caBlob) // signature key
				.toByteArray();
	}

	private byte[] sign(byte[] tbs) {
		try {
			Signature signer = Signature.getInstance("SHA256withECDSA");
			signer.initSign((PrivateKey) caKey.getPrivate());
			signer.update(tbs);
			EcdsaSignatures.RS rs = EcdsaSignatures.fromDer(signer.sign());
			return EcdsaSignatures.encodeSignatureBlob(CaKeyType.ECDSA_NISTP256, rs);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static KeyPair ecKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			return generator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
}
