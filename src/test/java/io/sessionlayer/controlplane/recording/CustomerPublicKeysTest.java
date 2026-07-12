package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;

/**
 * SPKI validation of the operator-configured customer recording key (FR-AUD-2,
 * §15): only a well-formed EC P-256 (ECIES) or RSA (RSA-OAEP) <b>public</b> key
 * for the configured algorithm passes; garbage or a private key is refused so
 * BeginRecording fails closed.
 */
class CustomerPublicKeysTest {

	@Test
	void ecP256PublicKeyIsValidForEcies() throws Exception {
		byte[] der = ec().getPublic().getEncoded();
		assertThat(CustomerPublicKeys.isValid(der, "ecies_p256")).isTrue();
		assertThat(CustomerPublicKeys.isValid(der, "rsa_oaep_sha256")).isFalse();
	}

	@Test
	void rsaPublicKeyIsValidForRsaOaep() throws Exception {
		byte[] der = rsa().getPublic().getEncoded();
		assertThat(CustomerPublicKeys.isValid(der, "rsa_oaep_sha256")).isTrue();
		assertThat(CustomerPublicKeys.isValid(der, "ecies_p256")).isFalse();
	}

	@Test
	void aPrivateKeyIsRejected() throws Exception {
		byte[] pkcs8 = ec().getPrivate().getEncoded();
		assertThat(CustomerPublicKeys.isValid(pkcs8, "ecies_p256")).isFalse();
	}

	@Test
	void garbageAndEmptyAreRejected() {
		assertThat(CustomerPublicKeys.isValid("not-a-key".getBytes(), "ecies_p256")).isFalse();
		assertThat(CustomerPublicKeys.isValid(new byte[0], "ecies_p256")).isFalse();
		assertThat(CustomerPublicKeys.isValid(null, "ecies_p256")).isFalse();
	}

	private static KeyPair ec() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		return generator.generateKeyPair();
	}

	private static KeyPair rsa() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}
}
