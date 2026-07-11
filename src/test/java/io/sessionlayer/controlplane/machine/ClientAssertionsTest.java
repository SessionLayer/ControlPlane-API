package io.sessionlayer.controlplane.machine;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;

class ClientAssertionsTest {

	@Test
	void parsesClaimsAndVerifiesWithMatchingKey() throws Exception {
		KeyPair key = rsa();
		String assertion = assertion(key, "svc-1", "jti-1", Instant.now().plusSeconds(60));

		ClientAssertions.Claims claims = ClientAssertions.parseUnverified(assertion);
		assertThat(claims.subject()).isEqualTo("svc-1");
		assertThat(claims.jti()).isEqualTo("jti-1");
		assertThat(claims.audience()).contains("sessionlayer://cp");

		assertThat(ClientAssertions.verify(assertion, key.getPublic())).isTrue();
	}

	@Test
	void rejectsSignatureFromAnotherKey() throws Exception {
		String assertion = assertion(rsa(), "svc-1", "jti-1", Instant.now().plusSeconds(60));
		assertThat(ClientAssertions.verify(assertion, rsa().getPublic())).isFalse();
	}

	@Test
	void parseOfGarbageIsNull() {
		assertThat(ClientAssertions.parseUnverified("not-a-jwt")).isNull();
	}

	private static KeyPair rsa() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		return gen.generateKeyPair();
	}

	private static String assertion(KeyPair key, String subject, String jti, Instant exp) throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(subject).subject(subject)
				.audience(List.of("sessionlayer://cp")).jwtID(jti).expirationTime(Date.from(exp)).build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
		jwt.sign(new RSASSASigner(key.getPrivate()));
		return jwt.serialize();
	}
}
