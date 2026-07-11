package io.sessionlayer.controlplane.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * Faithful FR-AUTH-7 validation gates: the ID-token decoder is built with the
 * same positive alg allow-list + iss/aud/exp validators {@link IdpJwtDecoder}
 * uses (here with a controllable local key), and {@link IdTokenValidator} adds
 * the nonce + claims→identity/groups mapping. Proves {@code alg:none}, a
 * wrong-key signature, a bad iss/aud, an expired token, and a bad nonce are
 * each rejected, and a valid token accepted.
 */
class OidcJwtValidationTest {

	private static final String ISS = "https://idp.example";
	private static final String AUD = "sessionlayer-cp";

	private static KeyPair rsa;
	private static KeyPair otherRsa;
	private static ReactiveJwtDecoder decoder;

	@BeforeAll
	static void keys() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		rsa = gen.generateKeyPair();
		otherRsa = gen.generateKeyPair();
		decoder = buildDecoder((RSAPublicKey) rsa.getPublic());
	}

	// Mirrors IdpJwtDecoder.build(): only the allow-listed alg (RS256 via
	// withPublicKey) is accepted (alg:none/others rejected), plus iss/aud/exp.
	private static ReactiveJwtDecoder buildDecoder(RSAPublicKey publicKey) {
		NimbusReactiveJwtDecoder d = NimbusReactiveJwtDecoder.withPublicKey(publicKey).build();
		OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience() != null && jwt.getAudience().contains(AUD)
				? OAuth2TokenValidatorResult.success()
				: OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
		d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(), new JwtIssuerValidator(ISS),
				audience));
		return d;
	}

	@Test
	void validTokenIsAccepted() throws Exception {
		StepVerifier.create(decoder.decode(idToken(rsa, ISS, AUD, Instant.now().plusSeconds(300), "n-1")))
				.assertNext(jwt -> assertThat(jwt.getSubject()).isEqualTo("sub-1")).verifyComplete();
	}

	@Test
	void algNoneIsRejected() throws Exception {
		PlainJWT plain = new PlainJWT(claims(ISS, AUD, Instant.now().plusSeconds(300), "n-1").build());
		StepVerifier.create(decoder.decode(plain.serialize())).verifyError();
	}

	@Test
	void wrongKeySignatureIsRejected() throws Exception {
		StepVerifier.create(decoder.decode(idToken(otherRsa, ISS, AUD, Instant.now().plusSeconds(300), "n-1")))
				.verifyError();
	}

	@Test
	void badIssuerIsRejected() throws Exception {
		StepVerifier
				.create(decoder
						.decode(idToken(rsa, "https://evil.example", AUD, Instant.now().plusSeconds(300), "n-1")))
				.verifyError();
	}

	@Test
	void badAudienceIsRejected() throws Exception {
		StepVerifier
				.create(decoder.decode(idToken(rsa, ISS, "some-other-client", Instant.now().plusSeconds(300), "n-1")))
				.verifyError();
	}

	@Test
	void expiredTokenIsRejected() throws Exception {
		StepVerifier.create(decoder.decode(idToken(rsa, ISS, AUD, Instant.now().minusSeconds(120), "n-1")))
				.verifyError();
	}

	@Test
	void validatorRejectsBadNonceAndResolvesGroups() {
		IdpJwtDecoder mockDecoder = mock(IdpJwtDecoder.class);
		OidcProperties props = new OidcProperties();
		props.setGroupsClaim("groups");
		props.setIdentityClaim("email");
		Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "sub-1")
				.claim("email", "alice@example.com").claim("groups", List.of("admins", "sre")).claim("nonce", "n-1")
				.issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build();
		when(mockDecoder.decode("t")).thenReturn(Mono.just(jwt));
		IdTokenValidator validator = new IdTokenValidator(mockDecoder, props);

		StepVerifier.create(validator.validate("t", "n-1")).assertNext(resolved -> {
			assertThat(resolved.identity()).isEqualTo("alice@example.com");
			assertThat(resolved.groups()).containsExactlyInAnyOrder("admins", "sre");
		}).verifyComplete();

		StepVerifier.create(validator.validate("t", "wrong-nonce")).verifyError();
	}

	@Test
	void resolveFallsBackToSubWhenIdentityClaimAbsent() {
		IdpJwtDecoder mockDecoder = mock(IdpJwtDecoder.class);
		OidcProperties props = new OidcProperties();
		Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "sub-only").issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(300)).build();
		IdTokenValidator validator = new IdTokenValidator(mockDecoder, props);
		assertThat(validator.resolve(jwt).identity()).isEqualTo("sub-only");
	}

	private static String idToken(KeyPair key, String iss, String aud, Instant exp, String nonce) throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims(iss, aud, exp, nonce).build());
		jwt.sign(new RSASSASigner(key.getPrivate()));
		return jwt.serialize();
	}

	private static JWTClaimsSet.Builder claims(String iss, String aud, Instant exp, String nonce) {
		return new JWTClaimsSet.Builder().issuer(iss).audience(aud).subject("sub-1").claim("email", "alice@example.com")
				.claim("nonce", nonce).issueTime(Date.from(Instant.now().minusSeconds(5)))
				.expirationTime(Date.from(exp)).claim("extra", Map.of());
	}
}
