package io.sessionlayer.controlplane.agent;

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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.test.StepVerifier;

/**
 * Faithful FR-JOIN-1 (OidcJoin) validation gates — the same rigor as the S6
 * OIDC RP. The decoder is built with the exact
 * {@link OidcJoinVerifier#jwtValidator} wiring (here over a controllable key),
 * proving {@code alg:none}, a wrong-key signature, a bad iss/aud, and an
 * expired token are each rejected and a valid token accepted; plus that
 * {@link OidcJoinVerifier#verify} fails closed when the method is disabled or
 * the token is blank.
 */
class OidcJoinVerifierTest {

	private static final String ISS = "https://workload-idp.example";
	private static final String AUD = "sessionlayer-agents";

	private static KeyPair rsa;
	private static KeyPair otherRsa;
	private static ReactiveJwtDecoder decoder;

	@BeforeAll
	static void keys() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		rsa = gen.generateKeyPair();
		otherRsa = gen.generateKeyPair();
		NimbusReactiveJwtDecoder d = NimbusReactiveJwtDecoder.withPublicKey((RSAPublicKey) rsa.getPublic()).build();
		d.setJwtValidator(OidcJoinVerifier.jwtValidator(oidc()));
		decoder = d;
	}

	@Test
	void validTokenIsAccepted() throws Exception {
		StepVerifier.create(decoder.decode(token(rsa, ISS, AUD, Instant.now().plusSeconds(300))))
				.assertNext(jwt -> org.assertj.core.api.Assertions.assertThat(jwt.getClaimAsString("node_name"))
						.isEqualTo("node-x"))
				.verifyComplete();
	}

	@Test
	void algNoneIsRejected() {
		PlainJWT plain = new PlainJWT(claims(ISS, AUD, Instant.now().plusSeconds(300)).build());
		StepVerifier.create(decoder.decode(plain.serialize())).verifyError();
	}

	@Test
	void wrongKeySignatureIsRejected() throws Exception {
		StepVerifier.create(decoder.decode(token(otherRsa, ISS, AUD, Instant.now().plusSeconds(300)))).verifyError();
	}

	@Test
	void badIssuerIsRejected() throws Exception {
		StepVerifier.create(decoder.decode(token(rsa, "https://evil.example", AUD, Instant.now().plusSeconds(300))))
				.verifyError();
	}

	@Test
	void badAudienceIsRejected() throws Exception {
		StepVerifier.create(decoder.decode(token(rsa, ISS, "some-other-audience", Instant.now().plusSeconds(300))))
				.verifyError();
	}

	@Test
	void expiredTokenIsRejected() throws Exception {
		StepVerifier.create(decoder.decode(token(rsa, ISS, AUD, Instant.now().minusSeconds(120)))).verifyError();
	}

	@Test
	void verifyFailsClosedWhenDisabled() {
		AgentJoinProperties props = new AgentJoinProperties();
		props.getOidc().setEnabled(false);
		StepVerifier.create(new OidcJoinVerifier(props).verify("any.jwt.here", "node-x")).verifyError();
	}

	@Test
	void verifyFailsClosedOnBlankToken() {
		AgentJoinProperties props = new AgentJoinProperties();
		props.getOidc().setEnabled(true);
		props.getOidc().setIssuer(ISS);
		props.getOidc().setJwksUri(ISS + "/jwks");
		props.getOidc().setAudience(AUD);
		StepVerifier.create(new OidcJoinVerifier(props).verify("  ", "node-x")).verifyError();
	}

	private static AgentJoinProperties.Oidc oidc() {
		AgentJoinProperties.Oidc oidc = new AgentJoinProperties.Oidc();
		oidc.setEnabled(true);
		oidc.setIssuer(ISS);
		oidc.setAudience(AUD);
		oidc.setNodeClaim("node_name");
		return oidc;
	}

	private static String token(KeyPair key, String iss, String aud, Instant exp) throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims(iss, aud, exp).build());
		jwt.sign(new RSASSASigner(key.getPrivate()));
		return jwt.serialize();
	}

	private static JWTClaimsSet.Builder claims(String iss, String aud, Instant exp) {
		return new JWTClaimsSet.Builder().issuer(iss).audience(aud).subject("workload-1").claim("node_name", "node-x")
				.issueTime(Date.from(Instant.now().minusSeconds(5))).expirationTime(Date.from(exp));
	}
}
