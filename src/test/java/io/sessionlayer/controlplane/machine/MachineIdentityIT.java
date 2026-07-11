package io.sessionlayer.controlplane.machine;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService.TokenRequest;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.test.StepVerifier;

/**
 * Machine identity (FR-AUTH-12): client-credentials via all three client-auth
 * methods + revocation.
 */
class MachineIdentityIT extends AbstractAuthIT {

	private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	@Autowired
	MachineIdentityService machineIdentity;
	@Autowired
	ServiceAccountRepository serviceAccounts;
	@Autowired
	MachineTokenSigner signer;

	@Test
	void privateKeyJwtIssuesATokenAndBlocksReplay() throws Exception {
		ServiceAccount sa = seedAccount("svc-pkjwt-" + UUID.randomUUID());
		KeyPair clientKey = rsa();
		machineIdentity.issueCredential(sa.id(), "private_key_jwt", pem(clientKey), null, null, null, "admin").block();

		String jti = "jti-" + UUID.randomUUID();
		String assertion = clientAssertion(clientKey, sa.name(), jti);
		var token = machineIdentity
				.issueToken(new TokenRequest("client_credentials", null, ASSERTION_TYPE, assertion, null, null), null,
						"203.0.113.10")
				.block();
		assertThat(token).isNotNull();
		assertThat(subjectOf(token.accessToken())).isEqualTo(sa.name());

		// Replaying the same assertion (same jti) is rejected.
		StepVerifier.create(machineIdentity.issueToken(
				new TokenRequest("client_credentials", null, ASSERTION_TYPE, assertion, null, null), null,
				"203.0.113.10")).verifyError(MachineIdentityService.TokenRequestDenied.class);
	}

	@Test
	void mtlsIssuesATokenByCertificateFingerprint() throws Exception {
		ServiceAccount sa = seedAccount("svc-mtls-" + UUID.randomUUID());
		X509Certificate cert = selfSigned();
		String fingerprint = CertificateFingerprints.sha256Hex(cert);
		machineIdentity.issueCredential(sa.id(), "mtls", null, null, fingerprint, null, "admin").block();

		var token = machineIdentity
				.issueToken(new TokenRequest("client_credentials", null, null, null, null, null), cert, "203.0.113.11")
				.block();
		assertThat(token).isNotNull();
		assertThat(subjectOf(token.accessToken())).isEqualTo(sa.name());
	}

	@Test
	void clientSecretIssuesATokenAndRevocationIsImmediate() {
		ServiceAccount sa = seedAccount("svc-secret-" + UUID.randomUUID());
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		assertThat(issued.clientSecret()).isNotBlank();

		var token = machineIdentity
				.issueToken(new TokenRequest("client_credentials", sa.name(), null, null, issued.clientSecret(), null),
						null, "203.0.113.12")
				.block();
		assertThat(token).isNotNull();

		machineIdentity.revokeCredential(sa.id(), issued.credential().id(), "admin").block();

		// A revoked credential can no longer obtain a new token (new sessions denied
		// immediately).
		StepVerifier.create(machineIdentity.issueToken(
				new TokenRequest("client_credentials", sa.name(), null, null, issued.clientSecret(), null), null,
				"203.0.113.12")).verifyError(MachineIdentityService.TokenRequestDenied.class);
	}

	private ServiceAccount seedAccount(String name) {
		return serviceAccounts.save(ServiceAccount.create(name, "test", "private_key_jwt", null, null, "api")).block();
	}

	private String subjectOf(String token) throws Exception {
		SignedJWT jwt = SignedJWT.parse(token);
		assertThat(jwt.verify(new RSASSAVerifier((RSAPublicKey) signer.publicKey()))).isTrue();
		return jwt.getJWTClaimsSet().getSubject();
	}

	private static String clientAssertion(KeyPair key, String subject, String jti) throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(subject).subject(subject)
				.audience(List.of("sessionlayer://cp")).jwtID(jti)
				.expirationTime(Date.from(Instant.now().plusSeconds(120))).build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
		jwt.sign(new RSASSASigner(key.getPrivate()));
		return jwt.serialize();
	}

	private static KeyPair rsa() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		return gen.generateKeyPair();
	}

	private static String pem(KeyPair key) {
		return "-----BEGIN PUBLIC KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getPublic().getEncoded())
				+ "\n-----END PUBLIC KEY-----\n";
	}

	private static X509Certificate selfSigned() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair kp = gen.generateKeyPair();
		Instant now = Instant.now();
		return X509Certificates.selfSignCa("svc-client", kp.getPublic(), kp.getPrivate(), BigInteger.valueOf(7),
				now.minusSeconds(60), now.plusSeconds(3600));
	}
}
