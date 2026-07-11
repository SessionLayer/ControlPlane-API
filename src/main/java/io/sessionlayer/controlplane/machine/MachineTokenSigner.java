package io.sessionlayer.controlplane.machine;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Mints and holds the key for CP-issued machine-identity tokens (FR-AUTH-12). A
 * dedicated RSA keypair is generated once per boot and never persisted (like
 * the decision-context signer, S5): the CP is the only issuer and the only
 * verifier of these tokens this session, so the public half is handed to the
 * resource-server decoder in-process. Tokens are short-lived (Design §5.6), so
 * a per-boot key rotation is harmless — outstanding tokens expire quickly.
 */
@Component
public class MachineTokenSigner {

	private final MachineTokenProperties properties;
	private final KeyPair keyPair;
	private final RSASSASigner signer;

	public MachineTokenSigner(MachineTokenProperties properties) {
		this.properties = properties;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			this.keyPair = generator.generateKeyPair();
			this.signer = new RSASSASigner(keyPair.getPrivate());
		} catch (Exception e) {
			throw new IllegalStateException("failed to initialise the machine-token signing key", e);
		}
	}

	public RSAPublicKey publicKey() {
		return (RSAPublicKey) keyPair.getPublic();
	}

	/**
	 * Sign a machine token binding {@code identity} + {@code groups} (first-class
	 * RBAC principal, FR-AUTH-12). CPU-bound; callers run it off the event loop.
	 */
	public String mint(String identity, List<String> groups) {
		Instant now = Instant.now();
		Instant exp = now.plus(properties.getTokenTtl());
		try {
			JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(properties.getIssuer())
					.audience(properties.getAudience()).subject(identity).claim("groups", groups)
					.claim("token_type", "machine").jwtID(UUID.randomUUID().toString()).issueTime(Date.from(now))
					.notBeforeTime(Date.from(now)).expirationTime(Date.from(exp)).build();
			SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
			jwt.sign(signer);
			return jwt.serialize();
		} catch (Exception e) {
			throw new IllegalStateException("failed to sign a machine token", e);
		}
	}
}
