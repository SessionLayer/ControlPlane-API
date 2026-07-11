package io.sessionlayer.controlplane.machine;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

/**
 * Parsing + signature verification for OAuth {@code private_key_jwt} client
 * assertions (RFC 7523, FR-AUTH-12). The unverified claims
 * (subject/jti/aud/exp) are read to locate the client's registered public key;
 * the signature is then verified against that key. No JWKS fetch this session —
 * the SA's public key is registered as its credential (a documented JWKS-URI
 * variant is future work).
 */
final class ClientAssertions {

	private ClientAssertions() {
	}

	record Claims(String subject, String jti, Instant expiresAt, List<String> audience) {
	}

	static Claims parseUnverified(String assertion) {
		try {
			var set = SignedJWT.parse(assertion).getJWTClaimsSet();
			Instant exp = set.getExpirationTime() == null ? null : set.getExpirationTime().toInstant();
			return new Claims(set.getSubject(), set.getJWTID(), exp,
					set.getAudience() == null ? List.of() : set.getAudience());
		} catch (Exception malformed) {
			return null;
		}
	}

	static boolean verify(String assertion, PublicKey key) {
		try {
			SignedJWT jwt = SignedJWT.parse(assertion);
			JWSVerifier verifier = switch (key) {
				case RSAPublicKey rsa -> new RSASSAVerifier(rsa);
				case ECPublicKey ec -> new ECDSAVerifier(ec);
				default -> null;
			};
			return verifier != null && jwt.verify(verifier);
		} catch (Exception invalid) {
			return false;
		}
	}
}
