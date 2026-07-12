package io.sessionlayer.controlplane.support;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A minimal, fully-controllable OIDC provider for the relying-party ITs: it
 * serves real {@code .well-known/openid-configuration} + JWKS and a token
 * endpoint that returns a genuinely RS256-signed ID token for a pre-registered
 * authorization code (with the nonce/claims the test wants). Unlike driving a
 * container IdP's interactive browser login, this exercises the CP's RP code
 * paths — discovery, JWKS fetch/validation, PKCE code exchange, ID-token
 * signature + iss/aud/nonce checks — deterministically and headlessly. The
 * Soluto {@code oidc-mock} container remains available for manual/compose E2E.
 */
public final class StubIdp implements AutoCloseable {

	private final HttpServer server;
	private final String issuer;
	private final KeyPair keyPair;
	private final RSAKey jwk;
	private final Map<String, JWTClaimsSet> codes = new ConcurrentHashMap<>();

	public StubIdp(String clientId) throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		this.keyPair = gen.generateKeyPair();
		this.jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).keyID("stub-1").build();
		this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		this.issuer = "http://127.0.0.1:" + server.getAddress().getPort();

		server.createContext("/.well-known/openid-configuration",
				ex -> json(ex,
						"{" + "\"issuer\":\"" + issuer + "\"," + "\"authorization_endpoint\":\"" + issuer
								+ "/authorize\"," + "\"token_endpoint\":\"" + issuer + "/token\"," + "\"jwks_uri\":\""
								+ issuer + "/jwks\"}"));
		server.createContext("/jwks", ex -> json(ex, "{\"keys\":[" + jwk.toPublicJWK().toJSONString() + "]}"));
		server.createContext("/token", ex -> {
			String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			String code = param(body, "code");
			JWTClaimsSet claims = code == null ? null : codes.remove(code);
			if (claims == null) {
				json(ex, 400, "{\"error\":\"invalid_grant\"}");
				return;
			}
			try {
				json(ex, "{\"access_token\":\"opaque\",\"token_type\":\"Bearer\",\"id_token\":\"" + sign(claims)
						+ "\"}");
			} catch (Exception signingFailed) {
				json(ex, 500, "{\"error\":\"server_error\"}");
			}
		});
		server.start();
	}

	public String issuer() {
		return issuer;
	}

	/**
	 * Register a code so the next {@code /token} call returns an ID token with
	 * these claims.
	 */
	public void registerCode(String code, String subject, String email, List<String> groups, String aud, String nonce,
			Instant expiry) {
		JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().issuer(issuer).subject(subject).audience(aud)
				.issueTime(Date.from(Instant.now().minusSeconds(5))).expirationTime(Date.from(expiry));
		if (email != null) {
			b.claim("email", email);
		}
		if (groups != null) {
			b.claim("groups", groups);
		}
		if (nonce != null) {
			b.claim("nonce", nonce);
		}
		codes.put(code, b.build());
	}

	/**
	 * Mint a standalone RS256-signed workload token (the OidcJoin proof, S12): iss
	 * = this issuer, the given audience, and {@code claimName=claimValue} (the
	 * node-binding claim). Verified by the CP against this stub's JWKS.
	 */
	public String workloadToken(String audience, String claimName, String claimValue, Instant expiry) {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer).subject("workload-sa").audience(audience)
				.claim(claimName, claimValue).issueTime(Date.from(Instant.now().minusSeconds(5)))
				.expirationTime(Date.from(expiry)).build();
		try {
			return sign(claims);
		} catch (Exception signingFailed) {
			throw new IllegalStateException("failed to sign workload token", signingFailed);
		}
	}

	private String sign(JWTClaimsSet claims) throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("stub-1").build(), claims);
		jwt.sign(new RSASSASigner(keyPair.getPrivate()));
		return jwt.serialize();
	}

	private static String param(String form, String key) {
		for (String pair : form.split("&")) {
			int eq = pair.indexOf('=');
			if (eq > 0 && java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8).equals(key)) {
				return java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
			}
		}
		return null;
	}

	private static void json(com.sun.net.httpserver.HttpExchange ex, String body) throws java.io.IOException {
		json(ex, 200, body);
	}

	private static void json(com.sun.net.httpserver.HttpExchange ex, int status, String body)
			throws java.io.IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().add("Content-Type", "application/json");
		ex.sendResponseHeaders(status, bytes.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(bytes);
		}
	}

	@Override
	public void close() {
		server.stop(0);
	}
}
