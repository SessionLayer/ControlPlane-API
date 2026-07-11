package io.sessionlayer.controlplane.oidc;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * OIDC relying-party + ID-token validation configuration (Design §5.2/§5.3,
 * FR-AUTH-6/7/8). One external IdP this session; the {@code oidc-mock}
 * container fills these in tests. The {@code algAllowList} is a <b>positive</b>
 * allow-list (reject {@code alg:none} and anything not listed);
 * {@code clockSkew} bounds {@code exp}/{@code iat}/{@code nbf} tolerance;
 * {@code groupsClaim} is the claim mapped server-side to RBAC groups
 * (FR-AUTH-8, never client-chosen principals).
 */
@ConfigurationProperties(prefix = "sessionlayer.oidc")
public class OidcProperties {

	/** Whether the OIDC relying party is configured (an issuer is present). */
	private boolean enabled = false;

	/** The IdP issuer URL (the {@code iss} the ID token must carry). */
	private String issuer;

	/** This CP's OIDC client id (the {@code aud} the ID token must carry). */
	private String clientId;

	/**
	 * The client secret, if the IdP requires one at the token endpoint (else null).
	 */
	private String clientSecret;

	/** The CP's public callback URL (the auth-code redirect_uri, FR-AUTH-6). */
	private String redirectUri;

	private List<String> scopes = List.of("openid", "profile", "email");

	/** Positive JWS-alg allow-list (FR-AUTH-7): reject {@code alg:none}/others. */
	private List<String> algAllowList = List.of("RS256", "ES256");

	/** Small skew for {@code exp}/{@code iat}/{@code nbf} (Design §5.3). */
	private Duration clockSkew = Duration.ofSeconds(60);

	/** JWKS cache TTL (keys rotated within this window). */
	private Duration jwksCacheTtl = Duration.ofMinutes(5);

	/** The claim carrying the user's groups (mapped server-side → RBAC groups). */
	private String groupsClaim = "groups";

	/** The claim used as the resolved identity (falls back to {@code sub}). */
	private String identityClaim = "email";

	/**
	 * Base64 HMAC key for deriving the PKCE verifier + nonce from {@code state}
	 * ({@link StateDerivation}). Leave unset for a per-boot random key (single
	 * instance); set a shared value across HA instances so a login begun on one
	 * instance can complete on another. Never the raw verifier/nonce — a key only.
	 */
	private String stateHmacKey;

	private final Device device = new Device();

	/** Device-flow (RFC 8628) knobs. */
	public static class Device {
		/** Poll interval advertised to the client (FR-AUTH-3). */
		private Duration pollInterval = Duration.ofSeconds(5);
		/** How long a device flow stays pending before it expires. */
		private Duration expiry = Duration.ofMinutes(10);
		/**
		 * If true, an approving-browser vs SSH source-context mismatch DENIES the flow
		 * (the enforceable binding, §5.2). Default false: the mismatch is flagged +
		 * audited (source IP is a deny-only reducer, not positive evidence —
		 * FR-AUTH-15); a legitimate user commonly approves from a different network
		 * than the SSH source. Operators enable enforcement where their network
		 * topology warrants it.
		 */
		private boolean enforceSourceMatch = false;

		public boolean isEnforceSourceMatch() {
			return enforceSourceMatch;
		}

		public void setEnforceSourceMatch(boolean enforceSourceMatch) {
			this.enforceSourceMatch = enforceSourceMatch;
		}

		public Duration getPollInterval() {
			return pollInterval;
		}

		public void setPollInterval(Duration pollInterval) {
			this.pollInterval = pollInterval;
		}

		public Duration getExpiry() {
			return expiry;
		}

		public void setExpiry(Duration expiry) {
			this.expiry = expiry;
		}
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public List<String> getScopes() {
		return scopes;
	}

	public void setScopes(List<String> scopes) {
		this.scopes = scopes;
	}

	public List<String> getAlgAllowList() {
		return algAllowList;
	}

	public void setAlgAllowList(List<String> algAllowList) {
		this.algAllowList = algAllowList;
	}

	public Duration getClockSkew() {
		return clockSkew;
	}

	public void setClockSkew(Duration clockSkew) {
		this.clockSkew = clockSkew;
	}

	public Duration getJwksCacheTtl() {
		return jwksCacheTtl;
	}

	public void setJwksCacheTtl(Duration jwksCacheTtl) {
		this.jwksCacheTtl = jwksCacheTtl;
	}

	public String getGroupsClaim() {
		return groupsClaim;
	}

	public void setGroupsClaim(String groupsClaim) {
		this.groupsClaim = groupsClaim;
	}

	public String getIdentityClaim() {
		return identityClaim;
	}

	public void setIdentityClaim(String identityClaim) {
		this.identityClaim = identityClaim;
	}

	public String getStateHmacKey() {
		return stateHmacKey;
	}

	public void setStateHmacKey(String stateHmacKey) {
		this.stateHmacKey = stateHmacKey;
	}

	public Device getDevice() {
		return device;
	}
}
