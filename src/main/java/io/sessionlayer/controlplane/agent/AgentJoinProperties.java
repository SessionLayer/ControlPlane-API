package io.sessionlayer.controlplane.agent;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for the Session Twelve Agent join &amp;
 * renewable-identity plane ({@code sessionlayer.agent-join.*}). Mirrors
 * {@code MtlsProperties} conventions. The durable Agent credential is the same
 * renewable internal mTLS X.509 identity the Gateway uses, so the cert
 * TTL/backdate default to the mtls values (independently tunable here); the
 * join methods add their own knobs:
 *
 * <ul>
 * <li><b>identity-cert-ttl</b> — the renewable Agent mTLS identity cert TTL
 * (default 24h). Renew-ahead (2/3 TTL ±10%) is the Agent's loop; the CP only
 * issues.</li>
 * <li><b>cert-backdate</b> — not-before backdating for clock skew (default 2m,
 * FR-BOOT-4).</li>
 * <li><b>join-token-ttl</b> — default single-use join-token TTL (default 10m);
 * short-lived by design.</li>
 * <li><b>join-token-max-ttl</b> — the ceiling a per-request TTL override is
 * clamped to (default 1h).</li>
 * <li><b>oidc.*</b> — the delegated-OIDC (workload identity) verifier config: a
 * distinct issuer from the user-facing OIDC RP, a positive alg allow-list, and
 * the claim bound to {@code node_name}. No shared secret (§8.1).</li>
 * <li><b>mtls.*</b> — the operator-PKI trust anchor (PEM) an MtlsJoin operator
 * certificate must chain to.</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.agent-join")
public class AgentJoinProperties {

	/** The renewable Agent mTLS identity certificate TTL (FR-JOIN-4). */
	private Duration identityCertTtl = Duration.ofHours(24);

	/**
	 * Backdating applied to issued certs' not-before for clock skew (FR-BOOT-4).
	 */
	private Duration certBackdate = Duration.ofMinutes(2);

	/** Default single-use join-token TTL (Design §8.1). */
	private Duration joinTokenTtl = Duration.ofMinutes(10);

	/** Ceiling a per-request join-token TTL override is clamped to. */
	private Duration joinTokenMaxTtl = Duration.ofHours(1);

	private final Oidc oidc = new Oidc();
	private final Mtls mtls = new Mtls();

	/**
	 * Delegated-OIDC (OidcJoin) verification config (Design §8.1, FR-JOIN-1). A
	 * workload OIDC token (K8s ServiceAccount / CI runner / cloud workload) is
	 * verified against this issuer's JWKS with the same rigor as the user-facing
	 * OIDC RP (§5.3) — a <b>positive</b> alg allow-list (reject {@code alg:none}),
	 * {@code iss}=={@link #issuer}, {@code aud} contains {@link #audience},
	 * {@code exp}/{@code nbf} within {@link #clockSkew} — then {@link #nodeClaim}'s
	 * value MUST equal the requested {@code node_name}. NO shared secret.
	 */
	public static class Oidc {

		/** Whether the OidcJoin method is configured/accepted. */
		private boolean enabled = false;

		/** The workload issuer URL (the {@code iss} the token must carry). */
		private String issuer;

		/** The issuer's JWKS URI (public signing keys; cached/rotated). */
		private String jwksUri;

		/** The audience the token must carry (the platform's agent-join audience). */
		private String audience;

		/** Positive JWS-alg allow-list (reject {@code alg:none}/others). */
		private List<String> allowedAlgs = List.of("RS256", "ES256");

		/** Small skew for {@code exp}/{@code iat}/{@code nbf}. */
		private Duration clockSkew = Duration.ofSeconds(60);

		/**
		 * The verified claim whose value must equal the requested {@code node_name}
		 * (the node-binding). Defaults to {@code sub}; set to a workload-specific claim
		 * (e.g. a custom {@code node_name} claim) that carries the node identity.
		 */
		private String nodeClaim = "sub";

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

		public String getJwksUri() {
			return jwksUri;
		}

		public void setJwksUri(String jwksUri) {
			this.jwksUri = jwksUri;
		}

		public String getAudience() {
			return audience;
		}

		public void setAudience(String audience) {
			this.audience = audience;
		}

		public List<String> getAllowedAlgs() {
			return allowedAlgs;
		}

		public void setAllowedAlgs(List<String> allowedAlgs) {
			this.allowedAlgs = allowedAlgs;
		}

		public Duration getClockSkew() {
			return clockSkew;
		}

		public void setClockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
		}

		public String getNodeClaim() {
			return nodeClaim;
		}

		public void setNodeClaim(String nodeClaim) {
			this.nodeClaim = nodeClaim;
		}
	}

	/**
	 * Operator-mTLS (MtlsJoin) verification config (Design §8.1, FR-JOIN-1). The
	 * operator's leaf certificate must chain to this trust anchor and be currently
	 * valid; its identity must match {@code node_name}; and a PoP signature must
	 * bind it to the enrollment CSR.
	 */
	public static class Mtls {

		/** Whether the MtlsJoin method is configured/accepted. */
		private boolean enabled = false;

		/** The operator CA trust anchor(s), PEM-encoded (one or more certificates). */
		private String operatorCaPem;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getOperatorCaPem() {
			return operatorCaPem;
		}

		public void setOperatorCaPem(String operatorCaPem) {
			this.operatorCaPem = operatorCaPem;
		}
	}

	public Duration getIdentityCertTtl() {
		return identityCertTtl;
	}

	public void setIdentityCertTtl(Duration identityCertTtl) {
		this.identityCertTtl = identityCertTtl;
	}

	public Duration getCertBackdate() {
		return certBackdate;
	}

	public void setCertBackdate(Duration certBackdate) {
		this.certBackdate = certBackdate;
	}

	public Duration getJoinTokenTtl() {
		return joinTokenTtl;
	}

	public void setJoinTokenTtl(Duration joinTokenTtl) {
		this.joinTokenTtl = joinTokenTtl;
	}

	public Duration getJoinTokenMaxTtl() {
		return joinTokenMaxTtl;
	}

	public void setJoinTokenMaxTtl(Duration joinTokenMaxTtl) {
		this.joinTokenMaxTtl = joinTokenMaxTtl;
	}

	public Oidc getOidc() {
		return oidc;
	}

	public Mtls getMtls() {
		return mtls;
	}
}
