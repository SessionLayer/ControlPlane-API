package io.sessionlayer.controlplane.security;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * REST API security configuration (FR-AUTH-17). The three first-class schemes
 * (OIDC bearer, mTLS, client-credentials) are always on; HTTP <b>Basic</b> is
 * <b>not first-class</b> — off unless explicitly enabled behind mTLS + an IP
 * allow-list, and it emits a startup warning (a discouraged escape hatch,
 * Design §5.7).
 */
@ConfigurationProperties(prefix = "sessionlayer.rest-security")
public class SecurityProperties {

	private final BasicAuth basicAuth = new BasicAuth();

	public BasicAuth getBasicAuth() {
		return basicAuth;
	}

	public static class BasicAuth {
		/** Off by default (FR-AUTH-17). Enabling it is a discouraged escape hatch. */
		private boolean enabled = false;
		/** Source CIDRs the escape hatch is reachable from (deny-only gate). */
		private List<String> allowedCidrs = List.of();
		/** The single operator username the escape hatch authenticates. */
		private String username;
		/** BCrypt hash of the operator password (never a raw password). */
		private String passwordHash;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public List<String> getAllowedCidrs() {
			return allowedCidrs;
		}

		public void setAllowedCidrs(List<String> allowedCidrs) {
			this.allowedCidrs = allowedCidrs;
		}

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getPasswordHash() {
			return passwordHash;
		}

		public void setPasswordHash(String passwordHash) {
			this.passwordHash = passwordHash;
		}
	}
}
