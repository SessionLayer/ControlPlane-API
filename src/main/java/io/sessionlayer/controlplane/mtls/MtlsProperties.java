package io.sessionlayer.controlplane.mtls;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for the Session Four CP↔Gateway mTLS plane
 * ({@code sessionlayer.mtls.*}). This is the first {@code @ConfigurationProperties}
 * in the code base; the open values chosen this session live here with documented
 * defaults (RESULT §7):
 *
 * <ul>
 * <li><b>identity-cert-ttl</b> — the renewable Gateway mTLS identity cert TTL
 * (default 24h). Renew-ahead is the Gateway's loop; the CP only issues.</li>
 * <li><b>enrollment-token-ttl</b> — the single-use bootstrap enrollment token
 * TTL (default 10m).</li>
 * <li><b>session-signing-token-ttl</b> — the single-use session-signing token
 * TTL (default 120s).</li>
 * <li><b>cert-backdate</b> — how far issued certs are backdated for clock skew
 * (default 2m, FR-BOOT-4).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.mtls")
public class MtlsProperties {

	private final Server server = new Server();

	/** The renewable Gateway mTLS identity certificate TTL (FR-JOIN-4). */
	private Duration identityCertTtl = Duration.ofHours(24);

	/** The single-use Gateway enrollment token TTL (Design §4.B). */
	private Duration enrollmentTokenTtl = Duration.ofMinutes(10);

	/** The single-use session-signing token TTL (Design §15). */
	private Duration sessionSigningTokenTtl = Duration.ofSeconds(120);

	/** Backdating applied to issued certs' not-before for clock skew (FR-BOOT-4). */
	private Duration certBackdate = Duration.ofMinutes(2);

	public Server getServer() {
		return server;
	}

	public Duration getIdentityCertTtl() {
		return identityCertTtl;
	}

	public void setIdentityCertTtl(Duration identityCertTtl) {
		this.identityCertTtl = identityCertTtl;
	}

	public Duration getEnrollmentTokenTtl() {
		return enrollmentTokenTtl;
	}

	public void setEnrollmentTokenTtl(Duration enrollmentTokenTtl) {
		this.enrollmentTokenTtl = enrollmentTokenTtl;
	}

	public Duration getSessionSigningTokenTtl() {
		return sessionSigningTokenTtl;
	}

	public void setSessionSigningTokenTtl(Duration sessionSigningTokenTtl) {
		this.sessionSigningTokenTtl = sessionSigningTokenTtl;
	}

	public Duration getCertBackdate() {
		return certBackdate;
	}

	public void setCertBackdate(Duration certBackdate) {
		this.certBackdate = certBackdate;
	}

	/** The self-managed grpc-netty mTLS server binding. */
	public static class Server {

		/** Whether to start the mTLS gRPC server (off in the data-model ITs). */
		private boolean enabled = true;

		/** The listen port (0 = ephemeral, used by the ITs). */
		private int port = 9090;

		/** The bind address (authenticated channel, so may bind beyond loopback). */
		private String bindAddress = "0.0.0.0";

		/** SANs stamped into the CP's gRPC server certificate. */
		private List<String> hostnames = new ArrayList<>(List.of("localhost", "controlplane"));

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public int getPort() {
			return port;
		}

		public void setPort(int port) {
			this.port = port;
		}

		public String getBindAddress() {
			return bindAddress;
		}

		public void setBindAddress(String bindAddress) {
			this.bindAddress = bindAddress;
		}

		public List<String> getHostnames() {
			return hostnames;
		}

		public void setHostnames(List<String> hostnames) {
			this.hostnames = hostnames;
		}
	}
}
