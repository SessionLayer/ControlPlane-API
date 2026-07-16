package io.sessionlayer.controlplane.mtls;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for the Session Four CP↔Gateway mTLS plane
 * ({@code sessionlayer.mtls.*}). This is the first
 * {@code @ConfigurationProperties} in the code base; the open values chosen
 * this session live here with documented defaults (RESULT §7):
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

	/**
	 * The Gateway OUTER SSH host-certificate TTL (S16, FR-ADDR-1). Short-lived; the
	 * Gateway re-fetches before expiry to rotate. Backdated by
	 * {@link #certBackdate}.
	 */
	private Duration hostCertTtl = Duration.ofHours(1);

	/**
	 * Backdating applied to issued certs' not-before for clock skew (FR-BOOT-4).
	 */
	private Duration certBackdate = Duration.ofMinutes(2);

	/**
	 * Server-side deadline applied to every mTLS RPC handler (M3): a hung DB /
	 * saturated R2DBC pool surfaces as {@code DEADLINE_EXCEEDED} rather than a hung
	 * call. The Gateway sets its own client deadline too.
	 */
	private Duration rpcTimeout = Duration.ofSeconds(15);

	public Server getServer() {
		return server;
	}

	public Duration getRpcTimeout() {
		return rpcTimeout;
	}

	public void setRpcTimeout(Duration rpcTimeout) {
		this.rpcTimeout = rpcTimeout;
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

	public Duration getHostCertTtl() {
		return hostCertTtl;
	}

	public void setHostCertTtl(Duration hostCertTtl) {
		this.hostCertTtl = hostCertTtl;
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

		// --- DoS bounds (M2) — the plane carries only tiny control messages (CSR,
		// pubkey), so these are deliberately small. ---

		/**
		 * Max inbound message size (bytes). A CSR/pubkey is ~1 KiB; 64 KiB is generous.
		 */
		private int maxInboundMessageSize = 64 * 1024;

		/** Max inbound header/metadata size (bytes). */
		private int maxInboundMetadataSize = 16 * 1024;

		/** Max concurrent in-flight calls per connection. */
		private int maxConcurrentCallsPerConnection = 128;

		/**
		 * Bounded handler-executor thread count (crypto/DB offload runs on Reactor
		 * schedulers).
		 */
		private int handlerThreads = Math.max(4, Runtime.getRuntime().availableProcessors() * 2);

		/** Reject client keepalive pings faster than this (ping-flood guard). */
		private Duration permitKeepAliveTime = Duration.ofSeconds(30);

		/** Recycle a connection after this age (bounds long-lived connection abuse). */
		private Duration maxConnectionAge = Duration.ofMinutes(30);

		/** Grace period for in-flight RPCs when a connection is aged out. */
		private Duration maxConnectionAgeGrace = Duration.ofSeconds(30);

		/** Close a connection idle for this long. */
		private Duration maxConnectionIdle = Duration.ofMinutes(5);

		/** Drain deadline on shutdown before a forced close (M5). */
		private Duration drainTimeout = Duration.ofSeconds(10);

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

		public int getMaxInboundMessageSize() {
			return maxInboundMessageSize;
		}

		public void setMaxInboundMessageSize(int maxInboundMessageSize) {
			this.maxInboundMessageSize = maxInboundMessageSize;
		}

		public int getMaxInboundMetadataSize() {
			return maxInboundMetadataSize;
		}

		public void setMaxInboundMetadataSize(int maxInboundMetadataSize) {
			this.maxInboundMetadataSize = maxInboundMetadataSize;
		}

		public int getMaxConcurrentCallsPerConnection() {
			return maxConcurrentCallsPerConnection;
		}

		public void setMaxConcurrentCallsPerConnection(int maxConcurrentCallsPerConnection) {
			this.maxConcurrentCallsPerConnection = maxConcurrentCallsPerConnection;
		}

		public int getHandlerThreads() {
			return handlerThreads;
		}

		public void setHandlerThreads(int handlerThreads) {
			this.handlerThreads = handlerThreads;
		}

		public Duration getPermitKeepAliveTime() {
			return permitKeepAliveTime;
		}

		public void setPermitKeepAliveTime(Duration permitKeepAliveTime) {
			this.permitKeepAliveTime = permitKeepAliveTime;
		}

		public Duration getMaxConnectionAge() {
			return maxConnectionAge;
		}

		public void setMaxConnectionAge(Duration maxConnectionAge) {
			this.maxConnectionAge = maxConnectionAge;
		}

		public Duration getMaxConnectionAgeGrace() {
			return maxConnectionAgeGrace;
		}

		public void setMaxConnectionAgeGrace(Duration maxConnectionAgeGrace) {
			this.maxConnectionAgeGrace = maxConnectionAgeGrace;
		}

		public Duration getMaxConnectionIdle() {
			return maxConnectionIdle;
		}

		public void setMaxConnectionIdle(Duration maxConnectionIdle) {
			this.maxConnectionIdle = maxConnectionIdle;
		}

		public Duration getDrainTimeout() {
			return drainTimeout;
		}

		public void setDrainTimeout(Duration drainTimeout) {
			this.drainTimeout = drainTimeout;
		}
	}
}
