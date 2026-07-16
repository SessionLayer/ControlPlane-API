package io.sessionlayer.controlplane.device;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.auth.AuthProperties;
import io.sessionlayer.controlplane.auth.RateLimiter;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.authz.Cidrs;
import io.sessionlayer.controlplane.data.runtime.DeviceFlow;
import io.sessionlayer.controlplane.data.runtime.DeviceFlowRepository;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * OIDC device flow (Design §5.2, FR-AUTH-3/5). The CP generates the device/user
 * codes and hosts the verification page as an auth-code + PKCE relying party
 * (the anti-phishing design — the CP page restores state/nonce/PKCE a raw
 * device grant lacks). Approval happens when the user completes the CP
 * verification page; the approving browser's source context is correlated with
 * the SSH source IP as a deny-only reducer (FR-AUTH-15) and recorded.
 * Fallback-only; the Gateway (S7) polls {@link #poll} and moves this onto the
 * auth gRPC plane.
 */
@Service
public class DeviceFlowService {

	private final DeviceFlowRepository deviceFlows;
	private final OidcProperties oidcProperties;
	private final AuthProperties authProperties;
	private final RateLimiter rateLimiter;
	private final AuditEventStore audit;
	private final ObjectMapper objectMapper;

	public DeviceFlowService(DeviceFlowRepository deviceFlows, OidcProperties oidcProperties,
			AuthProperties authProperties, RateLimiter rateLimiter, AuditEventStore audit, ObjectMapper objectMapper) {
		this.deviceFlows = deviceFlows;
		this.oidcProperties = oidcProperties;
		this.authProperties = authProperties;
		this.rateLimiter = rateLimiter;
		this.audit = audit;
		this.objectMapper = objectMapper;
	}

	public record Begun(UUID deviceFlowId, String userCode, String deviceCode, int intervalSeconds,
			long expiresInSeconds) {
	}

	public record Status(String status, String identity, Boolean sourceContextMatch) {
	}

	/** Begin a device flow bound to the SSH source (fallback-only, §5.2). */
	public Mono<Begun> begin(String sshSourceIp, String connectionBinding) {
		String deviceCode = Secrets.randomToken(32);
		String userCode = Secrets.randomUserCode();
		int interval = (int) oidcProperties.getDevice().getPollInterval().toSeconds();
		Instant expiresAt = Instant.now().plus(oidcProperties.getDevice().getExpiry());
		DeviceFlow flow = DeviceFlow.create(Secrets.sha256Hex(deviceCode), Secrets.sha256Hex(userCode),
				connectionBinding, sshSourceIp, interval, expiresAt);
		return deviceFlows.save(flow)
				.flatMap(saved -> audit
						.record("gateway", null, "device.begin", "success", null, null,
								Map.of("device_flow_id", saved.id().toString()))
						.thenReturn(new Begun(saved.id(), userCode, deviceCode, interval,
								oidcProperties.getDevice().getExpiry().toSeconds())));
	}

	/** Look up a pending flow by its user code (for the verification page). */
	public Mono<DeviceFlow> pendingByUserCode(String userCode) {
		return deviceFlows.findByUserCodeHash(Secrets.sha256Hex(userCode))
				.filter(f -> "pending".equals(f.status()) && f.expiresAt().isAfter(Instant.now()));
	}

	/**
	 * Approve a device flow from a completed verification-page login: resolve the
	 * identity and record the source-context correlation (§5.2). A mismatch is
	 * flagged (+ audited); it denies only when source-match enforcement is on.
	 */
	public Mono<DeviceFlow> approve(UUID deviceFlowId, String identity, String approverSourceIp) {
		return deviceFlows.findById(deviceFlowId).filter(f -> "pending".equals(f.status())).flatMap(flow -> {
			Boolean match = correlate(approverSourceIp, flow.sourceIp());
			// Fail closed under enforcement: an indeterminate (null) correlation denies
			// too,
			// so an attacker cannot bypass the binding by blanking a source (NFR-2).
			boolean deny = oidcProperties.getDevice().isEnforceSourceMatch() && !Boolean.TRUE.equals(match);
			ObjectNode context = objectMapper.createObjectNode();
			context.put("approver_source_ip", approverSourceIp == null ? "" : approverSourceIp);
			context.put("ssh_source_ip", flow.sourceIp() == null ? "" : flow.sourceIp());
			DeviceFlow updated = deny
					? flow.authorized(identity, Instant.now(), approverSourceIp, context, match).withStatus("denied")
					: flow.authorized(identity, Instant.now(), approverSourceIp, context, match);
			return deviceFlows.save(updated)
					.flatMap(saved -> audit
							.record(identity, identity, "device.approve", deny ? "denied" : "success", null, null,
									Map.of("device_flow_id", deviceFlowId.toString(), "source_context_match",
											String.valueOf(match), "enforced", String.valueOf(deny)))
							.thenReturn(saved));
		});
	}

	/**
	 * Poll a device flow by its device code (rate-limited). Empty = unknown code.
	 */
	public Mono<Status> poll(String deviceCode) {
		String hash = Secrets.sha256Hex(deviceCode == null ? "" : deviceCode);
		return rateLimiter.tryAcquire("device:poll:" + hash, authProperties.getDevicePoll()).flatMap(allowed -> {
			if (!allowed) {
				return Mono.error(new RateLimited());
			}
			return deviceFlows.findByDeviceCodeHash(hash).flatMap(flow -> {
				if ("pending".equals(flow.status()) && !flow.expiresAt().isAfter(Instant.now())) {
					return deviceFlows.save(flow.withStatus("expired")).thenReturn(new Status("expired", null, null));
				}
				return Mono.just(new Status(flow.status(), flow.identity(), flow.sourceContextMatch()));
			});
		});
	}

	/** Signals a throttled poll (→ HTTP 429). */
	public static final class RateLimited extends RuntimeException {
	}

	private static Boolean correlate(String approverIp, String sshIp) {
		if (approverIp == null || approverIp.isBlank() || sshIp == null || sshIp.isBlank()) {
			return null;
		}
		if (approverIp.equals(sshIp)) {
			return true;
		}
		// A soft correlation when the exact IPv4 differs (e.g. NAT within one /24).
		// Only
		// for IPv4 (a /24 is meaningless for IPv6); a malformed literal →
		// indeterminate.
		if (approverIp.indexOf(':') >= 0 || sshIp.indexOf(':') >= 0) {
			return false;
		}
		try {
			return Cidrs.contains(sshIp + "/24", approverIp);
		} catch (RuntimeException malformed) {
			return null;
		}
	}
}
