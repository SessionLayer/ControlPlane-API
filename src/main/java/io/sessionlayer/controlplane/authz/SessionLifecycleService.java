package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.GatewayRequestException.Reason;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import tools.jackson.databind.JsonNode;

/**
 * The S25 exact-lease session-lifecycle signals (FR-SESS-3). Both are bound to
 * the AUTHENTICATED mTLS caller owning the session (the same ownership gate as
 * the recording RPCs — one Gateway can never free or extend another's slot);
 * every mismatch fails closed generically (§7.1).
 *
 * <ul>
 * <li><b>endSession</b> ({@code NotifySessionEnd}) — the Gateway's reliable
 * session-end signal on EVERY teardown path (including the degraded ones where
 * no recording exists and FinalizeRecording never fires): stamps
 * {@code ended_at}/{@code end_reason} if nothing else has and releases the
 * concurrency lease promptly. Idempotent; race-safe with FinalizeRecording's
 * own end-stamp (an optimistic-lock loss re-reads and no-ops the stamp).</li>
 * <li><b>extendLease</b> ({@code ExtendSessionLease}) — re-stamps a live
 * session's lease expiry to now + the SERVER-authoritative extension window, so
 * a RunToTtl session outliving {@code grant_expiry} still occupies its slot.
 * Refused for an ended session or a released/absent lease.</li>
 * </ul>
 */
@Service
public class SessionLifecycleService {

	private final SshSessionRepository sshSessions;
	private final SessionLeaseRepository sessionLeases;
	private final NodeRepository nodes;
	private final SessionLimitProperties properties;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public SessionLifecycleService(SshSessionRepository sshSessions, SessionLeaseRepository sessionLeases,
			NodeRepository nodes, SessionLimitProperties properties, AuditEventStore audit, TransactionalOperator tx) {
		this.sshSessions = sshSessions;
		this.sessionLeases = sessionLeases;
		this.nodes = nodes;
		this.properties = properties;
		this.audit = audit;
		this.tx = tx;
	}

	/** Returns whether THIS call released a still-live lease (diagnostics). */
	public Mono<Boolean> endSession(UUID callerGatewayId, UUID sessionId, String reason) {
		if (callerGatewayId == null || sessionId == null) {
			return Mono.error(refused());
		}
		Mono<Boolean> body = sshSessions.findById(sessionId).switchIfEmpty(Mono.error(refused())).flatMap(session -> {
			if (!callerGatewayId.equals(session.gatewayId())) {
				return Mono.error(refused());
			}
			Instant now = Instant.now();
			Mono<Void> stampEnd = session.endedAt() == null
					? sshSessions.save(session.ended(now, reason)).then()
					: Mono.empty();
			boolean stamped = session.endedAt() == null;
			return stampEnd.then(sessionLeases.releaseBySessionId(sessionId, now))
					.flatMap(released -> auditEnd(callerGatewayId, session, reason, stamped, released > 0)
							.thenReturn(released > 0));
		});
		// A lost @Version race with FinalizeRecording's end-stamp retries once: the
		// re-read sees the session already ended, skips the stamp, and releases the
		// lease idempotently.
		return tx.transactional(body)
				.retryWhen(Retry.max(1).filter(OptimisticLockingFailureException.class::isInstance));
	}

	/** Returns the lease's new expiry (now + the server-authoritative window). */
	public Mono<Instant> extendLease(UUID callerGatewayId, UUID sessionId) {
		if (callerGatewayId == null || sessionId == null) {
			return Mono.error(refused());
		}
		return sshSessions.findById(sessionId).switchIfEmpty(Mono.error(refused())).flatMap(session -> {
			if (!callerGatewayId.equals(session.gatewayId())) {
				return Mono.error(refused());
			}
			if (session.endedAt() != null) {
				return Mono.error(new GatewayRequestException(Reason.FAILED_PRECONDITION, "session already ended"));
			}
			Instant expiry = Instant.now().plus(properties.getLeaseExtension());
			return sessionLeases.extendBySessionId(sessionId, expiry).flatMap(rows -> rows > 0
					? Mono.just(expiry)
					: Mono.error(new GatewayRequestException(Reason.FAILED_PRECONDITION, "lease not extendable")));
		});
	}

	// The lifecycle end joins the session's FR-AUD-9 correlation chain (alongside
	// the connect decision + recording events). Written only when this call
	// changed state — an idempotent repeat writes no duplicate rows.
	private Mono<Void> auditEnd(UUID callerGatewayId, SshSession session, String reason, boolean stamped,
			boolean released) {
		if (!stamped && !released) {
			return Mono.empty();
		}
		Map<String, String> detail = new HashMap<>();
		detail.put("gateway_id", callerGatewayId.toString());
		detail.put("reason", reason);
		detail.put("lease_released", Boolean.toString(released));
		return nodeLabels(session.nodeId()).flatMap(labels -> audit
				.record(AuditRecord.builder(callerGatewayId.toString(), session.identity(), "session.end", "success")
						.session(session.id()).node(session.nodeId()).accessModel(session.accessModel())
						.nodeLabels(labels).correlationId(session.correlationId()).detail(detail).build()));
	}

	private Mono<Map<String, String>> nodeLabels(UUID nodeId) {
		if (nodeId == null) {
			return Mono.just(Map.of());
		}
		return nodes.findById(nodeId).map(node -> labelsOf(node.resolvedLabels())).defaultIfEmpty(Map.of());
	}

	private static Map<String, String> labelsOf(JsonNode resolvedLabels) {
		Map<String, String> labels = new HashMap<>();
		if (resolvedLabels != null && resolvedLabels.isObject()) {
			for (var entry : resolvedLabels.properties()) {
				labels.put(entry.getKey(), entry.getValue().asString());
			}
		}
		return labels;
	}

	private static GatewayRequestException refused() {
		return new GatewayRequestException(Reason.PERMISSION_DENIED, "session lifecycle request refused");
	}
}
