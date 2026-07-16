package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The default {@link AgentSecurityAlertSink} (§8.2 / FR-JOIN-5): a
 * generation-mismatch clone detection is recorded as a distinct high-severity
 * audit event ({@code agent.identity.clone_detected}, outcome {@code error}) on
 * the one correlated audit stream, and logged loudly (ERROR) for operator
 * attention. This is the always-on baseline; a future notification transport
 * plugs in as an additional sink. Carries public ids only — no key material.
 */
@Component
public class AuditLogAgentSecurityAlertSink implements AgentSecurityAlertSink {

	private static final Logger LOG = LoggerFactory.getLogger(AuditLogAgentSecurityAlertSink.class);

	private final AuditEventStore audit;

	public AuditLogAgentSecurityAlertSink(AuditEventStore audit) {
		this.audit = audit;
	}

	@Override
	public Mono<Void> cloneDetected(UUID agentId, UUID nodeId, long expectedGeneration, long presentedGeneration) {
		LOG.error(
				"SECURITY: agent credential clone detected — agent_identity={} node={} expected_generation={} "
						+ "presented_generation={}; identity LOCKED (no auto-clear), operator re-provision required",
				agentId, nodeId, expectedGeneration, presentedGeneration);
		return audit.record("system:clone-detection", agentId.toString(), "agent.identity.clone_detected", "error",
				null, nodeId, Map.of("expected_generation", Long.toString(expectedGeneration), "presented_generation",
						Long.toString(presentedGeneration)));
	}
}
