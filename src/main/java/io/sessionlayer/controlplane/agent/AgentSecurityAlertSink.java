package io.sessionlayer.controlplane.agent;

import java.util.UUID;
import reactor.core.publisher.Mono;

/**
 * The pluggable security-alert seam (§8.2 / FR-JOIN-5). A generation-mismatch
 * (clone detection) is a genuine security event that must raise an alert;
 * SessionLayer has no built-in notification transport yet, so the alert is
 * modelled as a sink interface. The {@link AuditLogAgentSecurityAlertSink}
 * default writes a distinct high-severity audit event + a loud log line; a
 * future transport (email/webhook/pager) implements this interface and is
 * picked up automatically by {@link AgentSecurityAlerts}. Sinks receive only
 * public ids — never key material.
 */
public interface AgentSecurityAlertSink {

	/**
	 * A cloned Agent credential was detected: a renewal declared a generation that
	 * does not match the stored one, so the identity was locked (no auto-clear).
	 */
	Mono<Void> cloneDetected(UUID agentId, UUID nodeId, long expectedGeneration, long presentedGeneration);
}
