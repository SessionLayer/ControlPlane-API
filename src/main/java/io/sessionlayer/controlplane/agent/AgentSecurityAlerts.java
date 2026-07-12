package io.sessionlayer.controlplane.agent;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Fans a security alert out to every registered {@link AgentSecurityAlertSink}
 * (§8.2 / FR-JOIN-5). The {@link AuditLogAgentSecurityAlertSink} is always
 * present (audit + loud log); additional transports register as sinks and are
 * picked up here. Fan-out is best-effort — a failing sink must not suppress the
 * others or the refusal that raised the alert — so a sink error is swallowed
 * (the always-on audit sink is the durable record of record).
 */
@Component
public class AgentSecurityAlerts {

	private final List<AgentSecurityAlertSink> sinks;

	public AgentSecurityAlerts(List<AgentSecurityAlertSink> sinks) {
		this.sinks = sinks;
	}

	public Mono<Void> cloneDetected(UUID agentId, UUID nodeId, long expectedGeneration, long presentedGeneration) {
		return Flux.fromIterable(sinks)
				.flatMap(sink -> sink.cloneDetected(agentId, nodeId, expectedGeneration, presentedGeneration)
						.onErrorResume(failed -> Mono.empty()))
				.then();
	}
}
