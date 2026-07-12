package io.sessionlayer.controlplane.breakglass;

import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Fans a break-glass alert out to every registered
 * {@link BreakglassSecurityAlertSink} (§7 / FR-ACC-6). The
 * {@link AuditLogBreakglassSecurityAlertSink} is always present (audit + loud
 * log); additional transports register as sinks and are picked up here. The
 * alert fires at AUTHENTICATION ({@link #authenticated}), so a break-glass
 * credential use always alerts even when no session follows.
 *
 * <p>
 * Fan-out is best-effort — a failing sink must not suppress the others or the
 * resolve/decision that raised it — but a break-glass use without an alert IS a
 * defect, so a failing sink is logged loudly rather than silently swallowed. (A
 * silent swallow here previously hid an alert whose audit INSERT was rejected
 * by the {@code outcome} CHECK. Never make a dropped security alert quiet.)
 */
@Component
public class BreakglassSecurityAlerts {

	private static final Logger LOG = LoggerFactory.getLogger(BreakglassSecurityAlerts.class);

	private final List<BreakglassSecurityAlertSink> sinks;

	public BreakglassSecurityAlerts(List<BreakglassSecurityAlertSink> sinks) {
		this.sinks = sinks;
	}

	public Mono<Void> authenticated(String identity, UUID nodeId, String sourceIp, String method) {
		return Flux.fromIterable(sinks)
				.flatMap(sink -> sink.authenticated(identity, nodeId, sourceIp, method).onErrorResume(failed -> {
					LOG.error(
							"SECURITY: break-glass alert sink {} FAILED for identity {} ({}) — authentication stands "
									+ "but this alert was not delivered; investigate immediately",
							sink.getClass().getSimpleName(), identity, method, failed);
					return Mono.empty();
				})).then();
	}
}
