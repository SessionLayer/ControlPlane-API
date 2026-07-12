package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Fans a break-glass alert out to every registered
 * {@link BreakglassSecurityAlertSink} (§7 / FR-ACC-6). The
 * {@link AuditLogBreakglassSecurityAlertSink} is always present (audit + loud
 * log); additional transports register as sinks and are picked up here.
 *
 * <p>
 * Fan-out is best-effort — a failing sink must not suppress the others or the
 * Authorize decision that raised it — but a break-glass activation without an
 * alert IS a defect, so a failing sink is logged loudly rather than silently
 * swallowed. (A silent swallow here previously hid an alert whose audit INSERT
 * was rejected by the {@code outcome} CHECK: the session ran with no alert of
 * record. Never make a dropped security alert quiet.)
 */
@Component
public class BreakglassSecurityAlerts {

	private static final Logger LOG = LoggerFactory.getLogger(BreakglassSecurityAlerts.class);

	private final List<BreakglassSecurityAlertSink> sinks;

	public BreakglassSecurityAlerts(List<BreakglassSecurityAlertSink> sinks) {
		this.sinks = sinks;
	}

	public Mono<Void> activated(BreakglassActivation activation) {
		return Flux.fromIterable(sinks).flatMap(sink -> sink.activated(activation).onErrorResume(failed -> {
			LOG.error(
					"SECURITY: break-glass alert sink {} FAILED for activation {} — the activation stands but this "
							+ "alert was not delivered; investigate immediately",
					sink.getClass().getSimpleName(), activation.id(), failed);
			return Mono.empty();
		})).then();
	}
}
