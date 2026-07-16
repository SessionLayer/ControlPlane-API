package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import reactor.core.publisher.Mono;

/**
 * A second {@link AuditForwarder} implementation used only in tests to prove the
 * off-box exporter seam is real (owner requirement): swapping this in (it
 * suppresses the default {@code @ConditionalOnMissingBean} log forwarder) shows
 * the store ships every committed event through the interface, not a hardcoded
 * backend. Captures forwarded events for assertions.
 */
public final class CapturingAuditForwarder implements AuditForwarder {

	private final List<AuditEvent> captured = new CopyOnWriteArrayList<>();

	@Override
	public Mono<Void> forward(AuditEvent event) {
		return Mono.fromRunnable(() -> captured.add(event));
	}

	public List<AuditEvent> captured() {
		return List.copyOf(captured);
	}
}
