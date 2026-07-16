package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import reactor.core.publisher.Mono;

/**
 * The pluggable audit <b>exporter</b> seam (§15 "audit shipped off-box", NFR-5,
 * owner requirement). After an event is durably appended, the store ships it
 * off-box through this interface so the correlated stream can be mirrored to an
 * external system (Splunk / SIEM / S3 / syslog / webhook). This is deliberately
 * separate from {@link AuditEventStore} (the primary of record): forwarding is
 * best-effort and MUST NOT roll back or fail the audited action — a forward
 * failure is logged loudly, never propagated.
 *
 * <p>
 * The reference implementation ({@link LoggingAuditForwarder}) emits a
 * structured line to a dedicated logger; a real deployment swaps in a
 * connector. A no-op is a valid implementation (off-box shipping disabled).
 */
public interface AuditForwarder {

	/** Ship one already-committed event off-box. Best-effort; never throws. */
	Mono<Void> forward(AuditEvent event);
}
