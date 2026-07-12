package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.audit.AuditWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The default {@link BreakglassSecurityAlertSink} (§7 / FR-ACC-6): a
 * break-glass authentication is recorded as a distinct high-priority audit
 * event on the one correlated audit stream, and logged loudly (ERROR) for
 * immediate operator attention. This is the always-on baseline that makes "no
 * break-glass without an alert" true; a future notification transport plugs in
 * as an additional sink. Carries public ids only — no key material, no
 * resolving secret.
 *
 * <p>
 * The <b>action</b> ({@code breakglass.authenticated}) is what an auditor
 * queries — not the outcome, which the {@code audit_event} CHECK constrains to
 * {@code success|failure|denied|error}. A credential that authenticated is a
 * {@code success}; its severity is carried by the distinct action, the loud
 * log, and this alert seam.
 */
@Component
public class AuditLogBreakglassSecurityAlertSink implements BreakglassSecurityAlertSink {

	private static final Logger LOG = LoggerFactory.getLogger(AuditLogBreakglassSecurityAlertSink.class);

	private final AuditWriter audit;

	public AuditLogBreakglassSecurityAlertSink(AuditWriter audit) {
		this.audit = audit;
	}

	@Override
	public Mono<Void> authenticated(String identity, UUID nodeId, String sourceIp, String method) {
		LOG.error(
				"SECURITY: break-glass credential authenticated — identity={} node={} source_ip={} method={}; a "
						+ "mandatory-review activation follows if a session is opened",
				identity, nodeId, sourceIp, method);
		Map<String, String> detail = new HashMap<>();
		detail.put("method", method);
		if (sourceIp != null) {
			detail.put("source_ip", sourceIp);
		}
		return audit.record("system:break-glass", identity, "breakglass.authenticated", "success", null, nodeId,
				detail);
	}
}
