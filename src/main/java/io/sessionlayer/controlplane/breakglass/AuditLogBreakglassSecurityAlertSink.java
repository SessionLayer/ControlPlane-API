package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The default {@link BreakglassSecurityAlertSink} (§7 / FR-ACC-6): a
 * break-glass activation is recorded as a distinct high-priority audit event on
 * the one correlated audit stream, and logged loudly (ERROR) for immediate
 * operator attention. This is the always-on baseline that makes "no break-glass
 * without an alert" true; a future notification transport plugs in as an
 * additional sink. Carries public ids only — no key material, no resolving
 * secret.
 *
 * <p>
 * The <b>action</b> ({@code breakglass.activated}) is what an auditor queries —
 * not the outcome, which the {@code audit_event} CHECK constrains to
 * {@code success|failure|denied|error}. An activation that happened is a
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
	public Mono<Void> activated(BreakglassActivation activation) {
		LOG.error(
				"SECURITY: break-glass access activated — activation={} identity={} principal={} node={} source_ip={} "
						+ "credential={}; mandatory post-hoc review required",
				activation.id(), activation.identity(), activation.principal(), activation.targetNodeId(),
				activation.sourceIp(), activation.credentialRef());
		Map<String, String> detail = new HashMap<>();
		detail.put("activation_id", activation.id().toString());
		detail.put("principal", activation.principal());
		if (activation.credentialRef() != null) {
			detail.put("credential_ref", activation.credentialRef());
		}
		if (activation.breakglassPolicyName() != null) {
			detail.put("policy", activation.breakglassPolicyName());
		}
		if (activation.sourceIp() != null) {
			detail.put("source_ip", activation.sourceIp());
		}
		return audit.record("system:break-glass", activation.identity(), "breakglass.activated", "success", null,
				activation.targetNodeId(), detail);
	}
}
