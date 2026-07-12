package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import reactor.core.publisher.Mono;

/**
 * The pluggable break-glass alert seam (§7 / FR-ACC-6). A break-glass
 * activation is a high-priority security event that MUST raise an alert on use.
 * SessionLayer has no built-in notification transport yet, so the alert is
 * modelled as a sink interface — the
 * {@link AuditLogBreakglassSecurityAlertSink} default writes a distinct
 * high-priority audit event + a loud log line, and a future transport
 * (webhook/SMTP/pager, keyed off {@code breakglass_policy.alert_target}) plugs
 * in as an additional sink. Sinks receive only public ids — never key material
 * or the resolving secret.
 */
public interface BreakglassSecurityAlertSink {

	/** A break-glass credential was used to open a session (activation created). */
	Mono<Void> activated(BreakglassActivation activation);
}
