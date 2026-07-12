package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import java.util.UUID;
import reactor.core.publisher.Mono;

/**
 * The pluggable break-glass alert seam (§7 / FR-ACC-6). A break-glass
 * credential use is a high-priority security event that MUST raise an alert.
 * SessionLayer has no built-in notification transport yet, so the alert is
 * modelled as a sink interface — the
 * {@link AuditLogBreakglassSecurityAlertSink} default writes a distinct
 * high-priority audit event + a loud log line, and a future transport
 * (webhook/SMTP/pager, keyed off {@code breakglass_policy.alert_target}) plugs
 * in as an additional sink. Sinks receive only public ids — never key material
 * or the resolving secret.
 *
 * <p>
 * The alert fires at <b>authentication</b> ({@link #authenticated}) — the
 * moment a credential resolves at {@code ResolveBreakglass*} — so a break-glass
 * credential use ALWAYS alerts even if no session follows (a
 * resolve-without-Authorize, or a downstream deny). The activation record is
 * created later at Authorize as the durable, reviewable compensating control.
 */
public interface BreakglassSecurityAlertSink {

	/**
	 * A break-glass credential authenticated (resolved to an identity + a minted
	 * single-use token) via {@code method} ({@code fido2}/{@code offline_code}).
	 * {@code nodeId} may be null for a fleet-scoped resolution.
	 */
	Mono<Void> authenticated(String identity, UUID nodeId, String sourceIp, String method);

	/**
	 * A break-glass session was opened (activation persisted at Authorize). Default
	 * is a no-op — the alert already fired at {@link #authenticated}, and the
	 * activation carries its own audit; a transport may override to correlate the
	 * session.
	 */
	default Mono<Void> activated(BreakglassActivation activation) {
		return Mono.empty();
	}
}
