package io.sessionlayer.controlplane.platform;

import reactor.core.publisher.Mono;

/**
 * The platform-RBAC enforcement seam (FR-PADM-1/2/3, Design §6.2) the later
 * admin endpoints (S6/S15/S16) call before performing a control-plane action.
 * Default-deny; every decision is audited. This is a <b>separate</b> system
 * from the data-plane RBAC ({@code authz} package) — different
 * subjects/verbs/blast radius — and shares no rules or code with it.
 */
public interface PlatformAuthorization {

	/**
	 * Decide whether {@code subject} may exercise {@code permission} for the
	 * requested {@code scope}, and audit the decision. Fail-closed: an unknown
	 * permission, no granting binding, an out-of-scope binding, or any error
	 * denies.
	 *
	 * @param scope
	 *            the scopable-action target (node-label/user/time), or {@code null}
	 *            for an unscoped/global permission — which only an unscoped binding
	 *            can authorize
	 */
	Mono<PlatformDecision> authorize(PlatformSubject subject, String permission, PlatformScope scope);
}
