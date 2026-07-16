package io.sessionlayer.controlplane.platform;

import java.util.List;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

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

	/**
	 * Resolve a caller's grant for a permission whose scope <b>filters results</b>
	 * rather than gating one target (audit search, FR-AUD-8): an out-of-scope query
	 * returns fewer rows, not a {@code 403}. Fail-closed on error. Unlike
	 * {@link #authorize}, this does not itself audit — the calling read path audits
	 * the access.
	 */
	Mono<ScopeGrant> resolveScopeGrant(PlatformSubject subject, String permission);

	/**
	 * The caller's effective grant for a filtered permission: {@code granted} false
	 * denies outright; {@code unrestricted} means an unscoped binding grants it (no
	 * filter); otherwise {@code scopes} are the scoped bindings'
	 * {@code role_binding} scopes, which the caller applies OR-ed together as a
	 * result filter.
	 */
	record ScopeGrant(boolean granted, boolean unrestricted, List<JsonNode> scopes) {

		public ScopeGrant {
			scopes = (scopes == null) ? List.of() : List.copyOf(scopes);
		}

		public static ScopeGrant deny() {
			return new ScopeGrant(false, false, List.of());
		}

		public static ScopeGrant all() {
			return new ScopeGrant(true, true, List.of());
		}

		public static ScopeGrant scoped(List<JsonNode> scopes) {
			return new ScopeGrant(true, false, scopes);
		}
	}
}
