package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.time.Instant;
import java.util.Collection;

/**
 * The data-plane RBAC decision engine (FR-AUTHZ-3/4/7, Design §6.1). The
 * decision MUST be a <b>pure function of the grant set</b>: default-deny +
 * deny-overrides + order-independent, with a matching {@code access_lock} as a
 * top-tier un-overridable deny. Kept behind this interface so the hand-written
 * evaluator could be swapped for embedded Cedar later without touching callers
 * (FR-AUTHZ-7 permits either).
 */
public interface PolicyEngine {

	/**
	 * Evaluate {@code request} against the full {@code grants} and {@code locks}
	 * sets. Order-independent; any evaluation error fails closed to a generic deny.
	 *
	 * @param now
	 *            the reference instant (lock expiry) — passed in so the function
	 *            stays pure and deterministic
	 */
	DataPlaneDecision evaluate(AuthorizationRequest request, Collection<DpRule> grants, Collection<AccessLock> locks,
			Instant now);
}
