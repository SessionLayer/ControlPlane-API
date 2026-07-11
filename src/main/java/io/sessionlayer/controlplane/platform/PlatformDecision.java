package io.sessionlayer.controlplane.platform;

import java.util.UUID;

/**
 * A platform-RBAC decision. {@link #allowed} is the outcome; {@link #reason}
 * and the matched role are decision-log detail (every decision is audited,
 * FR-PADM-3/FR-AUD-7).
 */
public record PlatformDecision(boolean allowed, Reason reason, UUID matchedRoleId, String matchedRoleName) {

	public enum Reason {
		ALLOWED,
		/** No binding grants the permission (default-deny). */
		NO_GRANTING_BINDING,
		/** A binding grants the permission but its scope does not cover the request. */
		OUT_OF_SCOPE,
		/** A malformed binding/scope or datastore problem — fail closed. */
		EVALUATION_ERROR
	}

	static PlatformDecision allow(UUID roleId, String roleName) {
		return new PlatformDecision(true, Reason.ALLOWED, roleId, roleName);
	}

	static PlatformDecision deny(Reason reason) {
		return new PlatformDecision(false, reason, null, null);
	}
}
