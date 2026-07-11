package io.sessionlayer.controlplane.authz;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * The result of a data-plane RBAC evaluation. The {@link Effect} is the generic
 * outcome shown to the caller (§7.1); {@link #reason} and
 * {@link #matchedRuleId} / {@link #matchedRuleName} are the <b>decision-log</b>
 * detail (FR-AUTHZ-5) — which rule/lock decided it, for the Admin/Auditor,
 * never disclosed to the user. On {@link Effect#ALLOW}, {@link #allowedLogins}
 * / {@link #capabilities} / {@link #grantTtlSeconds} are populated; on a deny
 * they are empty/zero.
 */
public record DataPlaneDecision(Effect effect, Reason reason, Set<String> allowedLogins, Set<String> capabilities,
		int grantTtlSeconds, UUID matchedRuleId, String matchedRuleName) {

	public enum Effect {
		ALLOW, DENY
	}

	/** The decision-log reason (server-side only). */
	public enum Reason {
		ALLOWED,
		/** A matching {@code access_lock} — top-tier un-overridable deny. */
		LOCKED,
		/** An applicable {@code deny} rule won (deny-overrides). */
		EXPLICIT_DENY,
		/** No applicable allow (default-deny). */
		NO_MATCHING_ALLOW,
		/** The requested login is not within the resolved allowed set. */
		PRINCIPAL_NOT_ALLOWED,
		/** A malformed rule/lock/selector or datastore problem — fail closed. */
		EVALUATION_ERROR
	}

	public boolean allowed() {
		return effect == Effect.ALLOW;
	}

	static DataPlaneDecision allow(Set<String> logins, Set<String> capabilities, int grantTtlSeconds, UUID ruleId,
			String ruleName) {
		return new DataPlaneDecision(Effect.ALLOW, Reason.ALLOWED, Set.copyOf(logins), Set.copyOf(capabilities),
				grantTtlSeconds, ruleId, ruleName);
	}

	static DataPlaneDecision deny(Reason reason, UUID ruleId, String ruleName) {
		return new DataPlaneDecision(Effect.DENY, reason, Set.of(), Set.of(), 0, ruleId, ruleName);
	}

	/** Deterministic sorted view of the allowed logins (for the signed context). */
	public List<String> sortedLogins() {
		return allowedLogins.stream().sorted().toList();
	}

	public List<String> sortedCapabilities() {
		return capabilities.stream().sorted().toList();
	}
}
