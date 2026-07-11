package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * The hand-written, typed <b>deny-overrides</b> evaluator over the
 * policy-as-data {@code dp_rule} rows (FR-AUTHZ-3/4/7). Chosen over the Cedar
 * JNI binding because our policy is already typed data (not Cedar text), it
 * avoids a native dependency in a reactive service, and FR-AUTHZ-7 explicitly
 * permits a hand-written evaluator; the {@link PolicyEngine} seam keeps Cedar
 * swappable.
 *
 * <p>
 * The algebra (a pure function of the grant <i>set</i>):
 * <ol>
 * <li>compute the <b>applicable</b> rules — {@code identity ∧ node-label}
 * match; an ALLOW additionally passes the source-IP reducer, a DENY does not
 * (source IP may suppress an allow but never removes a deny — FR-AUTH-15,
 * §8.4);</li>
 * <li><b>Lock wins</b>: any unexpired {@code access_lock} matching the connect
 * → {@code LOCKED} (top-tier, beatable by no allow) — checked before any
 * allow/deny outcome is returned;</li>
 * <li><b>deny-overrides</b>: any applicable non-allow rule → {@code DENY} (a
 * mislabeled effect is treated as a deny — fail closed);</li>
 * <li><b>default-deny</b>: no applicable {@code allow} → {@code DENY};</li>
 * <li>otherwise <b>ALLOW</b> with logins = union of the allows' principals, and
 * capabilities = union of the capability sets of the allows that grant the
 * <b>chosen</b> login (gated per grant — no cross-login bleed; a grant that
 * names none contributes {@code shell}+{@code exec}; {@code agent_forward} only
 * if explicitly granted).</li>
 * </ol>
 * Every step is commutative/idempotent over the input, so shuffling the set
 * yields an identical decision. Any thrown error (malformed selector, bad CIDR/
 * regex) collapses to a generic fail-closed {@code DENY}.
 */
@Component
public class DenyOverridesPolicyEngine implements PolicyEngine {

	private static final Logger LOG = LoggerFactory.getLogger(DenyOverridesPolicyEngine.class);

	@Override
	public DataPlaneDecision evaluate(AuthorizationRequest request, Collection<DpRule> grants,
			Collection<AccessLock> locks, Instant now) {
		try {
			return decide(request, grants, locks, now);
		} catch (RuntimeException failClosed) {
			// Determinism is a security property: an error is deterministic for the set,
			// and it always denies (§8.4). The specific cause stays server-side.
			LOG.warn("data-plane evaluation failed closed: {}", failClosed.toString());
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.EVALUATION_ERROR, null, null);
		}
	}

	private DataPlaneDecision decide(AuthorizationRequest request, Collection<DpRule> grants,
			Collection<AccessLock> locks, Instant now) {
		List<DpRule> applicable = grants.stream().filter(rule -> applies(rule, request))
				.sorted(Comparator.comparing(DpRule::id)).toList();
		List<DpRule> allows = applicable.stream().filter(DenyOverridesPolicyEngine::isAllow).toList();
		// Fail closed: anything that is not exactly an allow (a deny, or a mislabeled
		// effect the DB CHECK somehow let through) is treated as a deny.
		List<DpRule> denies = applicable.stream().filter(r -> !isAllow(r)).toList();

		Set<String> allowedLogins = new TreeSet<>();
		allows.forEach(r -> allowedLogins.addAll(principals(r)));

		AccessLock lock = matchingLock(request, allowedLogins, locks, now);
		if (lock != null) {
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.LOCKED, lock.id(), lockName(lock));
		}
		if (!denies.isEmpty()) {
			DpRule d = denies.get(0);
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.EXPLICIT_DENY, d.id(), d.name());
		}
		if (allows.isEmpty()) {
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.NO_MATCHING_ALLOW, null, null);
		}

		String requested = request.requestedPrincipal();
		if (requested != null && !allowedLogins.contains(requested)) {
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.PRINCIPAL_NOT_ALLOWED, null, null);
		}

		// Capabilities/TTL are gated per grant (FR-AUTHZ-6): scope them to the allows
		// that grant the CHOSEN login, so capabilities from a different login's grant
		// never bleed onto this connect. The null-principal ("what may I do") case
		// keeps
		// the union across all allows.
		List<DpRule> contributing = requested == null
				? allows
				: allows.stream().filter(r -> principals(r).contains(requested)).toList();
		Set<String> capabilities = new TreeSet<>();
		contributing.forEach(r -> capabilities.addAll(Capabilities.effective(setOf(r.capabilities()))));
		int grantTtl = contributing.stream().mapToInt(DpRule::ttlSeconds).filter(t -> t > 0).min().orElse(0);
		DpRule representative = contributing.get(0); // applicable is id-sorted → lowest id
		return DataPlaneDecision.allow(allowedLogins, capabilities, grantTtl, representative.id(),
				representative.name());
	}

	private static boolean isAllow(DpRule rule) {
		return "allow".equals(rule.effect());
	}

	private static boolean applies(DpRule rule, AuthorizationRequest request) {
		if (!Selectors.identityMatches(rule.identitySelector(), request.identity(), request.groups())
				|| !Selectors.labelMatches(rule.nodeLabelSelector(), request.nodeLabels())) {
			return false;
		}
		// Source IP is a DENY-ONLY reducer (FR-AUTH-15, §8.4): it may suppress an
		// ALLOW,
		// but must never remove a DENY (deny must fail closed). A deny applies on
		// identity ∧ node-label regardless of source.
		return !isAllow(rule) || Selectors.sourceIpPasses(rule.sourceIpCondition(), request.sourceIp());
	}

	private static AccessLock matchingLock(AuthorizationRequest request, Set<String> allowedLogins,
			Collection<AccessLock> locks, Instant now) {
		LockMatching.LockSubject subject = new LockMatching.LockSubject(request.identity(),
				request.nodeId() == null ? null : request.nodeId().toString(), request.nodeLabels(),
				Set.copyOf(allowedLogins), request.requestedPrincipal(), Set.copyOf(request.groups()));
		return locks.stream().filter(l -> unexpired(l, now))
				.filter(l -> LockMatching.matches(l.targetSelector(), subject))
				.min(Comparator.comparing(AccessLock::id)).orElse(null);
	}

	private static boolean unexpired(AccessLock lock, Instant now) {
		return lock.expiresAt() == null || lock.expiresAt().isAfter(now);
	}

	private static Set<String> principals(DpRule rule) {
		return setOf(rule.principals());
	}

	private static Set<String> setOf(List<String> values) {
		return values == null ? Set.of() : Set.copyOf(values);
	}

	private static String lockName(AccessLock lock) {
		return lock.reason() == null ? "lock" : "lock:" + lock.reason();
	}
}
