package io.sessionlayer.controlplane.platform;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * The platform-RBAC engine (FR-PADM-1/2/3). Default-deny: {@code subject} is
 * granted {@code permission} only if some {@code role_binding} that targets it
 * maps to a {@link PlatformRole} carrying the permission <b>and</b> whose scope
 * covers the request (FR-PADM-2). <b>Every</b> decision — allow or deny — is
 * written to the audit stream (FR-PADM-3/FR-AUD-7). Deliberately independent of
 * the data-plane RBAC engine ({@code authz}): different subjects/verbs/blast
 * radius, no shared rules or code (Design §6).
 */
@Service
public class PlatformAuthorizationService implements PlatformAuthorization {

	private static final Logger LOG = LoggerFactory.getLogger(PlatformAuthorizationService.class);
	private static final String ACTION = "platform.authz";

	private final PlatformRoleRepository roles;
	private final RoleBindingRepository bindings;
	private final AuditEventStore audit;

	public PlatformAuthorizationService(PlatformRoleRepository roles, RoleBindingRepository bindings,
			AuditEventStore audit) {
		this.roles = roles;
		this.bindings = bindings;
		this.audit = audit;
	}

	@Override
	public Mono<PlatformDecision> authorize(PlatformSubject subject, String permission, PlatformScope scope) {
		return Mono.zip(roles.findAll().collectMap(PlatformRole::id), bindings.findAll().collectList())
				.map(loaded -> decide(loaded.getT1(), loaded.getT2(), subject, permission, scope))
				.onErrorResume(failure -> {
					LOG.warn("platform authorization failed closed: {}", failure.toString());
					return Mono.just(PlatformDecision.deny(PlatformDecision.Reason.EVALUATION_ERROR));
				}).flatMap(decision -> auditDecision(subject, permission, scope, decision).thenReturn(decision));
	}

	@Override
	public Mono<ScopeGrant> resolveScopeGrant(PlatformSubject subject, String permission) {
		return Mono.zip(roles.findAll().collectMap(PlatformRole::id), bindings.findAll().collectList())
				.map(loaded -> resolveScope(loaded.getT1(), loaded.getT2(), subject, permission))
				.onErrorResume(failure -> {
					LOG.warn("platform scope resolution failed closed: {}", failure.toString());
					return Mono.just(ScopeGrant.deny());
				});
	}

	private ScopeGrant resolveScope(Map<UUID, PlatformRole> roleById, List<RoleBinding> allBindings,
			PlatformSubject subject, String permission) {
		boolean granted = false;
		List<tools.jackson.databind.JsonNode> scopes = new java.util.ArrayList<>();
		for (RoleBinding binding : allBindings) {
			if (!targets(binding, subject)) {
				continue;
			}
			PlatformRole role = roleById.get(binding.roleId());
			if (role == null || !permissions(role).contains(permission)) {
				continue;
			}
			granted = true;
			var scope = binding.scope();
			if (scope == null || scope.isNull() || scope.isEmpty()) {
				return ScopeGrant.all(); // an unscoped grant sees everything
			}
			scopes.add(scope);
		}
		return granted ? ScopeGrant.scoped(scopes) : ScopeGrant.deny();
	}

	private PlatformDecision decide(Map<UUID, PlatformRole> roleById, List<RoleBinding> allBindings,
			PlatformSubject subject, String permission, PlatformScope scope) {
		boolean sawPermissionOutOfScope = false;
		// Deterministic attribution: iterate in id order so the matched role logged for
		// an audit is a pure function of the binding set, not the query encounter
		// order.
		List<RoleBinding> ordered = allBindings.stream().sorted(java.util.Comparator.comparing(RoleBinding::id))
				.toList();
		for (RoleBinding binding : ordered) {
			if (!targets(binding, subject)) {
				continue;
			}
			PlatformRole role = roleById.get(binding.roleId());
			if (role == null || !permissions(role).contains(permission)) {
				continue;
			}
			if (PlatformScopes.covers(binding.scope(), scope)) {
				return PlatformDecision.allow(role.id(), role.name());
			}
			sawPermissionOutOfScope = true;
		}
		return PlatformDecision.deny(sawPermissionOutOfScope
				? PlatformDecision.Reason.OUT_OF_SCOPE
				: PlatformDecision.Reason.NO_GRANTING_BINDING);
	}

	private static boolean targets(RoleBinding binding, PlatformSubject subject) {
		if ("user".equals(binding.subjectKind())) {
			return binding.subject() != null && binding.subject().equals(subject.identity());
		}
		if ("group".equals(binding.subjectKind())) {
			return subject.groups().contains(binding.subject());
		}
		return false;
	}

	private static List<String> permissions(PlatformRole role) {
		return role.permissions() == null ? List.of() : role.permissions();
	}

	private Mono<Void> auditDecision(PlatformSubject subject, String permission, PlatformScope scope,
			PlatformDecision decision) {
		Map<String, String> detail = new HashMap<>();
		detail.put("permission", permission);
		detail.put("reason", decision.reason().name());
		detail.put("scoped", Boolean.toString(scope != null));
		if (decision.matchedRoleName() != null) {
			detail.put("matched_role", decision.matchedRoleName());
		}
		String outcome = decision.allowed() ? "success" : "denied";
		return audit.record(subject.identity(), permission, ACTION, outcome, null, null, detail)
				.onErrorResume(e -> Mono.empty());
	}
}
