package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformDecision;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformScope;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Part C — the platform-RBAC engine end to end (FR-PADM-1/2/3): default-deny,
 * scoped {@code recording:replay} enforced, and <b>every</b> decision written
 * to the audit stream. Uses unique subjects per case so the shared-context DB
 * does not cross-contaminate.
 */
class PlatformAuthorizationIT extends AbstractMtlsIT {

	@Autowired
	private PlatformAuthorization platformAuthorization;
	@Autowired
	private PlatformRoleRepository roles;
	@Autowired
	private RoleBindingRepository bindings;

	@Test
	void defaultDenyWhenNoBinding() {
		PlatformDecision decision = platformAuthorization.authorize(
				new PlatformSubject("stranger-" + unique(), List.of()), PlatformPermissions.USER_MANAGE, null).block();
		assertThat(decision.allowed()).isFalse();
		assertThat(decision.reason()).isEqualTo(PlatformDecision.Reason.NO_GRANTING_BINDING);
		assertAudited(decision, "denied");
	}

	@Test
	void unscopedPermissionGrantedByUnscopedBinding() {
		String actor = "admin-" + unique();
		UUID roleId = saveRole("admins-" + unique(), List.of(PlatformPermissions.USER_MANAGE));
		saveBinding(roleId, "user", actor, null);

		PlatformDecision decision = platformAuthorization
				.authorize(new PlatformSubject(actor, List.of()), PlatformPermissions.USER_MANAGE, null).block();
		assertThat(decision.allowed()).isTrue();
		assertAudited(decision, "success");
	}

	@Test
	void scopedRecordingReplayOnlyWithinScope() {
		String actor = "auditor-" + unique();
		UUID roleId = saveRole("replayers-" + unique(), List.of(PlatformPermissions.RECORDING_REPLAY));
		ObjectNode scope = JsonNodeFactory.instance.objectNode();
		scope.set("node_labels", JsonNodeFactory.instance.objectNode().put("env", "prod"));
		saveBinding(roleId, "user", actor, scope);

		PlatformScope inScope = new PlatformScope(Map.of("env", "prod"), "someuser", Instant.now());
		PlatformScope outOfScope = new PlatformScope(Map.of("env", "staging"), "someuser", Instant.now());

		PlatformDecision allowed = platformAuthorization
				.authorize(new PlatformSubject(actor, List.of()), PlatformPermissions.RECORDING_REPLAY, inScope)
				.block();
		PlatformDecision denied = platformAuthorization
				.authorize(new PlatformSubject(actor, List.of()), PlatformPermissions.RECORDING_REPLAY, outOfScope)
				.block();

		assertThat(allowed.allowed()).isTrue();
		assertThat(denied.allowed()).isFalse();
		assertThat(denied.reason()).isEqualTo(PlatformDecision.Reason.OUT_OF_SCOPE);
		assertAudited(allowed, "success");
	}

	@Test
	void groupBindingGrantsGroupMembers() {
		String group = "sec-" + unique();
		UUID roleId = saveRole("group-role-" + unique(), List.of(PlatformPermissions.AUDIT_READ));
		saveBinding(roleId, "group", group, null);

		PlatformDecision member = platformAuthorization.authorize(
				new PlatformSubject("carol-" + unique(), List.of(group)), PlatformPermissions.AUDIT_READ, null).block();
		PlatformDecision nonMember = platformAuthorization.authorize(
				new PlatformSubject("dan-" + unique(), List.of("other")), PlatformPermissions.AUDIT_READ, null).block();
		assertThat(member.allowed()).isTrue();
		assertThat(nonMember.allowed()).isFalse();
	}

	private UUID saveRole(String name, List<String> permissions) {
		return roles.save(PlatformRole.create(name, permissions, "test", "api")).map(PlatformRole::id).block();
	}

	private void saveBinding(UUID roleId, String kind, String subject, ObjectNode scope) {
		bindings.save(RoleBinding.create(roleId, kind, subject, scope, "api")).block();
	}

	private void assertAudited(PlatformDecision decision, String outcome) {
		Long count = db.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'platform.authz' AND outcome = :o")
				.bind("o", outcome).map((row, meta) -> row.get(0, Long.class)).one().block();
		assertThat(count).isGreaterThan(0L);
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
