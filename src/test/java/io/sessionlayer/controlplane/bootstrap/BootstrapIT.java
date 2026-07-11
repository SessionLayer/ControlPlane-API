package io.sessionlayer.controlplane.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.bootstrap.BootstrapService.ClaimOutcome;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

/**
 * First-admin bootstrap (FR-BOOT-2): provision + race-safe self-disable +
 * claim.
 */
class BootstrapIT extends AbstractAuthIT {

	@Autowired
	BootstrapService bootstrapService;
	@Autowired
	PlatformRoleRepository roles;
	@Autowired
	RoleBindingRepository bindings;
	@Autowired
	DatabaseClient db;

	@BeforeEach
	void resetBootstrap() {
		db.sql("DELETE FROM config.role_binding WHERE role_id IN (SELECT id FROM config.platform_role"
				+ " WHERE name = 'platform-admin')").fetch().rowsUpdated().block();
		db.sql("DELETE FROM config.platform_role WHERE name = 'platform-admin'").fetch().rowsUpdated().block();
	}

	@Test
	void claimProvisionsTheAdminAndSelfDisables() {
		arm("secret-cred-1");

		assertThat(bootstrapService.claim("secret-cred-1", "admin@corp.example").block())
				.isEqualTo(ClaimOutcome.PROVISIONED);

		PlatformRole role = roles.findByName("platform-admin").block();
		assertThat(role).isNotNull();
		assertThat(role.permissions()).contains(PlatformPermissions.USER_MANAGE, PlatformPermissions.RBAC_WRITE);
		List<RoleBinding> adminBindings = bindings.findByRoleId(role.id()).collectList().block();
		assertThat(adminBindings).anyMatch(b -> "admin@corp.example".equals(b.subject()));
		assertThat(completed()).isTrue();

		// Self-disabled: a second claim is refused.
		assertThat(bootstrapService.claim("secret-cred-1", "attacker@corp.example").block())
				.isEqualTo(ClaimOutcome.ALREADY_COMPLETED);
	}

	@Test
	void wrongCredentialIsRejected() {
		arm("the-real-cred");
		assertThat(bootstrapService.claim("wrong-cred", "admin@corp.example").block())
				.isEqualTo(ClaimOutcome.INVALID_CREDENTIAL);
		assertThat(completed()).isFalse();
	}

	@Test
	void selfDisablesWhenAPlatformAdminAlreadyExists() {
		// An admin role+binding already exists; arm + not-completed.
		PlatformRole admin = roles
				.save(PlatformRole.create("platform-admin", List.copyOf(PlatformPermissions.ALL), "admin", "default"))
				.block();
		bindings.save(RoleBinding.create(admin.id(), "user", "someone@corp.example", null, "default")).block();
		setCompleted(false);

		bootstrapService.runAtStartup().block();

		// The startup path self-disabled without arming a credential.
		assertThat(completed()).isTrue();
		assertThat(bootstrapService.hasPlatformAdmin().block()).isTrue();
	}

	private void arm(String credential) {
		db.sql("UPDATE config.operator_settings SET bootstrap_completed = false, bootstrap_completed_at = null,"
				+ " bootstrap_credential_hash = :hash WHERE singleton = true")
				.bind("hash", Secrets.sha256Hex(credential)).fetch().rowsUpdated().block();
	}

	private void setCompleted(boolean value) {
		db.sql("UPDATE config.operator_settings SET bootstrap_completed = :v WHERE singleton = true").bind("v", value)
				.fetch().rowsUpdated().block();
	}

	private boolean completed() {
		return Boolean.TRUE.equals(db.sql("SELECT bootstrap_completed FROM config.operator_settings WHERE singleton")
				.map(r -> r.get(0, Boolean.class)).one().block());
	}
}
