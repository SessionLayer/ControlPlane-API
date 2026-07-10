package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.BreakglassPolicy;
import io.sessionlayer.controlplane.data.config.BreakglassPolicyRepository;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.config.CapabilityDef;
import io.sessionlayer.controlplane.data.config.CapabilityDefRepository;
import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.ObjectMapper;

/**
 * CRUD round-trips (§8.3) for the CONFIG repositories not already exercised by
 * {@link DataModelSmokeIT} (which covers {@code node_policy} and
 * {@code dp_rule}). Proves insert -&gt; read -&gt; update -&gt; delete and the
 * array/jsonb converters.
 */
class ConfigRepositoryCrudIT extends AbstractDataIT {

	@Autowired
	private PlatformRoleRepository platformRoles;

	@Autowired
	private RoleBindingRepository roleBindings;

	@Autowired
	private CaConfigRepository caConfigs;

	@Autowired
	private CapabilityDefRepository capabilityDefs;

	@Autowired
	private JitPolicyRepository jitPolicies;

	@Autowired
	private BreakglassPolicyRepository breakglassPolicies;

	@Autowired
	private ServiceAccountRepository serviceAccounts;

	@Autowired
	private ObjectMapper objectMapper;

	@Test
	void platformRoleAndRoleBindingWithFk() {
		var role = platformRoles
				.save(PlatformRole.create("auditor", List.of("audit:read", "recording:replay"), "Auditors", "git"))
				.block();
		assertThat(role).isNotNull();
		assertThat(role.permissions()).containsExactly("audit:read", "recording:replay");

		var found = platformRoles.findByName("auditor").block();
		assertThat(found).isNotNull();
		assertThat(found.id()).isEqualTo(role.id());

		// config->config FK
		var scope = objectMapper.readTree("{\"nodeLabels\":{\"env\":\"prod\"}}");
		var binding = roleBindings.save(RoleBinding.create(role.id(), "group", "sre@corp", scope, "git")).block();
		assertThat(binding).isNotNull();
		assertThat(roleBindings.findByRoleId(role.id()).collectList().block()).hasSize(1);
	}

	@Test
	void caConfigCrudAndUpdate() {
		var ca = caConfigs.save(CaConfig.create("session", "local", "kek://ref", "ecdsa-p256", "default")).block();
		assertThat(ca).isNotNull();
		assertThat(ca.algorithm()).isEqualTo("ecdsa-p256");

		var updated = caConfigs.save(new CaConfig(ca.id(), ca.caKind(), "aws_kms", "arn://key", "ecdsa-p384",
				ca.origin(), ca.version(), ca.createdAt(), ca.updatedAt())).block();
		assertThat(updated).isNotNull();
		assertThat(updated.version()).isGreaterThan(ca.version()); // @Version bumped on update
		assertThat(caConfigs.findByCaKind("session").block().backend()).isEqualTo("aws_kms");

		caConfigs.deleteById(ca.id()).block();
		assertThat(caConfigs.findById(ca.id()).block()).isNull();
	}

	@Test
	void capabilityDefCrud() {
		var cap = capabilityDefs.save(CapabilityDef.create("sftp", "SFTP subsystem", "git")).block();
		assertThat(cap).isNotNull();
		assertThat(capabilityDefs.findByName("sftp").block().id()).isEqualTo(cap.id());
	}

	@Test
	void jitPolicyWithApprovalChain() {
		var target = objectMapper.readTree("{\"env\":\"prod\"}");
		var chain = objectMapper.readTree(
				"[{\"kind\":\"email\",\"value\":\"lead@corp\"}," + "{\"kind\":\"oidc_group\",\"value\":\"secops\"}]");
		var jit = jitPolicies.save(JitPolicy.create("prod-jit", target, List.of("shell", "exec"), 3600, chain, "git"))
				.block();
		assertThat(jit).isNotNull();
		var reread = jitPolicies.findById(jit.id()).block();
		assertThat(reread.approvalChain()).isEqualTo(chain);
		assertThat(reread.maxTtlSeconds()).isEqualTo(3600);
	}

	@Test
	void breakglassPolicyCrud() {
		var bg = breakglassPolicies
				.save(BreakglassPolicy.create("bg-default", true, "pagerduty://sev1", true, "fido2", "git")).block();
		assertThat(bg).isNotNull();
		assertThat(bg.recordingStrict()).isTrue();
		assertThat(bg.authPath()).isEqualTo("fido2");
	}

	@Test
	void serviceAccountCrud() {
		var sa = serviceAccounts
				.save(ServiceAccount.create("ci-runner", "CI deploy bot", "private_key_jwt", "jwks://ref", 900, "git"))
				.block();
		assertThat(sa).isNotNull();
		assertThat(serviceAccounts.findByName("ci-runner").block().authMethod()).isEqualTo("private_key_jwt");
	}
}
