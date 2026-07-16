package io.sessionlayer.controlplane.support;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Base for the Session 17 config-management CRUD ITs: the {@link AbstractAuthIT}
 * container + a bearer token minted for a fresh service account granted an exact
 * set of platform permissions ({@link #tokenWith}), mirroring the per-suite
 * helper the S10/S16 CRUD ITs each inlined.
 */
@AutoConfigureWebTestClient
public abstract class AbstractConfigApiIT extends AbstractAuthIT {

	@Autowired
	protected WebTestClient client;
	@Autowired
	protected AuditEventRepository auditEvents;
	@Autowired
	private MachineIdentityService machineIdentity;
	@Autowired
	private ServiceAccountRepository serviceAccounts;
	@Autowired
	private PlatformRoleRepository roles;
	@Autowired
	private RoleBindingRepository bindings;

	/** Mint a bearer token for a new service account granted exactly {@code permissions}. */
	protected String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles
					.save(PlatformRole.create("role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
