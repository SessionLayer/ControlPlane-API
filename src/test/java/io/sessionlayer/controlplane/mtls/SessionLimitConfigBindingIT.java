package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * FR-SESS-3 — the cluster-default concurrent-session cap is settable via
 * standard deployment config, not DB-only. The
 * {@code sessionlayer.session-limits.default-max-concurrent} property is
 * reconciled into {@code operator_settings.default_max_concurrent_sessions} at
 * bootstrap and the Authorize path enforces it. Semantics: property SET ⇒
 * config-managed / authoritative on each boot; property UNSET ⇒ the DB value
 * (runtime-mutable singleton) stands — as every other IT here runs, unlimited
 * by default — so an operator picks exactly one source unambiguously.
 */
@TestPropertySource(properties = {"sessionlayer.session-limits.default-max-concurrent=2",
		"sessionlayer.session-limits.default-max-session-seconds=7200",
		"sessionlayer.session-limits.default-idle-timeout-seconds=1200"})
class SessionLimitConfigBindingIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Autowired
	private OperatorSettingsRepository operatorSettings;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;

	// Restore the shared singleton so other ITs (which share this Postgres) see the
	// null/unlimited default.
	@AfterEach
	void resetClusterDefault() {
		db.sql("UPDATE config.operator_settings SET default_max_concurrent_sessions = NULL, "
				+ "default_max_session_seconds = NULL, default_idle_timeout_seconds = NULL WHERE singleton = true")
				.fetch().rowsUpdated().block();
	}

	@Test
	void deploymentConfigSeedsAndEnforcesTheClusterDefault() {
		// All three FR-SESS-3 default knobs were reconciled into the cluster-default
		// columns at boot (S25: the duration/idle defaults are enforceable from
		// deployment config too — no dead default).
		var settings = operatorSettings.findSingleton().block();
		assertThat(settings.defaultMaxConcurrentSessions()).isEqualTo(2);
		assertThat(settings.defaultMaxSessionSeconds()).isEqualTo(7200);
		assertThat(settings.defaultIdleTimeoutSeconds()).isEqualTo(1200);

		// ...and the Authorize path enforces that config-seeded default for an identity
		// with no per-identity policy: two sessions allowed, the third refused.
		String identity = "cfg-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-cfg-" + unique());
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal("deploy").setSourceIp("203.0.113.5").setSessionId(UUID.randomUUID().toString())
				.build();
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return AuthorizationGrpc.newBlockingStub(channel).authorize(request);
		} finally {
			shutdown(channel);
		}
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, UUID nodeId) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, List.of("deploy"), 3600,
				List.of("shell"), "allow", "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
