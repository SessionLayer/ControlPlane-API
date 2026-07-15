package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.ConnectorKind;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.NodeConnection;
import io.sessionlayer.controlplane.grpc.v1.PresenceHeartbeatResponse;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * The HA routing READ path folded into {@code Authorize} (Design §10.2/§10.3;
 * FR-HA-2/4/5): the ALLOW {@code NodeConnection} carries the presence owner
 * ONLY for an outbound-agent node with a FRESH owner. A stale/absent owner, or
 * an agentless node, leaves the owner fields empty so the ingress Gateway fails
 * closed to "node offline" (the anti-stale + no-TOFU-of-liveness posture). The
 * owner is written by a heartbeat addressing the node by NAME; the read still
 * keys presence by the node UUID that Authorize resolves.
 */
class AuthorizeOwnerRoutingIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;

	@Test
	void agentNodeWithAFreshOwnerCarriesTheOwnerFields() {
		String identity = "alice-" + unique();
		Node node = seedAgentNode();
		seedAllow(identity, node.id());
		String ownerName = "gw-owner-" + unique();
		EnrolledGateway owner = enroll(ownerName);
		EnrolledGateway ingress = enroll("gw-ingress-" + unique());

		PresenceHeartbeatResponse claim = presenceHeartbeat(owner, node.name(), "10.9.5.5:7000");

		NodeConnection connection = authorizeConnection(ingress, identity, node.id());
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_OUTBOUND_AGENT);
		// The routing answer mirrors the fresh presence owner (the WRITE path above):
		// the owner's gateway_identity.name is the HA routing key the ingress compares.
		assertThat(connection.getOwningGatewayId()).isEqualTo(ownerName);
		assertThat(connection.getOwningGatewayAddr()).isEqualTo("10.9.5.5:7000");
		assertThat(connection.getOwnerNonce()).isEqualTo(claim.getNonce());
		assertThat(connection.getOwnerNonceId()).isEqualTo(claim.getNonceId());
	}

	@Test
	void agentNodeWithAStaleOwnerLeavesTheOwnerFieldsEmpty() {
		String identity = "bob-" + unique();
		Node node = seedAgentNode();
		seedAllow(identity, node.id());
		EnrolledGateway owner = enroll("gw-stale-owner-" + unique());
		EnrolledGateway ingress = enroll("gw-stale-ingress-" + unique());

		presenceHeartbeat(owner, node.name(), "10.9.6.6:7000");
		ageOwnerStale(node.id());

		NodeConnection connection = authorizeConnection(ingress, identity, node.id());
		// A stale owner reads as "no live Gateway holds the agent channel" → empty.
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_OUTBOUND_AGENT);
		assertThat(connection.getOwningGatewayId()).isEmpty();
		assertThat(connection.getOwningGatewayAddr()).isEmpty();
		assertThat(connection.getOwnerNonce()).isZero();
		assertThat(connection.getOwnerNonceId()).isEmpty();
	}

	@Test
	void agentNodeWithNoPresenceRowLeavesTheOwnerFieldsEmpty() {
		String identity = "carol-" + unique();
		Node node = seedAgentNode();
		seedAllow(identity, node.id());
		EnrolledGateway ingress = enroll("gw-noowner-" + unique());

		NodeConnection connection = authorizeConnection(ingress, identity, node.id());
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_OUTBOUND_AGENT);
		assertThat(connection.getOwningGatewayId()).isEmpty();
		assertThat(connection.getOwnerNonce()).isZero();
	}

	@Test
	void agentlessNodeNeverCarriesOwnerFieldsEvenWithAPresenceRow() {
		String identity = "dave-" + unique();
		Node node = seedAgentlessNode("10.0.0.5");
		seedAllow(identity, node.id());
		EnrolledGateway owner = enroll("gw-agentless-owner-" + unique());
		EnrolledGateway ingress = enroll("gw-agentless-ingress-" + unique());

		// Even if a presence row exists, an agentless node has no ownership routing —
		// any Gateway dials it directly (S8 path unchanged), so owner fields stay
		// empty.
		presenceHeartbeat(owner, node.name(), "10.9.7.7:7000");

		NodeConnection connection = authorizeConnection(ingress, identity, node.id());
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_AGENTLESS);
		assertThat(connection.getOwningGatewayId()).isEmpty();
		assertThat(connection.getOwnerNonce()).isZero();
	}

	private NodeConnection authorizeConnection(EnrolledGateway gateway, String identity, UUID nodeId) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			AuthorizeResponse response = AuthorizationGrpc.newBlockingStub(channel)
					.authorize(AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
							.setRequestedPrincipal("deploy").setSessionId(UUID.randomUUID().toString()).build());
			assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
			assertThat(response.hasNodeConnection()).isTrue();
			return response.getNodeConnection();
		} finally {
			shutdown(channel);
		}
	}

	private void ageOwnerStale(UUID nodeId) {
		Long updated = db.sql("UPDATE runtime.presence SET last_seen = now() - interval '1 hour' WHERE node_id = :id")
				.bind("id", nodeId).fetch().rowsUpdated().block();
		assertThat(updated).isEqualTo(1L);
	}

	private Node seedAgentNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("web-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.block();
	}

	private Node seedAgentlessNode(String address) {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes
				.save(Node.create("host-" + unique(), null, labels, "agentless", "active", "healthy", null, address))
				.block();
	}

	private void seedAllow(String identity, UUID nodeId) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, List.of("deploy"), 3600,
				List.of("shell", "exec"), "allow", "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
