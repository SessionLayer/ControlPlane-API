package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import io.sessionlayer.controlplane.oidc.IdTokenValidator;
import io.sessionlayer.controlplane.oidc.IdpJwtDecoder;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import io.sessionlayer.controlplane.oidc.ResolvedIdentity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * FR-AUTH-8 — an OIDC-validated identity's <b>groups</b> map to the RBAC login
 * <b>server-side</b>. End to end: the {@link IdTokenValidator} resolves
 * identity + groups from a validated ID token (server-side claim resolution),
 * and a data-plane rule keyed purely on the group grants exactly the mapped
 * Linux login at {@code Authorize}. The negative — the same identity WITHOUT
 * the group — is denied, proving the group membership is what maps to the login
 * (not the identity or a client assertion).
 */
class OidcGroupToLoginAuthorizeIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;

	@Test
	void oidcValidatedGroupsMapToTheRbacLoginServerSide() {
		String group = "team-" + unique();
		String login = "appuser";
		String email = "grp-" + unique() + "@example.com";

		// Server-side: validate an ID token and resolve identity + groups from it (the
		// FR-AUTH-7/8 resolution, not a client-asserted group).
		ResolvedIdentity resolved = resolveFromIdToken(email, group);
		assertThat(resolved.identity()).isEqualTo(email);
		assertThat(resolved.groups()).containsExactly(group);

		UUID nodeId = seedProdNode();
		Node node = nodes.findById(nodeId).block();
		// A rule keyed on the GROUP alone (no identity list) → the mapped login.
		seedGroupAllow(group, List.of(login));
		EnrolledGateway gateway = enroll("gw-oidc-grp-" + unique());

		AuthorizeResponse allow = authorize(gateway, resolved.identity(), resolved.groups(), node.name(), login);
		assertThat(allow.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext parsed = parse(allow);
		assertThat(parsed.getAllowedLoginsList()).containsExactly(login);
		assertThat(parsed.getPrincipal()).isEqualTo(login);
		// The resolved groups are signed into the context (matched server-side, S10).
		assertThat(parsed.getIdentityGroupsList()).containsExactly(group);

		// The same identity WITHOUT the group does not resolve to the login — the group
		// membership is the mapping (fail closed).
		AuthorizeResponse deny = authorize(gateway, resolved.identity(), List.of(), node.name(), login);
		assertThat(deny.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(deny.getSessionToken()).isEmpty();
	}

	// Mirrors OidcJwtValidationTest: the decoder is mocked (its
	// signature/iss/aud/exp
	// gates are proven there); here we exercise the server-side identity+groups
	// resolution the validated token feeds into RBAC.
	private ResolvedIdentity resolveFromIdToken(String email, String group) {
		IdpJwtDecoder decoder = mock(IdpJwtDecoder.class);
		OidcProperties props = new OidcProperties();
		props.setIdentityClaim("email");
		props.setGroupsClaim("groups");
		Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "sub-" + unique()).claim("email", email)
				.claim("groups", List.of(group)).claim("nonce", "n-1").issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(300)).build();
		when(decoder.decode("t")).thenReturn(Mono.just(jwt));
		return new IdTokenValidator(decoder, props).validate("t", "n-1").block();
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, List<String> groups, String nodeName,
			String principal) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).addAllIdentityGroups(groups)
				.setNodeName(nodeName).setRequestedPrincipal(principal).setSourceIp("10.0.0.5")
				.setSessionId(UUID.randomUUID().toString()).build();
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return AuthorizationGrpc.newBlockingStub(channel).authorize(request);
		} finally {
			shutdown(channel);
		}
	}

	private static DecisionContext parse(AuthorizeResponse response) {
		try {
			return DecisionContext.parseFrom(response.getSignedContext());
		} catch (Exception e) {
			throw new AssertionError("signed context did not parse", e);
		}
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	// A rule that matches on GROUP membership only (identity list omitted) and maps
	// to
	// the given login(s) — the group→login mapping under test.
	private void seedGroupAllow(String group, List<String> principals) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("groups", JSON.arrayNode().add(group));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("grp-rule-" + unique(), identitySelector, labelSelector, null, principals, 3600,
				List.of("shell"), "allow", "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
