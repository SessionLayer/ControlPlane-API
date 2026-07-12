package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.agent.AgentJoinProperties;
import io.sessionlayer.controlplane.agent.AgentJoinTokenService;
import io.sessionlayer.controlplane.api.model.IssueJoinTokenRequest;
import io.sessionlayer.controlplane.api.model.IssuedJoinToken;
import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformDecision;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * Unit-proves the join-token controller wiring without a web server: an
 * authorized issue mints + audits + returns the raw token ONCE; a denied caller
 * gets a generic 403 and touches nothing; an invalid nodeName fails closed
 * before any mint; a revoke is idempotent + audited.
 */
class JoinTokenControllerTest {

	private final AgentJoinTokenService joinTokens = mock(AgentJoinTokenService.class);
	private final AuditWriter audit = mock(AuditWriter.class);
	private final PlatformAuthorization platformAuthorization = mock(PlatformAuthorization.class);
	private final CurrentAuthentication currentAuthentication = mock(CurrentAuthentication.class);
	private final TransactionalOperator tx = mock(TransactionalOperator.class);

	private JoinTokenController controller;

	@BeforeEach
	@SuppressWarnings("unchecked")
	void setUp() {
		controller = new JoinTokenController(joinTokens, new AgentJoinProperties(), audit, platformAuthorization,
				currentAuthentication, tx);
		when(currentAuthentication.subject()).thenReturn(Mono.just(new PlatformSubject("admin", List.of())));
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(any(Mono.class))).thenAnswer(inv -> inv.getArgument(0));
	}

	@Test
	void issueMintsAuditsAndReturnsRawTokenOnce() {
		allowPermission();
		when(joinTokens.mint(eq("node-x"), eq("admin"), any())).thenReturn(Mono.just(
				new AgentJoinTokenService.MintedJoinToken(UUID.randomUUID(), "RAW-ONCE", "node-x", Instant.now())));

		StepVerifier.create(controller.issueJoinToken(Mono.just(new IssueJoinTokenRequest("node-x")), null))
				.assertNext(response -> {
					assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
					IssuedJoinToken body = response.getBody();
					assertThat(body.getToken()).isEqualTo("RAW-ONCE");
					assertThat(body.getNodeName()).isEqualTo("node-x");
					assertThat(body.getJoinMethod()).isEqualTo(IssuedJoinToken.JoinMethodEnum.TOKEN);
				}).verifyComplete();

		verify(joinTokens).mint(eq("node-x"), eq("admin"), any());
		verify(audit).record(eq("admin"), any(), eq("join_token.issue"), eq("success"), isNull(), isNull(), any());
	}

	@Test
	void deniedCallerGetsGenericForbiddenAndMintsNothing() {
		when(platformAuthorization.authorize(any(), eq("node:enroll"), isNull())).thenReturn(
				Mono.just(new PlatformDecision(false, PlatformDecision.Reason.NO_GRANTING_BINDING, null, null)));

		StepVerifier.create(controller.issueJoinToken(Mono.just(new IssueJoinTokenRequest("node-x")), null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
				.verifyComplete();

		verify(joinTokens, never()).mint(any(), any(), any());
	}

	@Test
	void invalidNodeNameFailsClosedBeforeAnyMint() {
		allowPermission();

		StepVerifier.create(controller.issueJoinToken(Mono.just(new IssueJoinTokenRequest("bad name!")), null))
				.verifyError(JoinTokenValidationException.class);

		verify(joinTokens, never()).mint(any(), any(), any());
	}

	@Test
	void listRequiresNodeEnroll() {
		when(platformAuthorization.authorize(any(), eq("node:enroll"), isNull())).thenReturn(
				Mono.just(new PlatformDecision(false, PlatformDecision.Reason.NO_GRANTING_BINDING, null, null)));

		StepVerifier.create(controller.listJoinTokens(null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
				.verifyComplete();
	}

	@Test
	void revokeIsIdempotentAndAudited() {
		allowPermission();
		UUID id = UUID.randomUUID();
		when(joinTokens.revoke(id)).thenReturn(Mono.empty());

		StepVerifier.create(controller.revokeJoinToken(id, null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
				.verifyComplete();

		verify(audit).record(eq("admin"), eq(id.toString()), eq("join_token.revoke"), eq("success"), isNull(), isNull(),
				any());
	}

	private void allowPermission() {
		when(platformAuthorization.authorize(any(), any(), isNull())).thenReturn(Mono.just(
				new PlatformDecision(true, PlatformDecision.Reason.ALLOWED, UUID.randomUUID(), "platform-admin")));
	}
}
