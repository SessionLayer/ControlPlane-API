package io.sessionlayer.controlplane.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.data.runtime.JoinToken;
import io.sessionlayer.controlplane.data.runtime.JoinTokenRepository;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Unit-proves the join-token mint/validate/consume gate: mint stores only the
 * hash + a {@code node_name} scope + {@code join_method='token'}; a probe never
 * burns the token; consume is single-use (a replay of a consumed token, a
 * wrong-scope, an expired, or a missing token are all generic rejects).
 */
class AgentJoinTokenServiceTest {

	private static final String RAW = "raw-join-token-value";
	private static final String HASH = SingleUseTokens.hash(RAW);

	private final JoinTokenRepository tokens = mock(JoinTokenRepository.class);
	private final AgentJoinTokenService service = new AgentJoinTokenService(tokens);

	@Test
	void mintStoresHashScopeAndMethodOnly() {
		when(tokens.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
		ArgumentCaptor<JoinToken> saved = ArgumentCaptor.forClass(JoinToken.class);

		AgentJoinTokenService.MintedJoinToken minted = service.mint("node-x", "admin", Duration.ofMinutes(10)).block();

		org.mockito.Mockito.verify(tokens).save(saved.capture());
		JoinToken row = saved.getValue();
		assertThat(row.tokenHash()).isEqualTo(SingleUseTokens.hash(minted.rawToken()));
		assertThat(row.tokenHash()).isNotEqualTo(minted.rawToken()); // hash, never the raw token
		assertThat(row.joinMethod()).isEqualTo("token");
		assertThat(AgentJoinTokenService.scopedNodeName(row)).isEqualTo("node-x");
		assertThat(minted.nodeName()).isEqualTo("node-x");
	}

	@Test
	void isValidIsTrueForAMatchingUnconsumedToken() {
		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(null, future())));
		StepVerifier.create(service.isValid(RAW, "node-x")).expectNext(true).verifyComplete();
	}

	@Test
	void isValidIsFalseForWrongNodeConsumedExpiredOrMissing() {
		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(null, future())));
		StepVerifier.create(service.isValid(RAW, "node-y")).expectNext(false).verifyComplete();

		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(Instant.now().minusSeconds(5), future())));
		StepVerifier.create(service.isValid(RAW, "node-x")).expectNext(false).verifyComplete();

		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(null, Instant.now().minusSeconds(5))));
		StepVerifier.create(service.isValid(RAW, "node-x")).expectNext(false).verifyComplete();

		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.empty());
		StepVerifier.create(service.isValid(RAW, "node-x")).expectNext(false).verifyComplete();
	}

	@Test
	void consumeBurnsThenReplayIsRejected() {
		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(null, future())));
		when(tokens.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

		StepVerifier.create(service.consume(RAW, "node-x"))
				.assertNext(consumed -> assertThat(consumed.consumedAt()).isNotNull()).verifyComplete();

		// A replay of an already-consumed token is a generic reject.
		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(Instant.now().minusSeconds(1), future())));
		StepVerifier.create(service.consume(RAW, "node-x")).verifyError(AgentJoinException.class);
	}

	@Test
	void consumeRejectsWrongScopeExpiredAndMissing() {
		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(null, future())));
		StepVerifier.create(service.consume(RAW, "node-y")).verifyError(AgentJoinException.class);

		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.just(token(null, Instant.now().minusSeconds(5))));
		StepVerifier.create(service.consume(RAW, "node-x")).verifyError(AgentJoinException.class);

		when(tokens.findByTokenHash(HASH)).thenReturn(Mono.empty());
		StepVerifier.create(service.consume(RAW, "node-x")).verifyError(AgentJoinException.class);
	}

	private static Instant future() {
		return Instant.now().plusSeconds(600);
	}

	private static JoinToken token(Instant consumedAt, Instant expiresAt) {
		ObjectNode scope = JsonNodeFactory.instance.objectNode();
		scope.put("node_name", "node-x");
		return new JoinToken(UUID.randomUUID(), HASH, scope, "token", null, true, expiresAt, consumedAt, "admin", 0L,
				Instant.now());
	}
}
