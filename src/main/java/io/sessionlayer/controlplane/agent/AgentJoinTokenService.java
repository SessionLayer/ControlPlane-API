package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.data.runtime.JoinToken;
import io.sessionlayer.controlplane.data.runtime.JoinTokenRepository;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import java.time.Duration;
import java.time.Instant;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Mints and atomically consumes single-use Agent <b>join</b> tokens for the
 * {@code TokenJoin} method (Design §8.1, FR-JOIN-2) — the bootstrap credential
 * presented to {@code EnrollAgent}. Mirrors
 * {@code GatewayEnrollmentTokenService} but persists to
 * {@code runtime.join_token} with a {@code node_name} scope +
 * {@code join_method='token'}. {@link #mint} is the admin/API mechanism
 * (surfaced via the secured join-token REST API); {@link #isValid} is the
 * non-burning probe; {@link #consume} verifies scope + expiry and burns the
 * token under the {@code @Version} optimistic lock (a concurrent replay loses
 * the race). The raw token is never stored (hash only); all rejections are
 * generic (fail closed, NFR-2).
 */
@Service
public class AgentJoinTokenService {

	private final JoinTokenRepository tokens;

	public AgentJoinTokenService(JoinTokenRepository tokens) {
		this.tokens = tokens;
	}

	/**
	 * A freshly minted join token: its id, raw bearer value, node scope and expiry.
	 */
	public record MintedJoinToken(java.util.UUID id, String rawToken, String nodeName, Instant expiresAt) {
	}

	/**
	 * Mint a single-use join token scoped to {@code nodeName}. Returns the raw
	 * token (shown once, never stored); only its hash + scope is persisted.
	 */
	public Mono<MintedJoinToken> mint(String nodeName, String createdBy, Duration ttl) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(ttl);
		JoinToken token = JoinToken.create(minted.hash(), scopeFor(nodeName), "token", null, true, expiresAt,
				createdBy);
		return tokens.save(token).map(saved -> new MintedJoinToken(saved.id(), minted.raw(), nodeName, expiresAt));
	}

	/**
	 * Non-consuming validity check for {@code nodeName}: true iff the token exists,
	 * is a {@code token}-method token scoped to this node, is unexpired, and is not
	 * yet consumed. Used to gate the enrollment decision behind a proven-valid
	 * token WITHOUT burning it on a probe; the atomic single-use guarantee rests on
	 * {@link #consume}.
	 */
	public Mono<Boolean> isValid(String rawToken, String nodeName) {
		if (rawToken == null || rawToken.isBlank()) {
			return Mono.just(false);
		}
		Instant now = Instant.now();
		return tokens.findByTokenHash(SingleUseTokens.hash(rawToken)).map(token -> authorizes(token, nodeName, now))
				.defaultIfEmpty(false);
	}

	/**
	 * Verify + atomically consume the join token for {@code nodeName}. Any unknown
	 * / wrong-scope / wrong-method / expired / already-consumed token — or a lost
	 * consume race — is rejected with a generic {@code UNAUTHENTICATED}.
	 */
	public Mono<JoinToken> consume(String rawToken, String nodeName) {
		if (rawToken == null || rawToken.isBlank()) {
			return Mono.error(invalid());
		}
		Instant now = Instant.now();
		return tokens.findByTokenHash(SingleUseTokens.hash(rawToken)).switchIfEmpty(Mono.error(invalid()))
				.flatMap(token -> {
					if (!authorizes(token, nodeName, now)) {
						return Mono.error(invalid());
					}
					JoinToken consumed = new JoinToken(token.id(), token.tokenHash(), token.scope(), token.joinMethod(),
							token.nodeId(), token.singleUse(), token.expiresAt(), now, token.createdBy(),
							token.version(), token.createdAt());
					return tokens.save(consumed).onErrorMap(OptimisticLockingFailureException.class, race -> invalid());
				});
	}

	/** The current unconsumed, unexpired join tokens (metadata only). */
	public Flux<JoinToken> listActive() {
		Instant now = Instant.now();
		return tokens.findByConsumedAtIsNull().filter(token -> token.expiresAt().isAfter(now));
	}

	/** Revoke (delete) a join token by id. Idempotent (a no-op if already gone). */
	public Mono<Void> revoke(java.util.UUID id) {
		return tokens.deleteById(id);
	}

	/**
	 * The {@code node_name} a join token authorizes, or null (not a token scope).
	 */
	public static String scopedNodeName(JoinToken token) {
		JsonNode name = token.scope() == null ? null : token.scope().get("node_name");
		return (name != null && name.isString()) ? name.stringValue() : null;
	}

	private static boolean authorizes(JoinToken token, String nodeName, Instant now) {
		return "token".equals(token.joinMethod()) && token.consumedAt() == null && token.expiresAt().isAfter(now)
				&& nodeName != null && nodeName.equals(scopedNodeName(token));
	}

	private static ObjectNode scopeFor(String nodeName) {
		ObjectNode scope = JsonNodeFactory.instance.objectNode();
		scope.put("node_name", nodeName);
		return scope;
	}

	private static AgentJoinException invalid() {
		return new AgentJoinException(AgentJoinException.Reason.UNAUTHENTICATED, "join token invalid");
	}
}
