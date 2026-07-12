package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.agent.AgentJoinProperties;
import io.sessionlayer.controlplane.agent.AgentJoinTokenService;
import io.sessionlayer.controlplane.agent.AgentNodeNames;
import io.sessionlayer.controlplane.api.JoinTokensApi;
import io.sessionlayer.controlplane.api.model.IssueJoinTokenRequest;
import io.sessionlayer.controlplane.api.model.IssuedJoinToken;
import io.sessionlayer.controlplane.api.model.JoinTokenList;
import io.sessionlayer.controlplane.api.model.JoinTokenResource;
import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.runtime.JoinToken;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The secured REST surface for Agent join tokens (Design §8.1; FR-JOIN-2). Each
 * route is platform-RBAC gated ({@code node:enroll}) + audited; the generic
 * {@code 403} on an unauthorized/empty subject mirrors {@link LockController}.
 * Issuance returns the raw single-use token EXACTLY once (only its hash is
 * stored); listing returns metadata only (never the raw token/hash); revoke is
 * idempotent. Because issuance is a pure API operation, an autoscaler /
 * config-mgmt can re-provision a token-join Agent without a human.
 */
@RestController
public class JoinTokenController implements JoinTokensApi {

	private final AgentJoinTokenService joinTokens;
	private final AgentJoinProperties properties;
	private final AuditWriter audit;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final TransactionalOperator tx;

	public JoinTokenController(AgentJoinTokenService joinTokens, AgentJoinProperties properties, AuditWriter audit,
			PlatformAuthorization platformAuthorization, CurrentAuthentication currentAuthentication,
			TransactionalOperator tx) {
		this.joinTokens = joinTokens;
		this.properties = properties;
		this.audit = audit;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
		this.tx = tx;
	}

	@Override
	public Mono<ResponseEntity<IssuedJoinToken>> issueJoinToken(Mono<IssueJoinTokenRequest> issueJoinTokenRequest,
			ServerWebExchange exchange) {
		return issueJoinTokenRequest.flatMap(req -> withPermission(PlatformPermissions.NODE_ENROLL, subject -> {
			String nodeName = req.getNodeName();
			// Validate before minting: the name flows into the token scope and later a
			// cert CN/SAN, so a bad name is a 400, never a persisted token.
			if (!AgentNodeNames.isValid(nodeName)) {
				throw new JoinTokenValidationException("invalid nodeName");
			}
			Duration ttl = clampTtl(req.getTtlSeconds());
			// Persist + audit atomically so a mint that cannot be audited never stands.
			Mono<AgentJoinTokenService.MintedJoinToken> minted = tx
					.transactional(
							joinTokens.mint(nodeName, subject.identity(), ttl)
									.flatMap(token -> audit
											.record(subject.identity(), token.id().toString(), "join_token.issue",
													"success", null, null, Map.of("node_name", nodeName))
											.thenReturn(token)));
			return minted.map(token -> ResponseEntity.status(HttpStatus.CREATED).body(toIssued(token)));
		}));
	}

	@Override
	public Mono<ResponseEntity<JoinTokenList>> listJoinTokens(ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.NODE_ENROLL,
				subject -> joinTokens.listActive().map(JoinTokenController::toResource).collectList()
						.map(list -> ResponseEntity.ok(new JoinTokenList(list))));
	}

	@Override
	public Mono<ResponseEntity<Void>> revokeJoinToken(UUID joinTokenId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.NODE_ENROLL, subject -> {
			// Idempotent: 204 whether or not the token existed (revoking an already-gone /
			// already-consumed token is a no-op; revocation of an issued identity is a
			// Lock).
			Mono<Void> revoked = tx.transactional(joinTokens.revoke(joinTokenId).then(audit.record(subject.identity(),
					joinTokenId.toString(), "join_token.revoke", "success", null, null, Map.of())));
			return revoked.thenReturn(ResponseEntity.noContent().<Void>build());
		});
	}

	private Duration clampTtl(Integer requestedSeconds) {
		if (requestedSeconds == null || requestedSeconds <= 0) {
			return properties.getJoinTokenTtl();
		}
		Duration requested = Duration.ofSeconds(requestedSeconds);
		Duration max = properties.getJoinTokenMaxTtl();
		return requested.compareTo(max) > 0 ? max : requested;
	}

	private <T> Mono<ResponseEntity<T>> withPermission(String permission,
			Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject()
				.flatMap(subject -> platformAuthorization.authorize(subject, permission, null)
						.flatMap(decision -> decision.allowed()
								? action.apply(subject)
								: Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<T>build())))
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	private static IssuedJoinToken toIssued(AgentJoinTokenService.MintedJoinToken minted) {
		return new IssuedJoinToken(minted.id(), minted.rawToken(), minted.nodeName(),
				IssuedJoinToken.JoinMethodEnum.TOKEN, Boolean.TRUE, toOffset(minted.expiresAt()));
	}

	private static JoinTokenResource toResource(JoinToken token) {
		JoinTokenResource resource = new JoinTokenResource(token.id(), AgentJoinTokenService.scopedNodeName(token),
				JoinTokenResource.JoinMethodEnum.TOKEN, token.singleUse(), toOffset(token.expiresAt()),
				toOffset(token.createdAt()));
		resource.setCreatedBy(token.createdBy());
		return resource;
	}

	private static OffsetDateTime toOffset(Instant instant) {
		return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
	}
}
