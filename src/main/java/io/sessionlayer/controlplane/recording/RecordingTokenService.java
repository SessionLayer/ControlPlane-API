package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.data.runtime.RecordingToken;
import io.sessionlayer.controlplane.data.runtime.RecordingTokenRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Mints and atomically consumes the single-use recording tokens that authorise
 * one {@code BeginRecording} call (Design §12/§15, FR-AUD-1). The token is
 * bound to {@code {gatewayId, sessionId, nodeId, principal, exp}} — the same
 * binding as the session-signing token, minted together on an {@code Authorize}
 * ALLOW. On {@link #consume} the CP verifies the caller's mTLS gateway owns the
 * token and that any advisory context agrees, then burns the token under the
 * {@code @Version} optimistic lock so a replay loses the race. Every mismatch
 * fails closed with one <b>generic</b> error so a caller cannot distinguish
 * cross-gateway from cross-session from expired from replayed (§15). Reuses the
 * single-use-token machinery (hash-only storage) shared with session signing.
 */
@Service
public class RecordingTokenService {

	private final RecordingTokenRepository tokens;
	private final MtlsProperties properties;

	public RecordingTokenService(RecordingTokenRepository tokens, MtlsProperties properties) {
		this.tokens = tokens;
		this.properties = properties;
	}

	/**
	 * Mint a single-use recording token; returns the raw token (shown once). Bound
	 * to the same {gateway, session, node, principal} as the session-signing token
	 * and expiring on the same TTL (both are connect-time, §15).
	 */
	public Mono<String> mint(UUID gatewayId, UUID sessionId, UUID nodeId, String principal, String sourceAddress) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(properties.getSessionSigningTokenTtl());
		return tokens.save(
				RecordingToken.create(minted.hash(), gatewayId, sessionId, nodeId, principal, sourceAddress, expiresAt))
				.thenReturn(minted.raw());
	}

	/**
	 * Validate the token is bound to {@code callerGatewayId} (and agrees with any
	 * advisory {@code context}), then atomically mark it used. Any unknown /
	 * cross-gateway / cross-session / expired / already-used token — or a lost
	 * consume race — is rejected with one generic {@code PERMISSION_DENIED}.
	 */
	public Mono<RecordingToken> consume(String rawToken, UUID callerGatewayId, RecordingRequestContext context) {
		if (rawToken == null || rawToken.isBlank() || callerGatewayId == null) {
			return Mono.error(denied());
		}
		String hash = SingleUseTokens.hash(rawToken);
		Instant now = Instant.now();
		RecordingRequestContext ctx = (context == null) ? RecordingRequestContext.EMPTY : context;
		return tokens.findByTokenHash(hash).switchIfEmpty(Mono.error(denied())).flatMap(token -> {
			if (!callerGatewayId.equals(token.gatewayId()) || token.used() || !token.expiresAt().isAfter(now)
					|| contextDisagrees(ctx, token)) {
				return Mono.error(denied());
			}
			RecordingToken used = new RecordingToken(token.id(), token.tokenHash(), token.gatewayId(),
					token.sessionId(), token.nodeId(), token.principal(), token.sourceAddress(), token.expiresAt(),
					true, now, token.version(), token.createdAt());
			return tokens.save(used).onErrorMap(OptimisticLockingFailureException.class, race -> denied());
		});
	}

	// The context is advisory: a field is checked only when the caller set it, and
	// when set it MUST equal the token's authoritative value.
	private static boolean contextDisagrees(RecordingRequestContext ctx, RecordingToken token) {
		if (ctx.sessionId() != null && !ctx.sessionId().equals(token.sessionId())) {
			return true;
		}
		if (ctx.nodeId() != null && !ctx.nodeId().equals(token.nodeId())) {
			return true;
		}
		return ctx.principal() != null && !Objects.equals(ctx.principal(), token.principal());
	}

	private static GatewayRequestException denied() {
		return new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
				"recording request refused");
	}
}
