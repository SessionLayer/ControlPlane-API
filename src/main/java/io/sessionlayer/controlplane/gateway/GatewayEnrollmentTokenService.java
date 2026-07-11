package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.data.runtime.GatewayEnrollmentToken;
import io.sessionlayer.controlplane.data.runtime.GatewayEnrollmentTokenRepository;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.time.Instant;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Mints and atomically consumes single-use Gateway enrollment tokens (Design
 * §4.B, FR-JOIN-3) — the bootstrap credential presented to {@code EnrollGateway}.
 * {@link #mint} is the CP-internal/admin mechanism (surfaced like the first-admin
 * bootstrap, not a secured REST endpoint this session); {@link #consume} verifies
 * scope + expiry and burns the token under the {@code @Version} optimistic lock,
 * so a concurrent replay loses the race and is rejected. All rejections are
 * generic (fail closed, NFR-2).
 */
@Service
public class GatewayEnrollmentTokenService {

	private final GatewayEnrollmentTokenRepository tokens;
	private final MtlsProperties properties;

	public GatewayEnrollmentTokenService(GatewayEnrollmentTokenRepository tokens, MtlsProperties properties) {
		this.tokens = tokens;
		this.properties = properties;
	}

	/**
	 * Mint a single-use enrollment token scoped to {@code gatewayName}. Returns the
	 * raw token (shown once, never stored); only its hash is persisted.
	 */
	public Mono<String> mint(String gatewayName, String createdBy) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(properties.getEnrollmentTokenTtl());
		return tokens.save(GatewayEnrollmentToken.create(minted.hash(), gatewayName, expiresAt, createdBy))
				.thenReturn(minted.raw());
	}

	/**
	 * Verify + atomically consume the enrollment token for {@code gatewayName}. Any
	 * unknown / wrong-scope / expired / already-consumed token — or a lost consume
	 * race — is rejected with a generic {@code UNAUTHENTICATED}.
	 */
	public Mono<GatewayEnrollmentToken> consume(String rawToken, String gatewayName) {
		if (rawToken == null || rawToken.isBlank()) {
			return Mono.error(invalid());
		}
		String hash = SingleUseTokens.hash(rawToken);
		Instant now = Instant.now();
		return tokens.findByTokenHash(hash).switchIfEmpty(Mono.error(invalid())).flatMap(token -> {
			if (!token.gatewayName().equals(gatewayName) || token.consumedAt() != null
					|| !token.expiresAt().isAfter(now)) {
				return Mono.error(invalid());
			}
			GatewayEnrollmentToken consumed = new GatewayEnrollmentToken(token.id(), token.tokenHash(),
					token.gatewayName(), token.singleUse(), token.expiresAt(), now, token.createdBy(), token.version(),
					token.createdAt());
			return tokens.save(consumed).onErrorMap(OptimisticLockingFailureException.class, race -> invalid());
		});
	}

	private static GatewayRequestException invalid() {
		return new GatewayRequestException(GatewayRequestException.Reason.UNAUTHENTICATED, "enrollment token invalid");
	}
}
