package io.sessionlayer.controlplane.oidc;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.runtime.OidcLoginRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * The CP-hosted OIDC relying party (Design §5.2/§5.3, FR-AUTH-6/7/8). It runs
 * an auth-code + PKCE flow so the verification page restores the {@code state}
 * / {@code nonce} / PKCE replay protection a raw grant lacks.
 * {@code beginLogin} stores single-use login state (state hash only;
 * verifier/nonce derived) and builds the IdP authorize URL;
 * {@code handleCallback} atomically consumes the state (CSRF/replay guard),
 * exchanges the code with PKCE, validates the ID token (the authentication
 * proof) including {@code nonce}, and resolves the identity server-side.
 */
@Service
public class OidcRpService {

	private static final Duration LOGIN_TTL = Duration.ofMinutes(10);

	// Single-use consume of the login state — a replayed/forged/expired state
	// matches nothing (CSRF + replay protection). RETURNING carries the purpose +
	// device linkage the callback needs.
	private static final String CONSUME_STATE = """
			UPDATE runtime.oidc_login SET consumed_at = now()
			WHERE state_hash = :hash AND consumed_at IS NULL AND expires_at > now()
			RETURNING id, purpose, device_flow_id, source_ip""";

	private static final String FINISH = """
			UPDATE runtime.oidc_login SET status = :status, resolved_identity = :identity WHERE id = :id""";

	private final OidcMetadataService metadata;
	private final OidcProperties properties;
	private final StateDerivation derivation;
	private final OidcLoginRepository logins;
	private final OidcClient client;
	private final IdTokenValidator idTokenValidator;
	private final AuditWriter audit;
	private final DatabaseClient db;

	public OidcRpService(OidcMetadataService metadata, OidcProperties properties, StateDerivation derivation,
			OidcLoginRepository logins, OidcClient client, IdTokenValidator idTokenValidator, AuditWriter audit,
			DatabaseClient db) {
		this.metadata = metadata;
		this.properties = properties;
		this.derivation = derivation;
		this.logins = logins;
		this.client = client;
		this.idTokenValidator = idTokenValidator;
		this.audit = audit;
		this.db = db;
	}

	public record LoginResult(String identity, List<String> groups, String purpose, UUID deviceFlowId,
			String browserSourceIp, boolean success) {
	}

	/**
	 * Start a login and return the IdP authorize URL the browser is redirected to.
	 */
	public Mono<String> beginLogin(String purpose, UUID deviceFlowId, String browserSourceIp) {
		String state = Secrets.randomToken(32);
		String stateHash = Secrets.sha256Hex(state);
		return logins
				.save(io.sessionlayer.controlplane.data.runtime.OidcLogin.create(stateHash, purpose, deviceFlowId,
						browserSourceIp, Instant.now().plus(LOGIN_TTL)))
				.then(metadata.discovery()).map(discovery -> authorizeUrl(discovery, state));
	}

	private String authorizeUrl(OidcDiscovery discovery, String state) {
		return UriComponentsBuilder.fromUriString(discovery.authorizationEndpoint()).queryParam("response_type", "code")
				.queryParam("client_id", properties.getClientId())
				.queryParam("redirect_uri", properties.getRedirectUri())
				.queryParam("scope", String.join(" ", properties.getScopes())).queryParam("state", state)
				.queryParam("nonce", derivation.nonce(state)).queryParam("code_challenge", derivation.challenge(state))
				.queryParam("code_challenge_method", "S256").build().encode().toUriString();
	}

	/** Handle the IdP redirect: consume state, exchange code, validate ID token. */
	public Mono<LoginResult> handleCallback(String code, String state, String browserSourceIp) {
		if (code == null || code.isBlank() || state == null || state.isBlank()) {
			return Mono.error(new IdTokenValidator.InvalidIdToken("missing code/state"));
		}
		String stateHash = Secrets.sha256Hex(state);
		return db.sql(CONSUME_STATE).bind("hash", stateHash)
				.map((row, meta) -> new Consumed(row.get("id", UUID.class), row.get("purpose", String.class),
						row.get("device_flow_id", UUID.class)))
				.one().switchIfEmpty(Mono.error(new IdTokenValidator.InvalidIdToken("unknown/expired/replayed state")))
				.flatMap(
						consumed -> metadata.discovery()
								.flatMap(discovery -> client.exchangeCode(discovery, code, derivation.verifier(state)))
								.flatMap(idToken -> idTokenValidator.validate(idToken, derivation.nonce(state)))
								.flatMap(resolved -> finish(consumed, resolved.identity(), "completed")
										.thenReturn(new LoginResult(resolved.identity(), resolved.groups(),
												consumed.purpose(), consumed.deviceFlowId(), browserSourceIp, true))
										.flatMap(result -> audit
												.record(resolved.identity(), resolved.identity(), "oidc.login",
														"success", null, null, Map.of("purpose", consumed.purpose()))
												.thenReturn(result)))
								.onErrorResume(err -> finish(consumed, null, "failed")
										.then(audit.record("unknown", null, "oidc.login", "denied", null, null,
												Map.of("reason", err.getClass().getSimpleName())))
										.then(Mono.error(err))));
	}

	private record Consumed(UUID id, String purpose, UUID deviceFlowId) {
	}

	private Mono<Long> finish(Consumed consumed, String identity, String status) {
		return db.sql(FINISH).bind("status", status).bind("id", consumed.id())
				.bind("identity", identity == null ? "" : identity).fetch().rowsUpdated();
	}
}
