package io.sessionlayer.controlplane.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.device.DeviceFlowService;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import io.sessionlayer.controlplane.support.StubIdp;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * OIDC relying-party round-trip (FR-AUTH-6/7/8): discovery + JWKS + auth-code +
 * PKCE state/nonce, exercised against a controllable stub IdP. Proves a valid
 * ID token is accepted and the identity/groups resolve server-side, a replayed
 * state is rejected (CSRF/replay), a bad nonce is rejected, and a device-flow
 * approval binds the resolved identity + source correlation.
 */
class OidcRpMockIT extends AbstractAuthIT {

	private static final StubIdp IDP;
	static {
		try {
			IDP = new StubIdp("sessionlayer-cp");
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	@Autowired
	OidcRpService oidcRpService;
	@Autowired
	DeviceFlowService deviceFlowService;

	@DynamicPropertySource
	static void oidc(DynamicPropertyRegistry registry) {
		registry.add("sessionlayer.oidc.enabled", () -> "true");
		registry.add("sessionlayer.oidc.issuer", IDP::issuer);
		registry.add("sessionlayer.oidc.client-id", () -> "sessionlayer-cp");
		registry.add("sessionlayer.oidc.redirect-uri", () -> "http://cp.example/v1/auth/callback");
	}

	@Test
	void authCodePkceRoundTripResolvesIdentityAndGroups() {
		String authorizeUrl = oidcRpService.beginLogin("web_login", null, "203.0.113.5").block();
		Map<String, String> params = query(authorizeUrl);
		assertThat(params).containsKeys("state", "nonce", "code_challenge");
		assertThat(params.get("code_challenge_method")).isEqualTo("S256");

		String code = "code-" + UUID.randomUUID();
		IDP.registerCode(code, "sub-1", "alice@corp.example", List.of("platform-admins"), "sessionlayer-cp",
				params.get("nonce"), Instant.now().plusSeconds(300));

		OidcRpService.LoginResult result = oidcRpService.handleCallback(code, params.get("state"), "203.0.113.5")
				.block();
		assertThat(result.identity()).isEqualTo("alice@corp.example");
		assertThat(result.groups()).containsExactly("platform-admins");
		assertThat(result.purpose()).isEqualTo("web_login");
	}

	@Test
	void replayedStateIsRejected() {
		String authorizeUrl = oidcRpService.beginLogin("web_login", null, "203.0.113.5").block();
		Map<String, String> params = query(authorizeUrl);
		String code = "code-" + UUID.randomUUID();
		IDP.registerCode(code, "sub-1", "bob@corp.example", List.of(), "sessionlayer-cp", params.get("nonce"),
				Instant.now().plusSeconds(300));
		oidcRpService.handleCallback(code, params.get("state"), "203.0.113.5").block();

		// The state is single-use; a second callback with the same state fails closed.
		IDP.registerCode("code2", "sub-1", "bob@corp.example", List.of(), "sessionlayer-cp", params.get("nonce"),
				Instant.now().plusSeconds(300));
		assertThatThrownBy(() -> oidcRpService.handleCallback("code2", params.get("state"), "203.0.113.5").block())
				.isInstanceOf(IdTokenValidator.InvalidIdToken.class);
	}

	@Test
	void mismatchedNonceIsRejected() {
		String authorizeUrl = oidcRpService.beginLogin("web_login", null, "203.0.113.5").block();
		Map<String, String> params = query(authorizeUrl);
		String code = "code-" + UUID.randomUUID();
		IDP.registerCode(code, "sub-1", "carol@corp.example", List.of(), "sessionlayer-cp", "not-the-nonce",
				Instant.now().plusSeconds(300));
		assertThatThrownBy(() -> oidcRpService.handleCallback(code, params.get("state"), "203.0.113.5").block())
				.isInstanceOf(IdTokenValidator.InvalidIdToken.class);
	}

	@Test
	void deviceFlowApprovalBindsIdentityViaTheVerificationPage() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.9", "conn-1").block();
		String authorizeUrl = oidcRpService.beginLogin("device", begun.deviceFlowId(), "198.51.100.9").block();
		Map<String, String> params = query(authorizeUrl);
		String code = "code-" + UUID.randomUUID();
		IDP.registerCode(code, "sub-9", "dave@corp.example", List.of("sre"), "sessionlayer-cp", params.get("nonce"),
				Instant.now().plusSeconds(300));

		OidcRpService.LoginResult result = oidcRpService.handleCallback(code, params.get("state"), "198.51.100.9")
				.block();
		assertThat(result.purpose()).isEqualTo("device");
		deviceFlowService.approve(result.deviceFlowId(), result.identity(), result.browserSourceIp()).block();

		DeviceFlowService.Status status = deviceFlowService.poll(begun.deviceCode()).block();
		assertThat(status.status()).isEqualTo("authorized");
		assertThat(status.identity()).isEqualTo("dave@corp.example");
		assertThat(status.sourceContextMatch()).isTrue();
	}

	private static Map<String, String> query(String url) {
		var params = UriComponentsBuilder.fromUri(URI.create(url)).build().getQueryParams();
		return params.toSingleValueMap();
	}
}
