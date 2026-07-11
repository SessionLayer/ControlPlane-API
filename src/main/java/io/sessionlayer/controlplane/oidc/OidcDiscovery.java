package io.sessionlayer.controlplane.oidc;

/**
 * The subset of an IdP's {@code .well-known/openid-configuration} the CP
 * relying party needs (Design §5.3). Fetched + cached by
 * {@link OidcMetadataService}.
 */
public record OidcDiscovery(String issuer, String authorizationEndpoint, String tokenEndpoint, String jwksUri,
		String deviceAuthorizationEndpoint, String endSessionEndpoint) {
}
