# F-jwks-timeout: Unbounded JWKS fetch inside the ID-token decoder

- Severity: medium
- Status: Verified-Fixed
- Area: oidc

NimbusReactiveJwtDecoder's lazy JWKS fetch had no response timeout, so a hung jwks_uri left decode() pending on three live paths. **Fixed:** IdpJwtDecoder.decode() wrapped in a 15s .timeout() failing closed as an invalid token.
