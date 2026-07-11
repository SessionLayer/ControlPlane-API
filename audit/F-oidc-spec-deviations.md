# F-oidc-spec-deviations: Documented, deliberate OIDC/OAuth deviations (at_hash, PKCE-derived, source-correlation default, assertion aud)

- Severity: info
- Status: Accepted-Risk
- Area: oidc

divergence V1-V5: (V1) at_hash not validated — code flow discards the access token, not required (OIDC Core §3.1.3.6); (V2) PKCE verifier/nonce derived from state via HMAC and never persisted — inside RFC 7636 §4.1 length, arguably safer than storing; (V3) device source-context correlation defaults to flag-only (deny-only reducer, FR-AUTH-15; legit users approve from a different network) — a conscious default-off risk acceptance; (V4) client-assertion aud = issuer identifier — permitted by RFC 7523 §3 (uniquely identifies this AS); (V5) RFC 8628 slow_down vocabulary not surfaced to the trusted-Gateway poll. All documented in RESULT §8.
