# F-idtoken-azp-exp: ID-token aud accepted extra audiences; azp/required-exp/iat unchecked

- Severity: low
- Status: Verified-Fixed
- Area: oidc

OIDC Core §3.1.3.7 items 3-5 + §2. **Fixed:** audience() rejects a multi-aud token without azp==client_id; requireExpiry() rejects a missing exp; JwtTimestampValidator keeps skew.
