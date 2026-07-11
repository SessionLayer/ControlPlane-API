# F-bcl-logout-token: Back-channel logout accepted any IdP-signed ID token

- Severity: medium
- Status: Verified-Fixed
- Area: oidc

/v1/auth/backchannel-logout validated only sig/iss/aud/exp, so a plain (replayable) ID token could revoke a subject's pins (OIDC BCL 1.0 §2.6 miss). Converged by redteam + security + divergence. **Fixed:** require the `events` claim to contain the backchannel-logout event, reject a present `nonce`, require `sub`/`sid`; rate-limited per source.
