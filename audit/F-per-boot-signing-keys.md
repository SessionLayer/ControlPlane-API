# F-per-boot-signing-keys: Per-boot signing keys (machine-token, state-derivation) are not shared across HA instances

- Severity: medium
- Status: Accepted-Risk
- Area: reliability

The machine-token RSA key and the state/PKCE-derivation HMAC key are per-boot in-memory (matching the S5 decision-context-signer precedent). In multi-instance HA a token minted by A fails on B, and a login begun on A cannot complete on B. **Justification:** single-instance is the default (FR-HA-1); HA is opt-in (largely S13). **Mitigations shipped:** StateDerivation now accepts a shared `sessionlayer.oidc.state-hmac-key` for HA; the DB-backed RateLimiter/ConsumedAssertion are already HA-safe. **Follow-up (S13/deploy):** a shared/persisted machine-token key + a CP JWKS endpoint so peers validate each other's tokens.
