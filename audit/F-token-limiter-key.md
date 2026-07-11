# F-token-limiter-key: Token-endpoint rate limiter keyed on attacker-controlled client_id

- Severity: medium
- Status: Verified-Fixed
- Area: machine

The bucket was `token:<client_id>`, so randomizing client_id gave a fresh unthrottled bucket → CPU-exhaustion via unbounded signature verifications. **Fixed:** key on the non-forgeable source IP (`token:<source-ip>`).
