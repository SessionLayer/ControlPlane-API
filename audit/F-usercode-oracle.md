# F-usercode-oracle: Device user-code verification page was an unthrottled enumeration oracle

- Severity: medium
- Status: Verified-Fixed
- Area: device

RFC 8628 §5.2/§6.1 require the user-code endpoint to be throttled; /v1/auth/verify returned 302 (valid) vs 400 (invalid) with no rate limit. **Fixed:** per-source rate limit on /v1/auth/verify (combined with the mTLS-gated begin, which removes the attacker's ability to seed codes).
