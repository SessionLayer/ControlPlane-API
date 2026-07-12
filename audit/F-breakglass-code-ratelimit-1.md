# F-breakglass-code-ratelimit-1: offline-code resolve was not rate-limited
- Severity: medium
- Status: Verified-Fixed
- Area: breakglass

## Summary
`BreakglassResolutionService.resolveCode` validated a guessable secret (the offline code) with no
per-source rate limit, though the sibling OTP path (`OtpService.validate`) rate-limits its equivalent
`otp:verify:<ip>` bucket. A code is ≥128-bit so brute force is infeasible, but the missing limiter is a
consistency gap and removes a cheap defense-in-depth throttle.

## Fix
`resolveCode` now acquires a per-source token from `breakglass:code:<ip>` using the shared
`RateLimiter` with the same `authProperties.getOtpVerify()` limit (5/min) before the atomic consume; a
throttled request is the generic non-resolution (`reason=rate_limited`, server-side audit). The KEY
path is deliberately NOT rate-limited (see F-breakglass-attestation-1 / the accepted-risk ledger): it
is PUBLIC material, bounded by the Gateway's per-connection auth-attempt cap, and a normal sk-ecdsa
user must not be locked out.
