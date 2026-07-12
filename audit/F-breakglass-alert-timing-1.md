# F-breakglass-alert-timing-1: break-glass alert fired at Authorize, not at authentication
- Severity: medium
- Status: Verified-Fixed
- Area: breakglass

## Summary
The high-priority break-glass alert was fired at `Authorize` (activation-creation time). A break-glass
`ResolveBreakglass*` that authenticated a credential but was NOT followed by an `Authorize` (a
resolve-without-session, or a downstream deny) spent the credential — a single-use offline code is
burned at resolve — with only a quiet `breakglass.resolve` audit and NO high-priority alert.

## Impact
An attacker (or a fumbled operator flow) could consume/probe break-glass credentials while suppressing
the loud alert by simply not proceeding to Authorize. The security signal (a break-glass credential was
used) was tied to session creation rather than to authentication.

## Fix
The alert now fires at AUTHENTICATION, in `BreakglassResolutionService.mint` (both key and code paths),
via the new `BreakglassSecurityAlerts.authenticated(...)` seam and a `breakglass.authenticated` audit —
BEFORE the token is returned. So every break-glass credential use alerts even if no session follows,
and a locked/denied downstream target still alerted (now earlier). The activation record is still
created at Authorize as the durable, mandatory-review compensating control, and does NOT re-alert (no
double-alert). Regression: `BreakglassAuthorizeIT` asserts the `breakglass.authenticated` alert exists
after resolve.

## Runbook note
A break-glass offline code is single-use and burned at AUTHENTICATION; a failed/denied downstream
session requires a fresh credential — provision offline codes in batches.
