# F-access-accepted-risk-1: S13 access-model accepted-risk / design notes (consolidated)
- Severity: info
- Status: Accepted-Risk
- Area: access

## Summary
Design decisions the S13 review panel confirmed as intentional, not defects. Recorded so a future
reviewer does not re-flag them.

## Break-glass FIDO2 attestation / user-verification NOT required
A break-glass `sk-ecdsa` key is registered by an admin holding `breakglass:manage`; the trust model is
"an admin vouched for this public key", not device attestation. Attestation-format pinning and UV
enforcement are future hardening. (The Gateway's mandated software-SK-provider E2E exercises the
sk-auth handshake.) FIDO2 proof-of-possession itself IS proven upstream by the Gateway's SSH sk-auth
handshake before the CP `ResolveBreakglassKey` — the CP resolves identity from the PUBLIC key only,
symmetric with ResolvePin (F1, documented in code).

## sk signature-counter not tracked
Matches OpenSSH `sshd` behavior (it does not persist/verify the FIDO2 signature counter). Cloning
detection for hardware authenticators is out of scope; revocation is by fingerprint.

## Break-glass alert delivery is best-effort (F3)
An alert delivered across a crash between the resolve commit and the sink fan-out may be lost — a
notification transport is inherently best-effort. The DURABLE compensating control is the persisted
`breakglass_activation` (review_status=pending) surfaced in the mandatory-review list, plus the
`breakglass.authenticated` audit written in the same reactive chain as the token mint. A failing sink
is logged loudly (never silently swallowed — see the earlier outcome-CHECK defect).

## JIT grants carry no source-IP restriction; Locks have no source facet (F5 / O-2)
By design: approval IS the control for JIT. Source-IP scoping of a JIT grant, and a source facet on
`LockTarget`, are possible future contract enhancements.

## Self-approval / chain level-match use exact identity strings (F6 / O-1)
Identity-namespace hygiene (e.g. canonicalizing `Alice@corp` vs `alice@corp`) is an auth-boundary
concern owned upstream (S6). Any bypass here is self-defeating (an attacker who controls two identity
strings that both resolve to themselves still cannot approve their own request without a second
distinct approver, because "approver may act at most once" is keyed on the same string set).

## "email" approval level matches the identity string
An `{kind:"email"}` chain level matches the approver's resolved identity string exactly — operators
must configure the level value to the identity as the IdP presents it. Documented for operators.

## No per-requester pending-request cap
A durable deny is a Lock, by design; there is no cap on the number of pending JIT requests a single
requester may open. Abuse is bounded by the approval requirement and the approval-window expiry.

## Alert transport default = audit/ERROR-log sink
The always-on sink is audit + a loud ERROR log. Deploy docs MUST wire a real alerting transport (the
`BreakglassSecurityAlertSink` seam) to page on `breakglass.authenticated`.
