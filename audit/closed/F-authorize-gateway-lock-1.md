# F-authorize-gateway-lock-1: Authorize RPC did not enforce caller-Gateway active/pinned status (incomplete Gateway revocation)
- Severity: high
- Status: Verified-Fixed
- Area: authz

## Context (S23 red-team panel A2 — CP↔GW gRPC trust boundary)

A Gateway is a first-class **lockable** principal (Design §2A / FR-BOOT-3): it is
revoked by setting `gateway_identity.status != "active"`, and there is **no
CRL/OCSP** on the internal mTLS CA, so a locked Gateway's client cert stays
cryptographically valid until it expires. Every gateway-facing handler is expected
to enforce the active-status + fingerprint-pin gate (`AuthInterceptor` only
validates chain-to-CA + temporal validity + SAN, and its doc-comment defers the
active/unlocked check to the handlers, fail closed).

The **Sign** path enforced it (`SessionCertificateService.requireAuthorizedGateway`
— active AND fingerprint ∈ {current, prev}), as did renew / host-cert / server-cert.
But `ConnectAuthorizationService.authorize` did **not**: it used the authenticated
`callerGatewayId` only to look up the gateway *name* for the audit row
(`gatewayIdentities.findById(callerGatewayId).map(g -> g.name())`), with no status
or fingerprint check.

## Impact

An attacker holding a **locked** Gateway's still-un-expired cert+key could call
`Authorize` and:
- act as a full data-plane RBAC **allow/deny oracle** (policy disclosure to a
  revoked principal);
- **consume** single-use break-glass tokens + raise a break-glass activation +
  high-priority alert (credential burn + alert fatigue);
- flip any user's approved JIT grant `APPROVED → ACTIVE` (cross-user perturbation);
- write `ssh_session` snapshot rows + mint `session_signing_token`/`recording_token`.

It could **not** obtain an inner cert (the Sign path *did* gate), so no direct node
access — capping this at HIGH, not CRITICAL. It defeats FR-BOOT-3 (“a compromised
Gateway can be locked out of the CP immediately”) and §8.4 / FR-LOCK-2 (a revocation
must be refused on every gateway-facing surface). Green tests masked it: the
locked-Gateway refusal was tested on the Sign path, never on Authorize.

## Root-cause fix

- `grpc/AuthorizationService.authorize`: compute the presented client-cert
  fingerprint from the authenticated mTLS peer
  (`CertificateFingerprints.sha256Hex(peer.certificate())`, null-safe) and pass it
  into the service — mirrors `SessionSigningService`.
- `authz/ConnectAuthorizationService.authorize`: gate on
  `requireActiveGateway(callerGatewayId, presentedFingerprint)` as the FIRST reactive
  step (before node resolution, RBAC eval, break-glass/JIT consumption, or any state
  write) — the same active + fingerprint-pin check the Sign path enforces; empty ⇒
  generic deny (`gateway_not_authorized`), audited server-side, `DECISION_DENY` to
  the caller.

## Regression test

`AuthorizeIT.aLockedCallerGatewayIsRefusedOnAuthorizeWithNoStateChange`: enroll a
gateway, seed an otherwise-allowed identity/node/principal, flip
`gateway_identity.status='locked'`, call Authorize → assert `DECISION_DENY`, empty
session token, no context, AND no `ssh_session` row written. Fails pre-fix (locked
gateway got `DECISION_ALLOW` + token + session row); passes post-fix.
