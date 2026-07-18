# F-lockfeed-caller-gate-1: LockFeed.streamLocks not gated on caller active-status/fingerprint (de-authorized Gateway reads the fleet deny-list)
- Severity: low
- Status: Verified-Fixed
- Area: authz

## Context (S23 red-team panel A3 — a distinct variant of the F-authorize-gateway-lock-1 class)

After the Authorize caller-gate fix (F-authorize-gateway-lock-1), A3 swept every
gateway-facing RPC and found **LockFeed.streamLocks was the one still un-gated**:
`LockFeedService.streamLocks` used `peer.gatewayId()` only for a debug log and
required merely an *authenticated* peer (any Gateway OR agent). A locked / revoked /
superseded-cert Gateway whose cert still chained to the internal CA (not yet expired)
kept receiving the full fleet `LockSnapshot` + live deltas — i.e. the complete set of
identities / node_ids / principals currently being denied. Read-only (no minting), so
LOW, but it is the same **de-authorized-cert-oracle** class as the headline HIGH, and
the deny-list is sensitive recon. (A3 confirmed SignSessionCertificate, RenewGatewayIdentity,
server/host-cert, and Presence already enforce `active` + fingerprint.)

## Root-cause fix

`streamLocks` now gates on `requireActiveGateway(callerGatewayId, presentedFingerprint)`
— the same `active` + current/prev-fingerprint pin the sign paths enforce — before the
snapshot/stream is built; empty ⇒ a generic `PERMISSION_DENIED` (fail closed, non-leaking).
Agent peers (`gatewayId == null`) are refused (the lock feed is a Gateway-only surface).

## Regression test

`LockFeedIT.aLockedCallerGatewayIsRefusedTheLockFeedWithNoSnapshot`: enroll a gateway,
flip `gateway_identity.status='locked'`, open StreamLocks with its still-valid cert →
`onError` is `PERMISSION_DENIED` and no `LockSnapshot` was ever delivered (the deny-list
never leaked). Fails pre-fix (the locked gateway got the snapshot).
