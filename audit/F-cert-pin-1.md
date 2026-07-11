# F-cert-pin-1: A superseded mTLS cert still authenticated SignSessionCertificate/Renew
- Severity: medium
- Status: Verified-Fixed
- Area: mtls

## Summary
Authentication resolved the caller only from (chain→internal CA) + (SAN URI → gateway id); it never
compared the presented leaf to the stored `gateway_identity.fingerprint`. After a renew, the prior
generation's cert stayed valid for its 24h TTL, so renewal was not a compromise-recovery primitive
(exploitable only with an already-stolen private key; locked/revoked was already refused).

## Impact
A stolen but superseded Gateway client certificate could still obtain session certificates until its
TTL expired, weakening renew as a rotation/recovery control.

## Remediation
The sign and renew tiers now pin the presented client-cert SHA-256 fingerprint to the identity's
`{fingerprint, prev_fingerprint}` (V15 adds `prev_fingerprint`; renew records the outgoing fingerprint
there), tolerating the renew-ahead overlap. A superseded cert stops authenticating after the next
renew. Full CRL/OCSP/lock-push remains S10.

## Evidence
`V15__mtls_fingerprint_pin_and_grants.sql`; `GatewayIdentity.prevFingerprint`;
`SessionCertificateService.requireAuthorizedGateway`; `GatewayRenewalService.fingerprintPins` + prev
recording; handlers pass `CertificateFingerprints.sha256Hex(peer.certificate())`.
