# F-eku-enforcement-1: clientAuth EKU enforcement (proto F3)
- Severity: info
- Status: Accepted-Risk
- Area: mtls

## Summary
Question raised whether the plane distinguishes client-EKU from server-EKU certs. The crypto and
red-team reviewers both CONFIRMED the PKIX trust manager already enforces the clientAuth EKU when
validating a presented client chain, so a serverAuth-only leaf cannot be replayed as a client cert —
CONFIRMED-CLOSED.

## Impact
None (already enforced by the PKIX path). Leaves carry a single EKU per LeafPurpose (SERVER/CLIENT).

## Remediation
No code change required; accepted as confirmed-closed. Leaf EKU is set per `LeafPurpose` in
`X509Certificates.issueLeaf`; the PKIX `X509TrustManager` enforces clientAuth on
`checkClientTrusted`. A future belt-and-suspenders explicit-EKU assertion is optional.

## Evidence
`X509Certificates.issueLeaf` (EKU per purpose); `AuthInterceptor` re-validates via
`trustManager.checkClientTrusted`.
