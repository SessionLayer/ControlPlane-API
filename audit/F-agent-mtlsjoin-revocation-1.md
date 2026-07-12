# F-agent-mtlsjoin-revocation-1: MtlsJoin does not check operator-PKI CRL/OCSP at bootstrap
- Severity: low
- Status: Accepted-Risk
- Area: agent

## Summary
`MtlsJoinVerifier` validates that the operator-provisioned certificate chains to the configured operator
CA trust anchor and is within its validity window (PKIX path validation with `setRevocationEnabled(false)`),
that its CN/SAN matches `node_name`, and that a PoP signature binds it to this CSR. It does NOT consult a
CRL or OCSP responder for the operator PKI, so an operator certificate that has been *revoked* (but not yet
expired) by the operator's own CA would still be accepted as a one-time bootstrap proof.

## Impact
Low and bounded. (1) The frozen `MtlsJoinProof` carries only the single operator leaf (DER) — there is no
field for a CRL/OCSP reference or an intermediate chain, and no configuration binds an arbitrary operator
PKI's revocation endpoint, so this cannot be fixed within the frozen contract this session. (2) The operator
certificate is a **one-time bootstrap proof**, not a standing credential: the durable Agent credential is the
CP-issued renewable mTLS identity, and revocation of THAT identity — for every join method — is via the
platform's lock + generation-counter primitive (§8.1), which is independent of the operator PKI. (3) A Lock
covering the node refuses enroll AND renew, so an incident response is not bypassable by re-presenting a
(revoked) operator cert. (4) Validity dates ARE enforced, so an expired operator cert is rejected.

## Justification (Accepted-Risk)
Operator-PKI revocation at the bootstrap edge is genuinely out of scope for this seam: the contract carries
no revocation locus and SessionLayer's revocation model is deliberately lock+generation, not operator-CRL.
The residual (a window between operator revocation and operator-cert expiry) only affects the *one* bootstrap
event and is fully contained by node-scoped locks and the independently-revocable durable identity. Operators
who need tight operator-cert revocation should issue short-lived operator certs or rotate the operator CA
trust anchor. Revisit if a future contract revision adds a revocation reference to `MtlsJoinProof`.

## Evidence
`MtlsJoinVerifier.requireChainsToOperatorCa` (PKIX, revocation disabled, validity enforced);
`AgentEnrollmentService.refuseIfLocked` (a node Lock refuses enroll for every method);
`AgentRenewalService` (lock + generation counter is the durable-identity revocation path).
