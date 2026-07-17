# F-inner-cert-source-address-1: inner-leg session cert pins source-address to an IP the node cannot observe

- Severity: high
- Status: Verified-Fixed
- Area: ca

## Summary

The CP minted the INNER-leg (node-facing) session cert with a `source-address`
critical option = the OUTER SSH client's IP (`AuthorizeRequest.source_ip` →
`SessionSigningToken.sourceAddress()` → `CertificateProfiles.innerLegSessionCert`).
The Gateway presents that cert to the node over its OWN egress connection, so the
node's `sshd` validates `source-address` against the **Gateway's** peer IP, not
the client's. They match ONLY in an all-loopback single-host topology; on any
bridge port-map / NAT / multi-host production deployment the node sees e.g.
`172.17.0.1` and REJECTS the valid, CA-trusted cert ("not from a permitted source
address"), degrading the session to "node offline". Masked until the full-stack
harness because `MockCp` omits `source-address`, so the real CP's value never hit
a real node.

Design §3.3 line 98 literally lists `source-address` "pinned" on the ephemeral
inner cert, so this is a deliberate, documented deviation: §3.3's pin is broken as
written (the node cannot observe the client IP), and §5.6 already defines the real
source-IP enforcement stages (TCP-accept CIDR gate; per-credential OTP/pin/cert on
the OUTER leg; RBAC-time condition) — none of which depend on the inner cert.

## Fix

`SessionCertificateService.mint` passes `null` for the inner cert's source-address
(the node-facing cert carries no `source-address` critical option). Source-IP
enforcement stays on the outer leg + the Authorize decision (FR-AUTHZ-1, §5.6),
which see the real client IP. The inner cert remains session-bound, short-TTL,
single-use, host-verified, and its keypair never leaves the Gateway (D2), so it
cannot be replayed from elsewhere. `CertificateProfiles.innerLegSessionCert`
keeps the (now-null-in-production) `sourceAddress` param only so the signer's
critical-option encoding tests still exercise that path.

## Verification

`SessionSigningIT.mintedInnerCertOmitsSourceAddress` mints a cert through the real
signing RPC from a token that DOES carry a source-address and asserts the issued
inner cert has ZERO critical options. The Gateway teammate re-runs the full-stack
harness on a BRIDGE topology (distinct node IP) to prove the node now accepts the
cert (cross-repo Verified-Fixed). Recommend Design §3.3 be amended to state the
inner cert omits source-address.
