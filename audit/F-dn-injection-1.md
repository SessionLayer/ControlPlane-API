# F-dn-injection-1: DN/SAN injection via string-concatenated X500Name
- Severity: low
- Status: Verified-Fixed
- Area: mtls

## Summary
`X509Certificates` built the subject as `new X500Name("CN=" + name)` with no charset/length
validation, allowing RDN injection (e.g. `gw1,O=Evil`) or a crafted dNSName SAN via the gateway name.

## Impact
A crafted gateway name could inject extra RDNs / SAN content into an issued certificate's subject.

## Remediation
Subjects are now built with `X500NameBuilder(BCStyle.CN, value)` (which RDN-escapes), and the gateway
name is allowlist-validated at enroll (`GatewayNames`: `[A-Za-z0-9._-]{1,64}`). The same builder path
covers the CP server-cert hostnames.

## Evidence
`X509Certificates.cn()`; `GatewayNames.isValid`; `GatewayEnrollmentService.enroll` name check.
