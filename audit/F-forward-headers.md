# F-forward-headers: Source-IP controls collapsed behind the L7 LB (no forwarded-header handling)

- Severity: medium
- Status: Verified-Fixed
- Area: reliability

getRemoteAddress() returned the LB, collapsing per-IP rate buckets + the OTP source-CIDR + device correlation. **Fixed:** server.forward-headers-strategy=framework (source IP is deny-only, so a spoof from a non-LB peer only over-restricts); verification URL now built from the configured redirect-uri origin, not the Host header.
