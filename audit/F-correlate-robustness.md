# F-correlate-robustness: Device correlate() used a v4 /24 for IPv6 and could throw on a malformed literal

- Severity: low
- Status: Verified-Fixed
- Area: device

**Fixed:** the /24 soft-match is IPv4-only and Cidrs.contains is wrapped (malformed → indeterminate/null).
