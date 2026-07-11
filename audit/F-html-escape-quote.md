# F-html-escape-quote: OIDC page HTML escaper omitted the single-quote

- Severity: low
- Status: Verified-Fixed
- Area: rest-security

Defense-in-depth (currently only element-text/static-attr interpolation). **Fixed:** escape() also encodes ' -> &#39;.
