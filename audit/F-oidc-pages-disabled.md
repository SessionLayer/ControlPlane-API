# F-oidc-pages-disabled: OIDC browser pages 500'd when the RP was not configured

- Severity: low
- Status: Verified-Fixed
- Area: oidc

**Fixed:** /v1/auth/verify and /callback return a clean disabled response when sessionlayer.oidc.enabled=false.
