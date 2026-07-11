# F-machine-token-typ-aud: Machine access token lacked typ:at+jwt and resource-server aud/token_type checks (RFC 9068)

- Severity: low
- Status: Verified-Fixed
- Area: machine

**Fixed:** mint stamps header `typ: at+jwt`; the CP-machine decoder validates aud==machine.audience and the converter requires token_type==machine.
