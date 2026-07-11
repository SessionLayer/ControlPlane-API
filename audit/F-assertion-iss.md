# F-assertion-iss: private_key_jwt assertion iss not validated (RFC 7523 §3)

- Severity: low
- Status: Verified-Fixed
- Area: machine

**Fixed:** authenticatePrivateKeyJwt requires iss == sub (both the client id).
