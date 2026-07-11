# F-rest-mtls-revocation: REST mTLS identity accepts a revoked-but-unexpired internal client cert

- Severity: low
- Status: Accepted-Risk
- Area: rest-security

The REST mTLS converter re-validates the chain + expiry against the internal CA but has no CRL/OCSP. **Justification:** CRL/OCSP + lock-push revocation is S10 (the S4 fingerprint-pin machinery); the internal CA issues short-TTL renewable leaves; an mTLS principal gets empty groups, so it authorizes only where an explicit role_binding names that identity. The token-endpoint mTLS path already honors per-credential fingerprint status.
