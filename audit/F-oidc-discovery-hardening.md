# F-oidc-discovery-hardening: OIDC discovery lacks single-flight; discovery/token/JWKS timeouts are literals; decoder cached per boot

- Severity: low
- Status: Accepted-Risk
- Area: oidc

reliability F2/F3/F4. **Justification:** discovery + token are already bounded (10s/15s) and JWKS is now bounded (F-jwks-timeout); the missing single-flight only amplifies load on an already-slow IdP (single-instance, low likelihood); a changed jwks_uri (not key rotation, which Nimbus handles) is picked up on restart. Tunable-timeout properties + single-flight are low-value hardening deferred to a scale/HA session.
