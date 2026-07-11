# F-usercert-ecdsa-only: user-cert verification supports only an ECDSA user CA
- Severity: info
- Status: Accepted-Risk
- Area: usercert

## Summary
`UserCertificateVerifier` verifies the CA signature over a presented user certificate only when the
trusted user-CA key is ECDSA (P-256/384/521) — the only CA key types SessionLayer's local CA factory
assembles (`SshEcdsaPublicKeys`, `CaKeyType`). A trusted user-CA key of any other type (e.g. Ed25519)
is not parseable by `SshEcdsaPublicKeys.parse` and the verification fails closed (`resolved = false`).
The *certified* user key may be any type (ed25519 / rsa / ecdsa / sk-*) — the field-skip map parses all
common cert types; only the *CA* signing key is constrained.

## Impact
None for the deployed configuration: the user-facing CA provisioned at cold start is ECDSA. Were an
operator to introduce a non-ECDSA user CA, outer-leg cert authentication would deny (fail closed, not
open) until Ed25519 CA verification is added.

## Remediation
Accepted: fail-closed matches the platform ethos and the currently-assemblable CA key set. Adding
Ed25519 CA verification is an additive change (a second signature path keyed off the trusted key's
key-type name) if a non-ECDSA user CA is ever deployed.

## Evidence
- `ca/cert/UserCertificateVerifier.matchTrustedCa` (returns null for a non-ECDSA trusted key).
- `ca/CaKeyType` (ECDSA-only); `ca/key/SshEcdsaPublicKeys` (ECDSA parse).
- `ca/cert/UserCertificateVerifierTest.ed25519CertifiedKeyIsParsedAndVerified` (certified-key type is
  independent of the CA type).
