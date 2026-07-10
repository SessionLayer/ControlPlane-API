# F-cert-hardening-1: certificate assembler / parser hardening (empty principals, curve, DER, serial)
- Severity: high
- Status: Verified-Fixed
- Area: ca

## Summary
Protocol + divergence reviews confirmed the emitted `ecdsa-sha2-nistp256-cert-v01` blob is
wire-conformant (ssh-keygen -L + golden cross-check + sshd handshake all pass), and surfaced
these hardenings at the primitive/parse layer:
- **HIGH (F-caprofile-1):** the reusable `CertificateParameters` would build a `type=USER`
  cert with an **empty valid-principals** list — which OpenSSH treats as valid for **any**
  login. The single S3 caller is safe, but the primitive (used directly by S8 issuance) was
  a footgun (Vault defaults `allow_empty_principals=false` for this reason).
- **LOW (F-SSHPUB-CURVE-1 / redteam INFO):** `parse` discarded the SSH curve field without
  checking it matches the key type (RFC 5656 §3.1), and did not validate the point is on the
  curve (JCA does not check on import).
- **LOW (F-DER-OVFL-1):** the strict DER reader's `pos + len > end` bound check could
  int-overflow (trusted producer, but cheap to fix).
- **LOW (F-cavault-1):** the Vault path surfaced the requested serial, not the one Vault
  stamped into the returned cert (wrong audit correlation).
- **INFO:** `writeUint32` had no range assertion; `principals` was not defensively copied.

## Remediation (Verified-Fixed)
- `CertificateParameters` rejects a USER cert with no non-blank principal, and defensively
  copies `principals` (chokepoint every backend funnels through).
- `SshEcdsaPublicKeys.parse` rejects a mismatched curve label and validates the point is on
  the named curve (rejects point-at-infinity, out-of-range coords, `y²≠x³+ax+b`).
- `EcdsaSignatures` DER length checks are overflow-safe (`len > end - pos`).
- `VaultCaCertSigner` parses the serial out of Vault's returned cert blob (falls back to the
  requested serial if unparseable).
- `SshWriter.writeUint32` asserts the value is in range.

## Dedicated gate
`OpenSshCertSignerValidationTest` (ssh-keygen -L / golden / sshd handshake, principals
present), `EcdsaSignaturesTest` (strict-DER rejection), `CloudBackendNormalizationTest`.
The `valid-forever` uint64 sentinel and a per-profile TTL ceiling are S8-issuance concerns
(see F-serial-allocator-1); the inner-leg profile is fixed-scope (5-min TTL, principal set).
