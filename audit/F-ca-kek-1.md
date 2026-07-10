# F-ca-kek-1: local-CA KEK custody — dev-default fail-open, missing AAD, zeroization gaps
- Severity: high
- Status: Verified-Fixed
- Area: ca

## Summary
Red-team + security + divergence reviews (3 independent) found the local-CA envelope
encryption (FR-CA-8) was defeatable by default and under-bound:
- **F1/HIGH — dev-default KEK fail-open:** an unset `sessionlayer.ca.local.kek-base64`
  silently fell back to a **public compile-time constant** KEK; the CA private keys were
  then "protected" by a key anyone with the source can read. Only a `LOG.warn` guarded it,
  and the warning fired only on generation, never on restart/load. PoC recovered the CA
  private key from `ca_key_material` ciphertext using the source constant.
- **F2/MEDIUM — no AAD:** the GCM envelope bound nothing to the row, so a DB-write attacker
  could lift a valid wrapped blob into a different CA's row (cross-CA / kind confusion).
- **F3/LOW — zeroization:** the transient JCA private key + dev-key detection by base64
  string (not bytes).

## Remediation (Verified-Fixed)
- **Fail closed:** `KekProvider` now REFUSES to start when the dev default is in effect
  unless `sessionlayer.ca.local.allow-dev-kek=true` is explicitly set (dev/test only; not
  set in application.properties, so a prod deploy that forgets the KEK fails closed). The
  dev-default check compares **decoded bytes** (constant-time), so a re-encoding cannot
  smuggle it past. The KEK warning now fires on **load** too, and the misleading
  `env:SESSIONLAYER_CP_KEK` reference default was corrected.
- **AAD:** `Kek.wrap/unwrap` now authenticate an AAD = `caConfigId | keyType | kekReference`
  (identical on wrap and unwrap), so a wrapped blob cannot be lifted between rows — unwrap
  fails closed on any context mismatch.
- **Zeroization:** the transient JCA private key is best-effort `destroy()`ed after wrap;
  the residual (immutable BigInteger scalar, GC-only) is inherent to a local software
  signer and is why production SHOULD use KMS/KeyVault/Vault (documented in `LocalCaBackend`).
- V12 adds ciphertext-only guards: `octet_length(iv)=12` and a `-----BEGIN` PEM-marker
  rejection on `wrapped_key`.

## Dedicated gate
`KekTest` (fail-closed dev default incl. re-encoded detection; AAD cross-context unwrap
fails). `CaLifecycleIT`/`ColdStartIT` boot with the explicit opt-in. Documented in
`application.properties` + DATA-MODEL §13.
