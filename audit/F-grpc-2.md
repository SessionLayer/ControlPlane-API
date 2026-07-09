# F-grpc-2: Version display formatted signed for uint32 fields
- Severity: info
- Status: Verified-Fixed
- Area: grpc

## Summary
`ProtocolVersions.display()` concatenated `getMajor()`/`getMinor()` as signed `int`, while the
negotiation logic correctly uses `Integer.compareUnsigned`. A hostile `ClientHello` with a
version component ≥ 2^31 (valid proto `uint32`) still fails closed, but rendered as e.g. `-1.0` in the
`FAILED_PRECONDITION` description and the warn log.

## Impact
Cosmetic only — no security decision is affected; the value returned to the client is its own input.

## Remediation
Use `Integer.toUnsignedString(...)` for both components in `display()`.

## Evidence
- `src/main/java/io/sessionlayer/controlplane/protocol/ProtocolVersions.java`: `display()` now uses
  `Integer.toUnsignedString`.
