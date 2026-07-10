# F-supplychain-1: Maven wrapper lacks a distribution checksum; codegen plugin currency
- Severity: info
- Status: Accepted-Risk
- Area: supplychain

## Summary
Two low-risk supply-chain hygiene items:
1. `.mvn/wrapper/maven-wrapper.properties` sets `distributionUrl` over HTTPS but no
   `distributionSha256Sum` for the Maven binary.
2. `openapi-generator-maven-plugin` is pinned at 7.14.0 (7.20.x is newer).

## Impact
1. HTTPS transport protects the download; a checksum would add defense-in-depth against a compromised
   mirror. No authoritative `.sha256` sidecar is published at the Maven Central path, and a
   self-computed checksum from the same download provides no independent assurance.
2. The generator is build-time only and parses a frozen, first-party spec (never attacker input); it
   is not part of the shipped artifact and is not scanned by OWASP dependency-check. Bumping it risks
   generated-code drift.

## Remediation
Accepted. (1) Add `distributionSha256Sum` if/when an authoritative Apache release checksum is wired
into the build's trust base. (2) Bump `openapi-generator.version` opportunistically on a
contract-versioning cycle, re-verifying the generated surface.

## Evidence
- `.mvn/wrapper/maven-wrapper.properties`; `pom.xml` `openapi-generator.version`.
