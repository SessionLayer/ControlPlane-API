# F-deps-1: PostgreSQL JDBC driver 42.7.11 affected by CVE-2026-54291 (channel-binding downgrade)
- Severity: high
- Status: Verified-Fixed
- Area: deps

## Summary
Spring Boot 4.1.0 manages `org.postgresql:postgresql` at 42.7.11, which is affected by
CVE-2026-54291 / GHSA-j92g-9f8w-j867 (CVSS 8.2): with `channelBinding=require`, the driver
silently downgrades SCRAM-SHA-256-PLUS to plain SCRAM-SHA-256 when the server certificate's
signature algorithm has no `tls-server-end-point` hash, losing MITM protection. Fixed in 42.7.12.

## Impact
The blocking JDBC driver exists here solely for Flyway. This scaffold configures no TLS / no
`channelBinding` on the Flyway JDBC URL, so the specific precondition is absent today — but the pin
would silently carry into Session Four's DB-TLS work and become live-exploitable, and an
NVD-current OWASP run could fail the CVSS≥7 gate on the pinned version.

## Remediation
Override the Boot-managed version to the fixed line: `<postgresql.version>42.7.13</postgresql.version>`
in `pom.xml` (drop-in patch, no API change). The R2DBC runtime driver (`r2dbc-postgresql`) is a
separate artifact and unaffected.

## Evidence
- `pom.xml` `<properties>`: `postgresql.version` overridden to 42.7.13 (fixed).
- CVE-2026-54291 fixed in 42.7.12; 42.7.13 is the current patch (verified on Maven Central).
