# F-secrets-1: Dev-only localhost DB credentials present in application.properties
- Severity: info
- Status: Accepted-Risk
- Area: secrets

## Summary
`application.properties` carries `spring.r2dbc.*` / `spring.flyway.*` defaults with
`username`/`password` = `sessionlayer` pointing at `localhost:5432`.

## Impact
Not a secret: identical values are published in the sibling `docker-compose.yml` dev stack, they only
work against localhost, and every real deployment overrides them via `SPRING_R2DBC_*` /
`SPRING_FLYWAY_*` environment variables (as the cross-repo e2e and Testcontainers IT both do).

## Remediation
Accepted for the dev scaffold. No real secret is committed. Production supplies credentials via env
(or a secret manager) — never via the packaged properties.

## Evidence
- `src/main/resources/application.properties` DB blocks (documented as dev-only, env-overridden).
- `../docker-compose.yml` Postgres service uses the same dev placeholders.
