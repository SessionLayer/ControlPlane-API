# F-dataaccess-1: Flyway JDBC DataSource has no build-time guard against reactive-path injection
- Severity: info
- Status: Accepted-Risk
- Area: dataaccess

## Summary
`DataSourceAutoConfiguration` is excluded so the WebFlux runtime is R2DBC-only, and Flyway builds its
own dedicated JDBC/HikariCP datasource from `spring.flyway.*` for startup migrations — implemented
correctly. That Flyway datasource bean remains in the context afterwards; nothing prevents a future
developer from injecting it into a reactive handler and reintroducing blocking JDBC on the event loop.

## Impact
No such injection exists today (the scaffold has no data-access handlers). It is a forward-looking
regression risk, not a present defect or an externally reachable issue.

## Remediation
Accepted for Session One. In a later session add a build-time guard (ArchUnit or a context test)
asserting no `javax.sql.DataSource`/JDBC bean is injected into `web`/`grpc` package classes, so any
regression is caught at build time.

## Evidence
- `ControlplaneApplication.java` (`DataSourceAutoConfiguration` exclude); `pom.xml` Flyway block.
