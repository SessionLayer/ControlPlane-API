# CLAUDE.md — ControlPlane-API

Standing guidance for the **SessionLayer Control Plane** (Java). Read this before
changing anything here. Source-of-truth specs live in `../Docs/01-Design.md` and
`../Docs/02-Requirements.md`; when this file and the specs disagree, the specs win.

## What this component is

The Control Plane is the API-first control/management plane (Design §1, §13). It
is a **Spring Boot 4.1 / Java 25, fully-reactive (WebFlux)** service. The public
surface is generated from frozen contracts, never hand-written.

## Scope discipline (read first)

- **Scope is per-session.** Do NOT implement future `FR-*` behaviours ahead of
  their session. Session One is scaffolding only: the build/codegen harness, the
  operational probes `GET /v1/healthz` + `GET /v1/version`, the gRPC `Handshake`
  server, quality tooling, tests, CI, the audit gate. No auth/CA/RBAC/OIDC/SSH/
  recorder logic yet. If you find yourself writing an `FR-*` behaviour, stop.

## Contracts are frozen upstream — generate, never hand-write

- The canonical cross-repo contracts live in `contracts/` (OpenAPI + protobuf +
  the agent↔gateway wire spec). **They are FROZEN.** Do not edit anything under
  `contracts/` here; changes go through the versioning procedure in
  `contracts/VERSIONING.md` and re-notify every consumer.
- REST interfaces/models are generated from `contracts/openapi/openapi.yaml` by
  `openapi-generator-maven-plugin` (spring generator, `reactive`, `interfaceOnly`).
  gRPC stubs are generated from `contracts/proto` by the ascopes
  `protobuf-maven-plugin` (protoc + grpc-java, both Boot-managed). **Generation
  runs on every build** into `target/generated-sources` and is **never committed**.
- **Never hand-edit generated code.** Controllers implement the generated API
  interfaces; the gRPC service extends the generated `*ImplBase`. This ties the
  hand-written code to the contract, so an incompatible spec change fails the
  compile — that compile failure IS the drift gate (FR-API-1).

## Data access: R2DBC-runtime / JDBC-Flyway split (intentional)

This is deliberate, not a mistake:

- **Runtime = R2DBC only.** All request-path data access is fully non-blocking
  via `spring-boot-starter-data-r2dbc` + `r2dbc-postgresql`. There must be **no
  blocking JDBC on the WebFlux request path.**
- **Flyway = JDBC only, startup-only.** Flyway has no R2DBC support, so it runs
  migrations at startup against a **dedicated JDBC datasource** built from
  `spring.flyway.*` (HikariCP pool + the `org.postgresql:postgresql` JDBC driver,
  which exists **solely** for Flyway).
- To keep a blocking primary `DataSource` off the runtime, `ControlplaneApplication`
  **excludes `DataSourceAutoConfiguration`**. Flyway autoconfig (`spring-boot-flyway`,
  Boot 4.x modular autoconfig) still builds its own datasource from `spring.flyway.url`.
- Do **NOT** add `spring-boot-starter-jdbc` or `spring-boot-starter-data-jpa`, and
  do not point runtime repositories at a JDBC datasource.

## Non-blocking rules

- WebFlux request path: no blocking calls (no blocking JDBC, no `.block()`, no
  blocking I/O on event-loop threads). Return `Mono`/`Flux`.
- gRPC: the `Handshake` service handler is a pure function (no I/O), so it is
  non-blocking by construction. Keep it that way; if a future RPC needs I/O, do it
  reactively / off the event loop — no blocking stubs on the hot path.

## Ports & conventions

- REST: `:8080` (`/v1/healthz`, `/v1/version`, `/actuator/health`).
- gRPC `Handshake`: `:9090` — **PLAINTEXT, dev-only this session, insecure by
  design; replaced by mTLS in Session Four.** Config: `spring.grpc.server.*`.
- Protocol version baseline: `1.0` (`ProtocolVersion{major:1,minor:0}`), single
  source of truth in `protocol/ProtocolVersions`, consumed by both the gRPC server
  and `/v1/version`. Component name: `"SessionLayer Control Plane"`. Build version
  `0.1.0`, filtered from the Maven project version into `application.version`.
- DB (dev): compose Postgres on `localhost:5432`, db/user/pass `sessionlayer`.
  Overridden by `SPRING_R2DBC_*` / `SPRING_FLYWAY_*` env in every real deploy.

## Build, test, gate

- `./mvnw -B -ntp verify` — codegen + compile + `spotless:check` + `checkstyle:check`
  + unit tests + the Testcontainers IT (`*IT`, needs Docker). Dependency CVE
  management is Dependabot's — no NVD/OWASP scanner in the build (owner rule, S22).
- `./mvnw spotless:apply` — auto-format before committing.
- `./scripts/gate.sh` — the full ROUND_FINAL gate: `mvnw verify` + `contracts/lint.sh`
  + zero-open-medium+ audit findings. Also `make cp-gate` from the parent.
- Unit tests (`*Test`) run in Surefire (no Docker); the integration smoke (`*IT`)
  runs in Failsafe during `verify` (needs Docker for Testcontainers Postgres).

## Comment discipline (Session Five onward)

Comment **sparingly — WHY, not WHAT.** No section-divider banners, no comments that
restate the code or a name, no obvious param docs. Prefer self-documenting names and
small functions. Keep terse doc-comments only on genuinely public API/contract
surfaces; a brief comment is fine for a security/spec-tied invariant (e.g. "fail
closed", "deny wins", a WHY tied to an FR/Design §). This is a **leaner baseline than
S1–S4** — match it; do not restore the denser earlier style.

## Formatting & static analysis

- **Spotless** owns formatting; **Checkstyle** owns hygiene only (imports, braces,
  naming, bug patterns) — the two are non-overlapping (checkstyle has no
  LineLength/indentation rules; the formatter owns those). Config in
  `config/checkstyle/checkstyle.xml`.
- Spotless uses the **Eclipse JDT formatter** (Spring's tab-indented house style),
  *not* palantir-java-format / google-java-format. Reason: both of those reach into
  `com.sun.tools.javac` internals that changed in JDK 25 (`NoSuchMethodError` on
  `Log$DeferredDiagnosticHandler.getDiagnostics()`), and no released version supports
  JDK 25 yet. Swap back to a google-style formatter once one supports JDK 25.
- Only `src/**/java` is formatted/linted; generated code under `target/` is excluded.

## Security posture (scaffold)

- **Dependency CVEs are Dependabot's job — there is NO NVD/OWASP scanner in the
  build** (the OWASP `dependency-check` plugin was retired in #2; the owner rule,
  S22, forbids re-adding any NVD/OWASP scanner). Dependabot (`.github/dependabot.yml`)
  raises upgrade PRs; adopt green ones. Do not re-introduce a CVSS build gate.
- **License:** the project is GPL-3.0-only; the dependency tree is Apache-2.0 /
  BSD / MIT except `jakarta.annotation-api` (EPL-2.0 OR GPL-2.0-with-Classpath-
  Exception). The GPL-2.0+Classpath-Exception alternative is the operative license
  and is GPL-3.0-compatible (it explicitly permits combination under other terms).
- `spring-boot-starter-security`, `spring-cloud-starter-vault-config`, and
  `spring-boot-starter-webclient` were **removed** this session: they are unused by
  the scaffold, add CVE/attack surface, and Spring Security on the classpath would
  401 the public meta probes. Re-add them in the session that needs them (auth =
  Session 4+, Vault CA backend later).

## Audit / ROUND gate

- `audit/STATE` holds `ROUND_DISCOVERY` (scaffolding / red-team) or `ROUND_FINAL`
  (clean, gate green). Do not go idle in `ROUND_FINAL` with a failing gate.
- Findings are `audit/F-<area>-<n>.md` with the exact front-matter a grep depends on
  (`# F-<area>-<n>: <title>`, `- Severity:`, `- Status:`, `- Area:`). Closed findings
  move to `audit/closed/`. The gate fails on any OPEN `critical|high|medium` finding.

## CI

- `.github/workflows/ci.yml` — one job id **`gate`** (the branch-protection required
  check; do not rename / add a matrix). All actions SHA-pinned; least-privilege
  `permissions: { contents: read }`.
