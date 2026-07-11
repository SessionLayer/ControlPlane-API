# OpenAPI contract

`openapi.yaml` is the **contract-first source of truth** for the SessionLayer
Control Plane REST surface (Design §13, FR-API-1). It is OpenAPI **3.1.0**.

## Contract-first, enforced

The spec is authored first; server and client code are **generated** from it,
and CI fails if the generated artifacts drift from the spec:

- **ControlPlane-API (Java):** `openapi-generator-maven-plugin` with the
  `spring` generator in reactive (`webflux`) mode produces API *interfaces* and
  *models*; controllers implement the interfaces. A drift between spec and code
  breaks the build.
- **ControlPlane-Dashboard (TypeScript):** `openapi-typescript` produces types
  and `openapi-fetch` provides a typed client. `npm run generate:api` +
  `git diff --exit-code` is the CI drift check.

## Session One scope

Only two operations are defined:

- `GET /v1/healthz` — liveness/readiness (public; returns `HealthStatus` or a
  `503` problem document).
- `GET /v1/version` — component + protocol version metadata (public; returns
  `VersionInfo`).

Error bodies are **RFC 9457** (`application/problem+json`, `ProblemDetails`).

## Security schemes (declared now, used later)

Three first-class schemes (Design §5.7, §13; FR-AUTH-17) are declared so later
operations reference them without changing the contract shape:

- `oidcBearer` — OIDC/JWT bearer (the ID token is the auth proof).
- `clientCredentials` — OAuth 2.0 client-credentials for machine consumers.
- `mtls` — mutual-TLS client certificate (`type: mutualTLS`).

HTTP Basic is intentionally **absent** — it is not a first-class scheme
(FR-AUTH-17).

### `mutualTLS` codegen note (Session Six)

`openapi-generator` 7.23 (the latest release) cannot model OpenAPI 3.1's
`type: mutualTLS` scheme: `DefaultCodegen.fromSecurity()` logs a non-fatal
`[ERROR] Unknown type mutualTLS ...` and emits no security metadata for it.
Because our generation uses `annotationLibrary=none` / `documentationProvider=none`,
security schemes are **documentation-only** and never appear in generated code —
so `mtls`-secured operations (e.g. `POST /v1/oauth2/token`, `POST /v1/auth/device`)
already generate compiling interfaces; mTLS is enforced by the Spring Security
client-cert filter, not by generated annotations. The contract keeps the correct
`type: mutualTLS`, and `.mvn/jvm.config` silences the redundant `DefaultCodegen`
logger so the build log stays clean. The FR-API-1 drift gate is **compile-based**,
so silencing that logger cannot mask a real contract/model drift — that always
surfaces as a compile failure. (See `Docs/sessions/six/RESULT.md` §2.)

## Linting

Linted by Redocly CLI via `contracts/lint.sh` (config: `contracts/redocly.yaml`).
