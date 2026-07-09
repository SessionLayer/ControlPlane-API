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
- `mtls` — mutual-TLS client certificate.

HTTP Basic is intentionally **absent** — it is not a first-class scheme
(FR-AUTH-17).

## Linting

Linted by Redocly CLI via `contracts/lint.sh` (config: `contracts/redocly.yaml`).
