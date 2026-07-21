# SessionLayer Control Plane

The **SessionLayer Control Plane** is the control/management plane of
[SessionLayer](https://github.com/SessionLayer), a self-hosted, API-first
Zero-Trust SSH access platform used from stock OpenSSH clients. It decides;
the [Gateway](https://github.com/SessionLayer/Gateway) enforces. It never sees
SSH session plaintext (Design §1/D30 — that is the Gateway's burden alone).

What lives here:

- **Authentication** — OIDC relying party (auth-code + PKCE verification page,
  device flow), OTP, key pinning, machine identities (OAuth client-credentials),
  the self-disabling first-admin bootstrap.
- **Authorization** — data-plane RBAC (default-deny, deny-overrides,
  order-independent; Locks as the un-overridable top tier) and a separate
  platform RBAC for admin actions; JIT approval chains and break-glass;
  per-session signed decision contexts; session limits on the `session_lease`
  seam.
- **Certificates** — the three SSH CAs (user / session / host) plus the internal
  mTLS CA, with local / AWS KMS / Azure Key Vault / Vault `/ssh/sign` backends;
  ephemeral inner-leg certificate signing (the Gateway generates the key, the CP
  only ever sees the public half).
- **Fleet identity** — Gateway and Agent enrollment, renewable mTLS identities
  with clone-detecting generation counters, join tokens, the lock feed, node
  inventory and presence.
- **Audit & recordings** — the single correlated `audit_event` stream, retention
  and legal hold, WORM recording references and signed replay/export URLs
  (recording bytes never pass through the CP).

## Stack

Spring Boot 4.1 / Java 25, fully reactive (WebFlux + R2DBC on Postgres; Flyway
migrates over JDBC at startup). The REST surface is **generated from the frozen
OpenAPI contract** in [`contracts/`](contracts/) — the compile failure on a
contract change is the drift gate. The CP↔Gateway/Agent plane is gRPC over
mTLS, generated from [`contracts/proto/`](contracts/proto/).

## Build & test

```bash
./mvnw -B -ntp verify     # codegen + compile + format/style checks + tests + ITs (needs Docker)
./scripts/gate.sh         # the full quality gate (adds contract lint + audit check)
java -jar target/controlplane-*.jar
```

## Documentation

Operator and user documentation for the whole platform lives in the
[Documentation repository](https://github.com/SessionLayer/Documentation) —
installation, admin guides, the API reference, security model, and runbooks.
Component internals: [`docs/DATA-MODEL.md`](docs/DATA-MODEL.md),
[`contracts/VERSIONING.md`](contracts/VERSIONING.md), and the design/requirements
specs in the platform's `Docs/` tree.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
