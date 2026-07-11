# F-r2dbc-pool-1: No explicit R2DBC pool sizing
- Severity: low
- Status: Accepted-Risk
- Area: reliability

## Summary
`spring.r2dbc.pool.*` is unset; under a connect storm the default pool could throttle (fail-closed via the RPC deadline).

## Justification
Deployment/ops tuning, not application logic; the sequential grants-then-locks read (F-authz-torn-read-1) reduced the
per-decision connection fan-out. Operator follow-up: set pool max-size + max-acquire-time before production traffic.
