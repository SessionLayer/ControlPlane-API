# F-dos-1: No explicit slow-client timeouts on the public WebFlux listener (:8080)
- Severity: low
- Status: Verified-Fixed
- Area: dos

## Summary
The Reactor Netty listener on `:8080` had no explicit `connection-timeout` / `idle-timeout`, so a
slow/partial-request client could hold a connection open under permissive library defaults
(slowloris-style resource use as the surface grows).

## Impact
Small today (two trivial side-effect-free GET handlers), but a resource-exhaustion vector if the
service is ever reachable without a fronting proxy enforcing slow-client timeouts.

## Remediation
Added `server.netty.connection-timeout=10s` and `server.netty.idle-timeout=60s`. In production the CP
also sits behind an internal L7 LB (Design §14) that enforces slow-client timeouts and TLS
termination.

## Evidence
- `src/main/resources/application.properties`: connection/idle timeouts set under the REST server block.
