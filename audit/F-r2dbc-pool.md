# F-r2dbc-pool: No R2DBC pool bound / acquire-timeout → auth requests hang under saturation

- Severity: medium
- Status: Verified-Fixed
- Area: reliability

The REST auth paths have no per-request deadline; an unbounded pool acquire would hang. **Fixed:** spring.r2dbc.pool.max-size + max-acquire-time (fail fast) in application.properties.
