# F-recording-access-oracle-1: Replay/export leaked recording existence + prune-state to a zero-permission caller, unaudited

- Severity: low
- Status: Verified-Fixed
- Area: security

`RecordingAccessService.issue` did `loadRef` (404 absent) + the pruned-check (409) BEFORE `authorize()`, and `authorize()` was the only thing that audited. So any authenticated principal holding ZERO recording permissions could probe 404 (absent) vs 409 (pruned) vs 403 (exists, forbidden) entirely unaudited — the opposite of the deliberate audit-first / collapse-to-404 idiom on `GET /v1/audit-events/{id}`.

**Fix (Verified-Fixed, ddff505):** a coarse `resolveScopeGrant(subject, recording:replay|export).granted()` check runs BEFORE `loadRef`; a caller with no such grant gets a bodiless 403 with the denied probe audited (no existence/prune-state oracle). The pruned-409 moved AFTER authorize. Among actual permission-holders the 404/409/403 distinction is retained (contract-documented, UUIDv7 ids not enumerable) — see F-replay-export-parity-1 for the residual.
