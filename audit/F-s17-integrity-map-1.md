# F-s17-integrity-map-1: DataIntegrityViolationException uniformly mapped to a name-conflict 409

- Severity: low
- Status: Accepted-Risk
- Area: config-api

## Summary
Each `*ConfigService.persist` maps ANY `DataIntegrityViolationException` at save to a 409 "…already exists".
A non-name integrity violation (a CHECK/NOT-NULL the service failed to pre-validate) would be mislabeled as a
name conflict rather than a 422.

## Justification (Accepted-Risk)
Latent: the pre-commit validation now covers every semantic invariant (ttl/max-ttl>0, capability/permission
subsets via typed enums, private-material guards, selector-shape via the S5 evaluator, approval-chain shape),
so at INSERT time the only realistic integrity violation left is the resource's UNIQUE(name) constraint (plus
the CA one-active-per-kind partial index, whose message already names it) — for which the 409 message is
accurate. Mapping to 409 also strictly beats leaking a 500. Precisely distinguishing constraints would require
DB-specific constraint-name matching (fragile). Accepted; the realistic path is correctly labeled.
