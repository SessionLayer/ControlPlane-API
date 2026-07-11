# F-platform-determinism-1: Platform matched-role attribution depended on query order
- Severity: low
- Status: Verified-Fixed
- Area: platform

## Summary
The matched role logged for a platform decision depended on `findAll()` encounter order (non-reproducible audit
attribution).

## Fix
Bindings are iterated in id order (deterministic representative), mirroring the data-plane engine.
