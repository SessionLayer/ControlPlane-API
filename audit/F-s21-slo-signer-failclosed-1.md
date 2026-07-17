# F-s21-slo-signer-failclosed-1: CA-sign availability SLI must measure fail-closed; SLO metrics must stay low-cardinality

- Severity: medium
- Status: Verified-Fixed
- Area: observability

## Summary
Session 21 adds the NFR-3 (session-CA signing availability) and NFR-4 (session-establishment latency) SLOs.
Two risks: (1) if the availability metric only counted successes, a signer-down outage would be invisible —
and the signer path must remain fail-closed (never sign with a wrong key / skip signing); (2) tagging any SLO
meter by `session_id`/`correlation_id`/`node_id` would explode cardinality (OTEL-CONTRACT §7) and could re-leak
identifiers into a scraped metric store.

## Fix (Verified-Fixed)
- `CaSignerService.activeSigner` (the availability seam) records `sessionlayer.ca.signer{kind,outcome}` where
  `outcome` is `available` (a signer resolved), `unavailable` (`NoSignerAvailable` — the fail-closed state), or
  `error`. Client-input rejections never reach this seam, so they never count as availability failures. The
  fail-closed behaviour is unchanged (it still errors, never returns a wrong-key signer).
- `CaSignerHealthIndicator` reports UP/OUT_OF_SERVICE for `/actuator/health` alerting (a datastore-peer SLO),
  cached, and — like `WormHealthIndicator` — does NOT gate readiness by default (opt-in), so a rotation gap
  cannot deregister the whole CP and defeat incident response.
- The establishment (`sessionlayer.session.establishment{outcome,access_model}`) and cert-sign
  (`sessionlayer.cert.sign{kind,outcome}`) meters are tagged by outcome/kind ENUM ONLY — never by any id.
- Targets set (documented in RESULT §5): NFR-4 CP-side establishment p95 = 250 ms (Authorize machine path;
  human OIDC excluded — it happens on the earlier outer-leg auth RPCs, not in this timer); cert-sign p95 =
  100 ms; NFR-3 session-CA signing availability objective = 99.9% (SLI = available / (available + unavailable +
  error), client-input rejections excluded).
- Gate: `CaSignerMetricsTest` proves a no-active-CA signing fails closed with `NoSignerAvailable` AND records
  `outcome=unavailable`; `CaSignerHealthIndicatorTest` proves UP vs OUT_OF_SERVICE;
  `ObservabilityIT.sloMetricsAreEmittedForTheEstablishmentAndSigningPaths` proves all three meters emit with the
  enum-only tags.
