# F-s21-slo-p95-histogram-1: session-establishment / cert-sign p95 SLOs were not queryable (no histogram buckets)

- Severity: medium
- Status: Verified-Fixed
- Area: observability

## Summary

`SloMetrics` registered the `sessionlayer.session.establishment` and
`sessionlayer.cert.sign` Timers with NO distribution config, so
`/actuator/prometheus` exported only the `_count`/`_sum`/`_max` series — there
were **no `_bucket` series**, and `histogram_quantile()` cannot compute a p95
without them. This defeated the primary Part D deliverable (Design §14 / SESSION
gate: session-establishment **p95** emitted, NFR-4). The IT only asserted
`count > 0`, so nothing caught the gap.

## Fix

Enabled Prometheus histogram buckets via `management.metrics.distribution.*` in
`application.properties` for both timers: `percentiles-histogram=true` +
`slo=<target>` (250ms establishment / 100ms cert-sign — the SLO buckets) +
min/max-expected-value bracketing. **Histogram buckets, NOT client-side
`percentiles`** — pre-computed per-instance quantiles are not aggregatable, so a
fleet p95 from them would be statistically wrong; `histogram_quantile()` over the
merged `_bucket` series is correct. The SLO targets (250ms / 100ms / 99.9%
CA-availability) are documented there and next to the meters.

## Verification

`ObservabilityIT.sloMetricsAreEmittedForTheEstablishmentAndSigningPaths` now
asserts `timer.takeSnapshot().histogramCounts()` is non-empty for both timers
(the `_bucket` series that `histogram_quantile()` needs).

Evidence status: the config change (`application.properties`) and the new
assertion are the static proof `review-cp-rel` can confirm. The full local
`mvnw verify` was intentionally stopped to free the shared 2-core build lock for
Gateway's build, so **CI is the authoritative gate** for this IT — flip to
ROUND_FINAL is gated on CI green, not a local run.
