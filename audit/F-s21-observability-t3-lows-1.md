# F-s21-observability-t3-lows-1: Part C+D T3 low-severity hardening (no-content gate breadth, ca_unavailable audit, span defer, SLI dilution)

- Severity: low
- Status: Verified-Fixed
- Area: observability

## Summary + fixes (S21 Part C+D T3 review)

Four low-severity improvements on top of an implementation the reviewers rated
strong (fail-closed correct + tested, NFR-4 excludes human OIDC, reactive-safe,
no-content invariant holds, exporter truly off-by-default):

1. **No-content gate breadth** — `ObservabilityIT` scanned only span *attributes*.
   Widened to also scan span **events** (`recordException` would write
   `exception.message` as an event, not an attribute — the exact future-regression
   class), the status description, the span name, and **metric tags**; and added
   source IP + the issued cert to the secret set (alongside the session/recording
   tokens + subject key).

2. **`ca_unavailable` denied-audit on the cert-sign paths** — `NoSignerAvailable`
   is not a `GatewayRequestException`, so a signer-down previously propagated with
   NO `session.sign`/`gateway.host_cert.sign` denied row. Added a distinct
   `reason=ca_unavailable` denied-audit on both paths (fail-closed unchanged;
   forensic completeness for a CA-availability incident, FR-AUD-7).

3. **`CpTracing` span defer** — `traceAuthorize`/`traceCertSign` built the span at
   assembly time; wrapped both in `Mono.defer` so the span starts at SUBSCRIBE
   (parity with `SloMetrics.timeEstablishment`) — a re-subscribe gets a fresh span
   instead of reusing an ended one.

4. **CA-availability SLI dilution** — the `sessionlayer.ca.signer` counter was fed
   by both real signs AND the ~6/min health-probe polls, so the NFR-3 99.9% read
   optimistically under partial degradation. Added a `source` tag
   (`request` vs `probe`); the health indicator polls with `source=probe`, real
   signs with `source=request`, so the SLI is computed over the request population.

## Verification

`ObservabilityIT` (widened no-content gate over spans+events+metric-tags;
`source=request` SLI assertion) + `CaSignerMetricsTest` (asserts `source=request`
and `source=probe` are metered distinctly, both fail-closed `unavailable`).

Evidence status: `CaSignerMetricsTest` passes green locally (Surefire, no
Docker). The `ObservabilityIT` assertions run under CI — the local full verify
was stopped to free the shared build lock, so **CI is the authoritative gate**
for the IT.
