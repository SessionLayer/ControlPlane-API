# SessionLayer observability — RED / saturation dashboards + alerts (Session 23, Part B)

Closes the S21 "observability missing half": S21 shipped OTel traces + the SLO
histograms but no dashboards/alerts. This bundle wires the **3am-page** artifacts on
the telemetry S21 already produces, plus a span-derived RED layer for the Tier-0 data
plane (which by design emits traces, not Prometheus metrics).

## What emits what

| Source | Signal | Where |
|---|---|---|
| **CP** (Micrometer→Prometheus) | SLO histograms + CA-signer counter | `SloMetrics.java` → `/actuator/prometheus` |
| **CP** (Spring Boot actuator) | r2dbc pool, JVM, process fds | auto |
| **Gateway / Agent** | OTel **spans** (no Prometheus metrics — Tier-0, no new listener) | OTLP → the collector |
| **OTel Collector** | **span-metrics** (RED derived from GW/Agent spans) | `../../../Gateway/deploy/observability/otel-collector-spanmetrics.yaml` → `:9464/metrics` |

## Alert rules (the pages)

- **CP SLOs / fail-closed** — `prometheus-slo-rules.yaml` (this dir): NFR-4 establishment
  p95 > 250ms; cert-sign p95 > 100ms; NFR-3 CA-signer availability < 99.9%; CA-signer
  fail-closed spike; Authorize error-rate; no-traffic.
- **Gateway data-path RED** — `../../../Gateway/deploy/observability/prometheus-gateway-red-rules.yaml`:
  session rate/error-ratio; host-verify-failure spike (no-TOFU aborts / possible MITM);
  node.connect p95; agent dial-back errors.

## Dashboard panels (PromQL — import `grafana-slo-dashboard.json`)

**RED — session establishment (NFR-4)**
- Rate `sum(rate(sessionlayer_session_establishment_seconds_count[5m]))`
- Errors `sum(rate(sessionlayer_session_establishment_seconds_count{outcome=~"error|cancelled"}[5m]))`
  (deny is a SEPARATE security panel, not an error)
- p95 `histogram_quantile(0.95, sum by (le)(rate(sessionlayer_session_establishment_seconds_bucket[5m])))` → 0.25s SLO

**CA-signer (NFR-3)**
- Availability `sum(rate(sessionlayer_ca_signer_total{source="request",outcome="available"}[30m])) / sum(rate(sessionlayer_ca_signer_total{source="request"}[30m]))` → 0.999
- cert-sign p95 `histogram_quantile(0.95, sum by(le,kind)(rate(sessionlayer_cert_sign_seconds_bucket[5m])))` → 0.1s

**Gateway data-path RED (span-metrics)** — `calls_total` + `duration_milliseconds_bucket`
tagged `{service_name, span_name, span_kind, status_code, sessionlayer_outcome, sessionlayer_access_model}`:
- Rate/Errors/Duration per `span_name ∈ {gateway.session, outer_leg.auth, node.connect, host_verify, bridge_setup}`
- host_verify error spikes = no-TOFU aborts (security)

**Saturation** — CP r2dbc pool (`r2dbc_pool_acquired / r2dbc_pool_max_allocated`,
`r2dbc_pool_pending`), JVM, process fds (all auto from actuator).

## Missing metrics — the enumerated follow-up (A8 F-OBS-1/3/4/5)

The Tier-0 Gateway/Agent deliberately emit **no Prometheus metrics** (no new listener on
the plaintext-MITM box). The RED half is delivered above via span-metrics. Two of the
originally-enumerated Gateway gauges shipped in **S24** (`gateway-core/src/telemetry.rs`):
`sessionlayer.gateway.live_sessions` (from `LiveSessionRegistry::len()`) and
`sessionlayer.gateway.lock_feed_healthy` (0/1 from the live `LockSet`), wired via
`register_gateway_gauges`/`register_gateway_gauges_on`. The remaining **saturation gauges /
counters are not span-derivable** and are still the clean next increment (out of the S23
"no new features" scope; the fail-closed events they'd count are captured in the
structured logs today and can be shipped to the same collector):

- **Gateway:** `gateway_lock_feed_disconnect_total`,
  `gateway_cp_rpc_total{rpc,outcome}` (the fail-closed CP-down signal), `gateway_channel_open_total{outcome,reason}`,
  `gateway_pending_relays`, recorder spool bytes, `gateway_open_fds`.
- **Agent:** `agent_dial_back{outcome}`, `agent_renew{outcome}` (renew-storm/clone signal),
  a `control_channels` gauge (FR-HA-6 ≥2), + a bind-guarded `/metrics` or OTLP-metrics emitter.
  (`src/telemetry.rs` today emits OTel **spans** only, no metrics.)
- **CP:** a gRPC `MetricCollectingServerInterceptor` on `GrpcMtlsServer` (per-method RED for
  all ~15 RPCs), `sessionlayer.lockfeed.subscribers` gauge, `sessionlayer.authz.decision_total{outcome,reason,access_model}`,
  `sessionlayer.breakglass.activation_total`.

Recommended emission path for the Tier-0 binaries: OTel **metrics** over the existing
OTLP pipeline (no new inbound listener), surfaced to Prometheus by the collector — the
same low-attack-surface pattern as the span-metrics here.

## Preconditions & corrections for the span-derived Gateway RED (A8)

- **Fixed in S24 — span status on fail-closed paths.** Every deny/fault path in the Gateway
  funnels through the single choke-point `close_with()` (`gateway-core/src/ssh/handler.rs`),
  which unconditionally calls `telemetry::record_span_fail_closed(&session_span,
  outcome.span_label())` before closing the channel — covering every `SshOutcome` variant
  (`policy_denied` in all its `reason`s, `cp_unavailable`, `node_unreachable`,
  `recording_unavailable`). The allow path separately stamps
  `session_span.record("sessionlayer.outcome", "allow")`. So a span-metrics error-rate keyed
  on `status_code` now **does** see fail-closed sessions — the Gateway span-RED error-rate is
  a reliable 3am signal, not rate/latency-only. The CP
  `sessionlayer_session_establishment_seconds_count{outcome=~"error|cancelled"}` metric (this
  dir) remains a valid corroborating signal, just no longer the *only* trustworthy one.
- **Metric names are collector-version-dependent.** Depending on the `spanmetrics`
  connector version the series are either `calls_total` / `duration_milliseconds_bucket`
  (used in the alert rules here) or `traces_spanmetrics_calls_total` /
  `traces_spanmetrics_latency_bucket` — confirm against your collector and adjust the
  rule/dashboard names to match.
- **Sampling + cardinality preconditions.** The OTLP exporter is off by default, so
  span-metrics require it ON in prod with **head sampling at 100%** on the
  establishment path (sampled spans undercount RED rates); the connector `dimensions`
  MUST stay an allow-list (outcome, access_model, connector_kind) — never
  session_id/correlation_id/node_id (cardinality bomb + OTEL-CONTRACT §7).
