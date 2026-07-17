# F-s21-telemetry-no-content-1: OTel spans must carry correlation, never content; exporter off by default

- Severity: high
- Status: Verified-Fixed
- Area: observability

## Summary
Session 21 adds distributed tracing (Design §14, OTEL-CONTRACT). A naive span implementation could leak SSH
plaintext, private keys, OTP codes, bearer/session/join tokens, device codes, or recording bytes into a span
name/attribute/event — telemetry is shipped off-box, so a leak there is a disclosure. Two invariants must hold:
(1) spans carry IDs/enums/outcomes/durations ONLY; (2) the OTLP exporter is OFF unless explicitly configured
(no accidental off-box shipping).

## Fix (Verified-Fixed)
- The CP creates exactly two spans (`cp.authorize`, `cp.cert_sign`) via `CpTracing`, and stamps only
  non-content attributes: `sessionlayer.session_id`, `sessionlayer.correlation_id`, `sessionlayer.node_id`,
  `sessionlayer.access_model` (enum), `sessionlayer.outcome` (enum), `sessionlayer.cert_kind` (enum), and — on
  failure — `sessionlayer.error_type` = the exception CLASS name (a category, never the message, which could
  echo input). The signing services pass only public/subject material and IDs into the span, never the token or
  key bytes.
- No Boot tracing auto-configuration is on the classpath, so nothing auto-instruments arbitrary HTTP/DB calls
  (which could carry request data); the span pipeline is hand-wired (`TracingConfiguration`) and minimal.
- The OTLP exporter is added to the SDK only when `management.otlp.tracing.export.enabled=true` AND an endpoint
  is set — off by default; otherwise spans are created (for local correlation) but never exported off-box.
- Gate: `ObservabilityIT.oneTraceAcrossAuthorizeAndCertSignCarryingNoContent` injects a Gateway `traceparent`,
  drives a real allow + inner-cert sign over mTLS, asserts both spans are children of the SAME trace, and
  asserts NO span attribute value contains the session token, recording token, or the subject-key base64.
  `OtlpTraceExporterTest` proves a blank endpoint yields no exporter.
