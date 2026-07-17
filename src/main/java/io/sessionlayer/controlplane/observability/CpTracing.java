package io.sessionlayer.controlplane.observability;

import io.grpc.Metadata;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.sessionlayer.controlplane.authz.ConnectDecision;
import reactor.core.publisher.Mono;

/**
 * The CP tracing seam (Design §14, OTEL-CONTRACT). Extracts the Gateway's W3C
 * trace context from gRPC metadata and wraps the two decision RPCs in the
 * contract spans so they become children of the Gateway root:
 * {@code cp.authorize} and {@code cp.cert_sign}.
 *
 * <p>
 * Spans carry <b>correlation, never content</b> (OTEL-CONTRACT §5): only IDs,
 * enums, outcomes, and — on failure — the error <i>type</i>. No SSH plaintext,
 * key, OTP, token, or recording byte ever enters a span. The parent is passed
 * <b>explicitly</b> to each span builder (never via a thread-local), so the
 * parent→child link is correct across the reactive/Reactor thread hops without
 * any context-propagation hooks.
 */
public final class CpTracing {

	/** The extracted Gateway trace context, stashed by {@code AuthInterceptor}. */
	public static final io.grpc.Context.Key<Context> OTEL_PARENT = io.grpc.Context.key("sessionlayer-otel-parent");

	private static final String CP_AUTHORIZE = "cp.authorize";
	private static final String CP_CERT_SIGN = "cp.cert_sign";

	static final AttributeKey<String> SESSION_ID = AttributeKey.stringKey("sessionlayer.session_id");
	static final AttributeKey<String> CORRELATION_ID = AttributeKey.stringKey("sessionlayer.correlation_id");
	static final AttributeKey<String> NODE_ID = AttributeKey.stringKey("sessionlayer.node_id");
	static final AttributeKey<String> ACCESS_MODEL = AttributeKey.stringKey("sessionlayer.access_model");
	static final AttributeKey<String> OUTCOME = AttributeKey.stringKey("sessionlayer.outcome");
	static final AttributeKey<String> CERT_KIND = AttributeKey.stringKey("sessionlayer.cert_kind");
	static final AttributeKey<String> ERROR_TYPE = AttributeKey.stringKey("sessionlayer.error_type");

	private static final TextMapGetter<Metadata> METADATA_GETTER = new TextMapGetter<>() {
		@Override
		public Iterable<String> keys(Metadata carrier) {
			return carrier.keys();
		}

		@Override
		public String get(Metadata carrier, String key) {
			if (carrier == null) {
				return null;
			}
			return carrier.get(Metadata.Key.of(key, Metadata.ASCII_STRING_MARSHALLER));
		}
	};

	private final Tracer tracer;
	private final TextMapPropagator propagator;

	public CpTracing(OpenTelemetry openTelemetry) {
		this.tracer = openTelemetry.getTracer("io.sessionlayer.controlplane");
		this.propagator = openTelemetry.getPropagators().getTextMapPropagator();
	}

	/**
	 * Extract the Gateway's {@code traceparent}/{@code tracestate} from gRPC
	 * metadata.
	 */
	public Context extractParent(Metadata headers) {
		return propagator.extract(Context.root(), headers, METADATA_GETTER);
	}

	/**
	 * Wrap the connect decision in {@code cp.authorize}, correlated by
	 * session/correlation id.
	 */
	public Mono<ConnectDecision> traceAuthorize(Context parent, String sessionId, String requestNodeId,
			Mono<ConnectDecision> source) {
		Span span = tracer.spanBuilder(CP_AUTHORIZE).setSpanKind(SpanKind.SERVER).setParent(orRoot(parent)).startSpan();
		setIfPresent(span, SESSION_ID, sessionId);
		setIfPresent(span, NODE_ID, requestNodeId);
		return source.doOnNext(decision -> onDecision(span, decision)).doOnError(error -> markError(span, error))
				.doFinally(signal -> span.end());
	}

	/**
	 * Wrap a certificate signing (session inner cert or gateway host cert) in
	 * {@code cp.cert_sign}.
	 */
	public <T> Mono<T> traceCertSign(Context parent, String kind, String sessionId, Mono<T> source) {
		Span span = tracer.spanBuilder(CP_CERT_SIGN).setSpanKind(SpanKind.SERVER).setParent(orRoot(parent)).startSpan();
		span.setAttribute(CERT_KIND, kind);
		setIfPresent(span, SESSION_ID, sessionId);
		return source.doOnNext(value -> span.setAttribute(OUTCOME, "success"))
				.doOnError(error -> markError(span, error)).doFinally(signal -> span.end());
	}

	private static void onDecision(Span span, ConnectDecision decision) {
		span.setAttribute(OUTCOME, decision.allowed() ? "allow" : "deny");
		ConnectDecision.TraceInfo trace = decision.trace();
		if (trace == null) {
			return;
		}
		setIfPresent(span, ACCESS_MODEL, trace.accessModel());
		if (trace.nodeId() != null) {
			span.setAttribute(NODE_ID, trace.nodeId().toString());
		}
		if (trace.correlationId() != null) {
			span.setAttribute(CORRELATION_ID, trace.correlationId().toString());
		}
	}

	private static void markError(Span span, Throwable error) {
		// Record the error CATEGORY only — never the message (which could echo input).
		span.setStatus(StatusCode.ERROR);
		span.setAttribute(OUTCOME, "error");
		span.setAttribute(ERROR_TYPE, error.getClass().getSimpleName());
	}

	private static void setIfPresent(Span span, AttributeKey<String> key, String value) {
		if (value != null && !value.isBlank()) {
			span.setAttribute(key, value);
		}
	}

	private static Context orRoot(Context parent) {
		return parent != null ? parent : Context.root();
	}
}
