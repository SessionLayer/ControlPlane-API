package io.sessionlayer.controlplane.observability;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.SdkTracerProviderBuilder;
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.sdk.trace.samplers.Sampler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Hand-wires the OpenTelemetry SDK for the CP (Design §14, OTEL-CONTRACT). Boot
 * 4.1 does not auto-configure tracing on this classpath (no
 * {@code spring-boot-tracing}/{@code -opentelemetry} module), so this owns
 * exactly the span pipeline the contract needs and nothing auto-instruments
 * arbitrary HTTP/DB calls (which could otherwise carry request data). Only the
 * two contract spans ({@code cp.authorize}, {@code cp.cert_sign}) are created,
 * via {@link CpTracing}, correlated by {@code correlation_id}.
 *
 * <p>
 * It reads the S21 Part-C-1 config keys ({@code management.otlp.tracing.*},
 * {@code management.opentelemetry.resource-attributes.service.name},
 * {@code management.tracing.sampling.probability}). The OTLP exporter ships
 * spans off-box ONLY when {@code export.enabled=true} AND an endpoint is set —
 * off by default; otherwise the local Logback logging is unchanged. The W3C
 * propagator lets CP spans attach as children of the Gateway root span.
 */
@Configuration
public class TracingConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(TracingConfiguration.class);
	private static final AttributeKey<String> SERVICE_NAME = AttributeKey.stringKey("service.name");

	/**
	 * The self-managed SDK. {@code close()} flushes/shuts the exporter on context
	 * stop. Not registered as the OTel global (per-context bean only) so multiple
	 * test contexts never collide on {@code GlobalOpenTelemetry}.
	 */
	@Bean(destroyMethod = "close")
	@ConditionalOnMissingBean(OpenTelemetry.class)
	OpenTelemetrySdk openTelemetry(
			@Value("${management.opentelemetry.resource-attributes.service.name:sessionlayer-controlplane}") String serviceName,
			@Value("${management.otlp.tracing.endpoint:}") String otlpEndpoint,
			@Value("${management.otlp.tracing.export.enabled:false}") boolean exportEnabled,
			@Value("${management.tracing.sampling.probability:1.0}") double sampleProbability,
			ObjectProvider<SpanProcessor> extraProcessors) {
		Resource resource = Resource.getDefault()
				.merge(Resource.create(Attributes.of(SERVICE_NAME, serviceName)));
		// parentBased: honour the Gateway root's sampling decision when it propagates
		// one; the ratio only governs a CP-ROOTED span (an RPC with no traceparent).
		SdkTracerProviderBuilder tracerProvider = SdkTracerProvider.builder().setResource(resource)
				.setSampler(Sampler.parentBased(Sampler.traceIdRatioBased(sampleProbability)));
		if (exportEnabled) {
			OtlpTraceExporter.forEndpoint(otlpEndpoint).ifPresentOrElse(
					exporter -> tracerProvider.addSpanProcessor(BatchSpanProcessor.builder(exporter).build()),
					() -> LOG.warn("OTLP trace export enabled but no management.otlp.tracing.endpoint set — exporter off"));
		} else {
			LOG.info("OTLP trace exporter disabled (management.otlp.tracing.export.enabled=false); "
					+ "spans are created but not exported off-box");
		}
		// Tests attach an in-memory SpanProcessor to assert propagation + no-content.
		extraProcessors.orderedStream().forEach(tracerProvider::addSpanProcessor);
		return OpenTelemetrySdk.builder().setTracerProvider(tracerProvider.build())
				.setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance())).build();
	}

	@Bean
	@ConditionalOnMissingBean(CpTracing.class)
	CpTracing cpTracing(OpenTelemetry openTelemetry) {
		return new CpTracing(openTelemetry);
	}
}
