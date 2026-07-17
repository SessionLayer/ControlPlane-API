package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.protobuf.ByteString;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.micrometer.core.instrument.MeterRegistry;
import io.netty.handler.ssl.SslContext;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.SessionSigningGrpc;
import io.sessionlayer.controlplane.grpc.v1.SignContext;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateResponse;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Part C + Part D gate (Design §14, OTEL-CONTRACT). A Gateway-injected
 * {@code traceparent} makes the CP's {@code cp.authorize} and
 * {@code cp.cert_sign} spans children of the SAME trace — one trace across the
 * CP↔GW gRPC plane — and NO span attribute carries plaintext / key / token /
 * recording content (the no-content assertion). The NFR-3/NFR-4 SLO meters are
 * emitted for the same flow.
 */
@Import(ObservabilityIT.SpanCapture.class)
class ObservabilityIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	// A fixed W3C traceparent the "Gateway" injects: 00-<trace32>-<span16>-01.
	private static final String TRACE_ID = "0af7651916cd43dd8448eb211c80319c";
	private static final String SPAN_ID = "b7ad6b7169203331";

	@Autowired
	private InMemorySpanExporter spans;
	@Autowired
	private MeterRegistry meters;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;

	@BeforeEach
	void resetSpans() {
		spans.reset();
	}

	@Test
	void oneTraceAcrossAuthorizeAndCertSignCarryingNoContent() {
		String identity = "trace-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-trace-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse authorized = authorizeWithTrace(gateway,
				AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
						.setRequestedPrincipal("deploy").setSourceIp("10.0.0.5").setSessionId(sessionId.toString())
						.build());
		assertThat(authorized.getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		byte[] subjectKey = MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic());
		SignSessionCertificateResponse signed = signWithTrace(gateway, authorized.getSessionToken(), subjectKey,
				SignContext.newBuilder().setSessionId(sessionId.toString()).build());
		assertThat(signed.getCertificateLine()).startsWith("ecdsa-sha2-nistp256-cert-v01@openssh.com");

		// Both CP spans are children of the SAME Gateway-injected trace/span → one trace.
		SpanData authorizeSpan = awaitSpan("cp.authorize");
		assertThat(authorizeSpan.getTraceId()).isEqualTo(TRACE_ID);
		assertThat(authorizeSpan.getParentSpanId()).isEqualTo(SPAN_ID);
		assertThat(attr(authorizeSpan, "sessionlayer.session_id")).isEqualTo(sessionId.toString());
		assertThat(attr(authorizeSpan, "sessionlayer.outcome")).isEqualTo("allow");
		assertThat(attr(authorizeSpan, "sessionlayer.access_model")).isEqualTo("standing");
		// A standing chain's correlation_id == the session id (pivot to audit/recording).
		assertThat(attr(authorizeSpan, "sessionlayer.correlation_id")).isEqualTo(sessionId.toString());

		SpanData certSpan = awaitSpan("cp.cert_sign");
		assertThat(certSpan.getTraceId()).isEqualTo(TRACE_ID);
		assertThat(certSpan.getParentSpanId()).isEqualTo(SPAN_ID);
		assertThat(attr(certSpan, "sessionlayer.cert_kind")).isEqualTo("session");
		assertThat(attr(certSpan, "sessionlayer.outcome")).isEqualTo("success");

		// No-content gate: NO span attribute value carries the session/recording token or
		// the subject key material — spans carry IDs/enums/outcomes only. (Guard blanks:
		// an empty secret would make doesNotContain("") vacuously fail.)
		List<String> secrets = java.util.stream.Stream
				.of(authorized.getSessionToken(), authorized.getRecordingToken(),
						Base64.getEncoder().encodeToString(subjectKey))
				.filter(s -> s != null && !s.isBlank()).toList();
		assertThat(secrets).isNotEmpty();
		for (SpanData span : spans.getFinishedSpanItems()) {
			for (Object value : span.getAttributes().asMap().values()) {
				String rendered = String.valueOf(value);
				secrets.forEach(secret -> assertThat(rendered).doesNotContain(secret));
			}
		}
	}

	@Test
	void sloMetricsAreEmittedForTheEstablishmentAndSigningPaths() {
		String identity = "slo-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-slo-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse authorized = authorizeWithTrace(gateway,
				AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
						.setRequestedPrincipal("deploy").setSourceIp("10.0.0.5").setSessionId(sessionId.toString())
						.build());
		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		signWithTrace(gateway, authorized.getSessionToken(),
				MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic()), null);

		// NFR-4: the CP-side session-establishment timer, tagged by outcome/model enum.
		assertThat(meters.find("sessionlayer.session.establishment").tag("outcome", "allow")
				.tag("access_model", "standing").timer()).isNotNull();
		assertThat(meters.get("sessionlayer.session.establishment").tag("outcome", "allow").timer().count())
				.isGreaterThan(0);
		// The cert-sign leg timer.
		assertThat(meters.get("sessionlayer.cert.sign").tag("kind", "session").tag("outcome", "success").timer().count())
				.isGreaterThan(0);
		// NFR-3: an available session signer was measured (fail-closed unavailable is
		// proven in CaSignerMetricsTest without Docker).
		assertThat(meters.get("sessionlayer.ca.signer").tag("kind", "session").tag("outcome", "available").counter()
				.count()).isGreaterThan(0);
	}

	// ----- helpers -----

	private AuthorizeResponse authorizeWithTrace(EnrolledGateway gateway, AuthorizeRequest request) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return AuthorizationGrpc.newBlockingStub(channel).withInterceptors(traceparentInjector()).authorize(request);
		} finally {
			shutdown(channel);
		}
	}

	private SignSessionCertificateResponse signWithTrace(EnrolledGateway gateway, String rawToken, byte[] subjectKey,
			SignContext context) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			SignSessionCertificateRequest.Builder request = SignSessionCertificateRequest.newBuilder()
					.setSessionToken(rawToken).setSubjectPublicKey(ByteString.copyFrom(subjectKey));
			if (context != null) {
				request.setContext(context);
			}
			return SessionSigningGrpc.newBlockingStub(channel).withInterceptors(traceparentInjector())
					.signSessionCertificate(request.build());
		} finally {
			shutdown(channel);
		}
	}

	// The Gateway would inject W3C context on every CP RPC; here a fixed traceparent.
	private static ClientInterceptor traceparentInjector() {
		return new ClientInterceptor() {
			@Override
			public <Q, R> ClientCall<Q, R> interceptCall(MethodDescriptor<Q, R> method, CallOptions options,
					Channel next) {
				return new SimpleForwardingClientCall<>(next.newCall(method, options)) {
					@Override
					public void start(Listener<R> responseListener, Metadata headers) {
						headers.put(Metadata.Key.of("traceparent", Metadata.ASCII_STRING_MARSHALLER),
								"00-" + TRACE_ID + "-" + SPAN_ID + "-01");
						super.start(responseListener, headers);
					}
				};
			}
		};
	}

	private SpanData awaitSpan(String name) {
		for (int attempt = 0; attempt < 150; attempt++) {
			Optional<SpanData> found = spans.getFinishedSpanItems().stream().filter(s -> s.getName().equals(name))
					.findFirst();
			if (found.isPresent()) {
				return found.get();
			}
			sleep();
		}
		throw new AssertionError("span not exported: " + name);
	}

	private static String attr(SpanData span, String key) {
		return span.getAttributes().get(AttributeKey.stringKey(key));
	}

	private static void sleep() {
		try {
			Thread.sleep(20);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, UUID nodeId, List<String> principals, List<String> capabilities) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, principals, 3600,
				capabilities, "allow", "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}

	@TestConfiguration
	static class SpanCapture {
		@Bean
		InMemorySpanExporter inMemorySpanExporter() {
			return InMemorySpanExporter.create();
		}

		@Bean
		SpanProcessor testSpanProcessor(InMemorySpanExporter exporter) {
			return SimpleSpanProcessor.create(exporter);
		}
	}
}
