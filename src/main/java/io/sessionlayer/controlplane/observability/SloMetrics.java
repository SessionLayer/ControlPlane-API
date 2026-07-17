package io.sessionlayer.controlplane.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.sessionlayer.controlplane.authz.ConnectDecision;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The Session-21 SLO instruments (Design §14, NFR-3/NFR-4). Every meter is
 * tagged by <b>outcome/kind enum only</b> — never {@code session_id} /
 * {@code correlation_id} / {@code node_id} (OTEL-CONTRACT §7: those are
 * high-cardinality and live on the trace, not the metric).
 *
 * <ul>
 * <li>{@code sessionlayer.session.establishment} — NFR-4 session-establishment
 * latency: the CP-side machine work of the {@code Authorize} path (decision +
 * session-row write + token mint). It is machine-only — the human OIDC login
 * happens on the earlier outer-leg auth RPCs, never in this timer.</li>
 * <li>{@code sessionlayer.cert.sign} — the inner-leg / host cert-sign latency
 * (the second machine leg of establishment).</li>
 * <li>{@code sessionlayer.ca.signer} — NFR-3 session-CA signing availability:
 * whether an active signer could be obtained ({@code available} vs
 * {@code unavailable} = fail-closed vs {@code error}).</li>
 * </ul>
 */
@Component
public class SloMetrics {

	static final String ESTABLISHMENT = "sessionlayer.session.establishment";
	static final String CERT_SIGN = "sessionlayer.cert.sign";
	static final String CA_SIGNER = "sessionlayer.ca.signer";

	static final String TAG_OUTCOME = "outcome";
	static final String TAG_ACCESS_MODEL = "access_model";
	static final String TAG_KIND = "kind";
	// The CA-availability SLI population: a real cert-sign REQUEST vs the periodic
	// health PROBE. Kept distinct so the NFR-3 99.9% is computed over real requests
	// (the ~6/min probe baseline would otherwise mask partial degradation).
	static final String TAG_SOURCE = "source";
	public static final String SOURCE_REQUEST = "request";
	public static final String SOURCE_PROBE = "probe";

	static final String OUTCOME_AVAILABLE = "available";
	static final String OUTCOME_UNAVAILABLE = "unavailable";
	static final String OUTCOME_ERROR = "error";

	private final MeterRegistry registry;

	public SloMetrics(MeterRegistry registry) {
		this.registry = registry;
	}

	/**
	 * Time the CP-side session-establishment path (the {@code Authorize} machine
	 * work).
	 */
	public Mono<ConnectDecision> timeEstablishment(Mono<ConnectDecision> source) {
		return Mono.defer(() -> {
			long start = System.nanoTime();
			return source
					.doOnNext(decision -> recordEstablishment(start, decision.allowed() ? "allow" : "deny",
							modelOf(decision)))
					.doOnError(error -> recordEstablishment(start, OUTCOME_ERROR, "none"))
					.doOnCancel(() -> recordEstablishment(start, "cancelled", "none"));
		});
	}

	/** Time a certificate signing leg (session inner cert or gateway host cert). */
	public <T> Mono<T> timeCertSign(String kind, Mono<T> source) {
		return Mono.defer(() -> {
			long start = System.nanoTime();
			return source.doOnNext(value -> recordCertSign(start, kind, "success"))
					.doOnError(error -> recordCertSign(start, kind, OUTCOME_ERROR))
					.doOnCancel(() -> recordCertSign(start, kind, "cancelled"));
		});
	}

	/** NFR-3 availability signal from {@code CaSignerService.activeSigner}. */
	public void recordSignerOutcome(String kind, String source, String outcome) {
		Counter.builder(CA_SIGNER).tag(TAG_KIND, kind).tag(TAG_SOURCE, source).tag(TAG_OUTCOME, outcome)
				.register(registry).increment();
	}

	private void recordEstablishment(long startNanos, String outcome, String accessModel) {
		Timer.builder(ESTABLISHMENT).tag(TAG_OUTCOME, outcome).tag(TAG_ACCESS_MODEL, accessModel).register(registry)
				.record(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);
	}

	private void recordCertSign(long startNanos, String kind, String outcome) {
		Timer.builder(CERT_SIGN).tag(TAG_KIND, kind).tag(TAG_OUTCOME, outcome).register(registry)
				.record(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);
	}

	private static String modelOf(ConnectDecision decision) {
		if (decision.trace() != null && decision.trace().accessModel() != null) {
			return decision.trace().accessModel();
		}
		return decision.allowed() ? "standing" : "none";
	}
}
