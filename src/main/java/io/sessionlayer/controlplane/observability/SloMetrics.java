package io.sessionlayer.controlplane.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.sessionlayer.controlplane.authz.ConnectDecision;
import io.sessionlayer.controlplane.data.runtime.JitRequest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The Session-21 SLO instruments (Design §14, NFR-3/NFR-4) plus the Session-25
 * FR-SESS-3 limit/lease lifecycle meters. Every meter is tagged by
 * <b>outcome/kind enum only</b> — never {@code session_id} /
 * {@code correlation_id} / {@code node_id} / identity (OTEL-CONTRACT §7: those
 * are high-cardinality and live on the trace, not the metric).
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
 * <li>{@code sessionlayer.session.limit} — FR-SESS-3 limit hits
 * ({@code outcome=denied}, by access model).</li>
 * <li>{@code sessionlayer.session.lease.reaped} — leaked leases released by the
 * {@code SessionLeaseReaper} sweep.</li>
 * <li>{@code sessionlayer.session.lease.live} — fleet-wide live (unreleased +
 * unexpired) concurrency leases, refreshed on a schedule. Reads 0 until the
 * first refresh; every CP instance reports the SAME fleet-wide count, so
 * scaled-out dashboards aggregate with max/last, never sum. Staleness is
 * observable via {@code sessionlayer.session.lease.live.refresh.failed}.</li>
 * <li>{@code sessionlayer.session.lifecycle} — the S25 lifecycle-RPC outcomes
 * ({@code rpc=notify_session_end|extend_session_lease},
 * {@code outcome=released|not_released|extended|refused|error}) — the
 * lease-partition / reaped-live-lease signatures show up here.</li>
 * <li>{@code sessionlayer.jit.lookup} — the S30 unconditional-per-connect JIT
 * grant lookup latency, {@code outcome=hit|miss|error|cancelled} (a
 * {@code lookup-timeout} degrades to {@code cancelled}) — isolates this
 * lookup's contribution to establishment latency from dp_rule/lock load and the
 * session-row write.</li>
 * </ul>
 */
@Component
public class SloMetrics {

	static final String ESTABLISHMENT = "sessionlayer.session.establishment";
	static final String CERT_SIGN = "sessionlayer.cert.sign";
	static final String CA_SIGNER = "sessionlayer.ca.signer";
	static final String SESSION_LIMIT = "sessionlayer.session.limit";
	static final String LEASE_REAPED = "sessionlayer.session.lease.reaped";
	static final String LEASE_LIVE = "sessionlayer.session.lease.live";
	static final String LEASE_GAUGE_REFRESH_FAILED = "sessionlayer.session.lease.live.refresh.failed";
	static final String SESSION_LIFECYCLE = "sessionlayer.session.lifecycle";
	static final String JIT_LOOKUP = "sessionlayer.jit.lookup";

	static final String TAG_RPC = "rpc";
	public static final String RPC_NOTIFY_SESSION_END = "notify_session_end";
	public static final String RPC_EXTEND_SESSION_LEASE = "extend_session_lease";

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
	private final AtomicLong liveLeases = new AtomicLong();

	public SloMetrics(MeterRegistry registry) {
		this.registry = registry;
		Gauge.builder(LEASE_LIVE, liveLeases, AtomicLong::doubleValue)
				.description("Live (unreleased, unexpired) FR-SESS-3 concurrency leases, fleet-wide")
				.register(registry);
	}

	/** A per-identity session-limit denial at Authorize (FR-SESS-3, S25). */
	public void recordSessionLimitDenied(String accessModel) {
		Counter.builder(SESSION_LIMIT).tag(TAG_OUTCOME, "denied").tag(TAG_ACCESS_MODEL, accessModel).register(registry)
				.increment();
	}

	/** Leaked leases released by a reaper sweep. */
	public void recordLeasesReaped(long reaped) {
		if (reaped > 0) {
			Counter.builder(LEASE_REAPED).register(registry).increment(reaped);
		}
	}

	/** Refresh the live-lease gauge (scheduled; no per-identity breakdown). */
	public void updateLiveLeases(long count) {
		liveLeases.set(count);
	}

	/** A failed gauge refresh — the live-lease gauge is now stale (F4). */
	public void recordLeaseGaugeRefreshFailed() {
		Counter.builder(LEASE_GAUGE_REFRESH_FAILED).register(registry).increment();
	}

	/** An S25 lifecycle-RPC outcome (enum tags only — never identity/session). */
	public void recordSessionLifecycle(String rpc, String outcome) {
		Counter.builder(SESSION_LIFECYCLE).tag(TAG_RPC, rpc).tag(TAG_OUTCOME, outcome).register(registry).increment();
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

	/**
	 * Time the S30 unconditional per-connect JIT grant lookup. {@code cancelled} is
	 * the {@code lookup-timeout} signature — distinguish it from a genuine
	 * {@code miss} (query answered, no usable grant) so a degraded jit_request
	 * table is attributable, not just visible in aggregate establishment p95.
	 */
	public Mono<JitRequest> timeJitLookup(Mono<JitRequest> source) {
		return Mono.defer(() -> {
			long start = System.nanoTime();
			return source.doOnSuccess(grant -> recordJitLookup(start, grant != null ? "hit" : "miss"))
					.doOnError(error -> recordJitLookup(start, OUTCOME_ERROR))
					.doOnCancel(() -> recordJitLookup(start, "cancelled"));
		});
	}

	private void recordJitLookup(long startNanos, String outcome) {
		Timer.builder(JIT_LOOKUP).tag(TAG_OUTCOME, outcome).register(registry).record(System.nanoTime() - startNanos,
				TimeUnit.NANOSECONDS);
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
