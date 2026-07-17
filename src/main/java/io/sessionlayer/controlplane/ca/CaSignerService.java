package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Builds a {@link SshCertSigner} for a CA (FR-SIGN-3 — per-CA, independent
 * backends) and enforces the HA <b>fail-closed</b> semantics (FR-CA-9): if
 * there is no active CA of the requested kind, or the local key material is
 * missing, it errors — it never returns a signer that would sign with the wrong
 * key or skip signing. (Connection-time <i>use</i> of the signer is Session
 * Eight.)
 */
@Service
public class CaSignerService {

	private final CaConfigRepository caConfigs;
	private final CaKeyMaterialRepository caKeyMaterials;
	private final LocalCaFactory localCaFactory;
	private final SloMetrics metrics;

	public CaSignerService(CaConfigRepository caConfigs, CaKeyMaterialRepository caKeyMaterials,
			LocalCaFactory localCaFactory, SloMetrics metrics) {
		this.caConfigs = caConfigs;
		this.caKeyMaterials = caKeyMaterials;
		this.localCaFactory = localCaFactory;
		this.metrics = metrics;
	}

	/**
	 * Signals that no signer is available for a CA — the caller MUST fail closed
	 * (FR-CA-9).
	 */
	public static final class NoSignerAvailable extends RuntimeException {
		public NoSignerAvailable(String message) {
			super(message);
		}
	}

	/**
	 * The signer for the currently-active CA of a kind, or a fail-closed error. A
	 * real cert-sign request; the NFR-3 availability SLI is measured over the
	 * {@code request} population.
	 */
	public Mono<SshCertSigner> activeSigner(String kind) {
		return activeSigner(kind, SloMetrics.SOURCE_REQUEST);
	}

	/**
	 * As {@link #activeSigner(String)} but attributing the availability sample to
	 * {@code source} ({@code request} = a real sign, {@code probe} = the health
	 * indicator poll) so the NFR-3 SLI is not diluted by the periodic probe.
	 */
	public Mono<SshCertSigner> activeSigner(String kind, String source) {
		// NFR-3 availability SLI: whether an active signer could be obtained. A missing
		// CA / key material is NoSignerAvailable ("unavailable" = fail-closed, not an
		// error); anything else is "error". Client-input rejections never reach here.
		return caConfigs.findByCaKindAndRotationState(kind, "active")
				.switchIfEmpty(Mono.error(new NoSignerAvailable("no active " + kind + " CA (fail closed)")))
				.flatMap(this::signerFor).doOnSuccess(signer -> {
					if (signer != null) {
						metrics.recordSignerOutcome(kind, source, "available");
					}
				}).doOnError(error -> metrics.recordSignerOutcome(kind, source,
						error instanceof NoSignerAvailable ? "unavailable" : "error"));
	}

	/**
	 * Build a signer for a specific CA config (validates the algorithm, FR-CA-4).
	 */
	public Mono<SshCertSigner> signerFor(CaConfig config) {
		return Mono.defer(() -> {
			// Deferred so a validation failure surfaces as a Mono error, not a synchronous
			// throw (FR-CA-4 rejection is reactive-safe for every caller).
			CaBackendCapabilities.validate(config.backend(), config.algorithm());
			if (!"local".equals(config.backend())) {
				// Cloud backends are fully implemented (KmsCaBackend/AzureKeyVaultCaBackend/
				// VaultCaCertSigner) but their signer seams are injected by the deployment;
				// the runtime wiring lands with the gRPC signer plane (S4). Fail closed here.
				return Mono.error(new NoSignerAvailable(
						"cloud CA '" + config.backend() + "' signer requires an injected backend seam (wired S4+)"));
			}
			return caKeyMaterials.findByCaConfigId(config.id())
					.switchIfEmpty(
							Mono.error(new NoSignerAvailable("local CA key material missing for " + config.name())))
					.map(material -> localCaFactory.load(config, material));
		});
	}
}
