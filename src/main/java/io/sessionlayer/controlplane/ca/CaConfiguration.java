package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import io.sessionlayer.controlplane.ca.backend.local.LocalCaKeyStore;
import io.sessionlayer.controlplane.ca.cert.OpenSshCertificateAssembler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;

/**
 * Wiring for the CA / certificate-signing subsystem (Part A). The KEK source,
 * the key store, the shared cert assembler and the reactive transaction
 * operator are beans; the cold-start runner provisions the three CAs at startup
 * (FR-BOOT-1), gated by {@code sessionlayer.coldstart.enabled} (default on) so
 * the data-model IT suite can disable it.
 */
@Configuration(proxyBeanMethods = false)
public class CaConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(CaConfiguration.class);

	/**
	 * The local-CA KEK (FR-CA-8). Sourced from configuration/env. Production MUST
	 * set {@code sessionlayer.ca.local.kek-base64}; if it is unset the built-in DEV
	 * default is used, which {@link KekProvider} refuses to start with unless
	 * {@code sessionlayer.ca.local.allow-dev-kek=true} (dev/test only — fail
	 * closed).
	 */
	@Bean
	public KekProvider kekProvider(@Value("${sessionlayer.ca.local.kek-base64:}") String kekBase64,
			@Value("${sessionlayer.ca.local.kek-reference:}") String kekReference,
			@Value("${sessionlayer.ca.local.allow-dev-kek:false}") boolean allowDevKek) {
		return new KekProvider(kekBase64, kekReference, allowDevKek);
	}

	@Bean
	public LocalCaKeyStore localCaKeyStore() {
		return new LocalCaKeyStore();
	}

	@Bean
	public OpenSshCertificateAssembler openSshCertificateAssembler() {
		return new OpenSshCertificateAssembler();
	}

	@Bean
	public TransactionalOperator caTransactionalOperator(ReactiveTransactionManager transactionManager) {
		return TransactionalOperator.create(transactionManager);
	}

	/**
	 * Cold-start CA provisioning at startup (FR-BOOT-1 / §5.5): the app comes up
	 * unattended, provisions the three CAs exactly once (idempotent, race-safe),
	 * then continues. Blocking here is intentional — startup must not proceed until
	 * the CAs exist, and this runs on the startup thread, never the reactive event
	 * loop.
	 */
	// Ordering note (R-WR-3): this ApplicationRunner is the first code to open an
	// R2DBC
	// connection (as cp_runtime), and it runs after Flyway has migrated (creating
	// the
	// cp_runtime role in V11) — Flyway completes during context refresh, before any
	// runner and before the server accepts traffic, and the R2DBC pool opens no
	// eager
	// connections. Any future eager @PostConstruct R2DBC work must respect this
	// invariant.
	@Bean
	@ConditionalOnProperty(value = "sessionlayer.coldstart.enabled", havingValue = "true", matchIfMissing = true)
	public ApplicationRunner caColdStartRunner(CaProvisioningService provisioningService,
			@Value("${sessionlayer.coldstart.timeout-seconds:60}") long timeoutSeconds) {
		return args -> {
			LOG.info("cold start: ensuring operator settings + the three CAs (FR-BOOT-1)");
			// Bounded block (R-COLD-1): a stuck provisioner CRASHES the boot (which the
			// orchestrator heals) rather than hanging the pod NotReady forever.
			provisioningService.provisionAll().block(java.time.Duration.ofSeconds(timeoutSeconds));
			LOG.info("cold start: CA provisioning complete");
		};
	}
}
