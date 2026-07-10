package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import java.util.List;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Cold-start CA provisioning (FR-BOOT-1 / D31, §5.5). On first run against an
 * empty DB it ensures the operator-settings singleton exists and provisions the
 * three CAs (user / internal session / host) exactly once, then is a no-op on
 * every subsequent start (idempotent, restart-safe). It is <b>race-safe</b>:
 * the whole operation runs under a Postgres transaction-scoped <b>advisory
 * lock</b>, so two starting instances cannot double-generate, and the
 * partial-unique active-per-kind index is a hard backstop.
 *
 * <p>
 * Local CAs are generated and KEK-wrapped (FR-CA-8) with a loud production
 * warning; cloud CAs (KMS/KeyVault/Vault) are <b>referenced</b> via an
 * operator-pre-created {@code ca_config} (their key lives in the cloud, not
 * generated here).
 */
@Service
public class CaProvisioningService {

	/** A stable advisory-lock key for cold start (arbitrary 64-bit constant). */
	private static final long COLD_START_LOCK = 0x53_4C_5F_43_41_5F_43_53L; // "SL_CA_CS"

	/**
	 * The three CAs (Design §3.1). Session first so a node can be targeted early.
	 */
	private static final List<String> CA_KINDS = List.of("session", "user", "host");

	private final OperatorSettingsRepository operatorSettings;
	private final CaConfigRepository caConfigs;
	private final CaKeyMaterialRepository caKeyMaterials;
	private final DatabaseClient db;
	private final TransactionalOperator tx;
	private final LocalCaFactory localCaFactory;

	public CaProvisioningService(OperatorSettingsRepository operatorSettings, CaConfigRepository caConfigs,
			CaKeyMaterialRepository caKeyMaterials, DatabaseClient db, TransactionalOperator tx,
			LocalCaFactory localCaFactory) {
		this.operatorSettings = operatorSettings;
		this.caConfigs = caConfigs;
		this.caKeyMaterials = caKeyMaterials;
		this.db = db;
		this.tx = tx;
		this.localCaFactory = localCaFactory;
	}

	/** Provision (or no-op) the operator settings + the three CAs, race-safely. */
	public Mono<Void> provisionAll() {
		Mono<Void> body = acquireLock().then(ensureSettings()).flatMap(settings -> Flux.fromIterable(CA_KINDS)
				.concatMap(kind -> ensureCa(kind, settings.defaultCaBackend())).then());
		return tx.transactional(body).then();
	}

	private Mono<Long> acquireLock() {
		return db.sql("SELECT pg_advisory_xact_lock(:k)").bind("k", COLD_START_LOCK).fetch().rowsUpdated();
	}

	private Mono<OperatorSettings> ensureSettings() {
		return operatorSettings.findSingleton()
				.switchIfEmpty(Mono.defer(() -> operatorSettings.save(OperatorSettings.defaults())));
	}

	private Mono<Void> ensureCa(String kind, String backend) {
		return caConfigs.findByCaKindAndRotationState(kind, "active").hasElement()
				.flatMap(exists -> exists
						? Mono.<Void>empty() // idempotent: an active CA of this kind already exists
						: provisionKind(kind, backend));
	}

	private Mono<Void> provisionKind(String kind, String backend) {
		CaBackendCapabilities.validate(backend, CaKeyType.ECDSA_NISTP256.algorithmId());
		if (!"local".equals(backend)) {
			// Cloud CAs are referenced, not generated: their key lives in
			// KMS/KeyVault/Vault
			// and the operator pre-creates the ca_config with the key_reference.
			return Mono.error(new IllegalStateException("cold start cannot auto-generate a '" + backend + "' CA for '"
					+ kind + "': create the ca_config referencing the externally-managed key (key_reference)"));
		}
		return Mono.fromCallable(() -> localCaFactory.create(kind, kind + "-ca", "active"))
				.flatMap(provisioned -> caConfigs.save(provisioned.config())
						.then(caKeyMaterials.save(provisioned.material())).then());
	}
}
