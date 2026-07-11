package io.sessionlayer.controlplane.ca.mtls;

import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * Provisions (idempotently, race-safely) and loads the internal mTLS CA (Part B).
 * The CA is provisioned as part of cold start ({@code CaProvisioningService} calls
 * {@link #ensureProvisioned} under the shared advisory lock) and is also
 * self-provisioned on demand by the gRPC server startup via
 * {@link #loadOrProvision} (which takes the same lock), so the mTLS plane comes up
 * even if it is the first thing to touch the CA. Loading is fail-closed: if there
 * is no active mTLS CA it errors rather than falling back (NFR-2).
 */
@Service
public class InternalMtlsCaService {

	/** Same advisory-lock key as {@code CaProvisioningService} cold start. */
	private static final long COLD_START_LOCK = 0x53_4C_5F_43_41_5F_43_53L; // "SL_CA_CS"

	private final CaConfigRepository caConfigs;
	private final CaKeyMaterialRepository caKeyMaterials;
	private final InternalMtlsCaFactory factory;
	private final DatabaseClient db;
	private final TransactionalOperator tx;

	public InternalMtlsCaService(CaConfigRepository caConfigs, CaKeyMaterialRepository caKeyMaterials,
			InternalMtlsCaFactory factory, DatabaseClient db, TransactionalOperator tx) {
		this.caConfigs = caConfigs;
		this.caKeyMaterials = caKeyMaterials;
		this.factory = factory;
		this.db = db;
		this.tx = tx;
	}

	/** Signals that no internal mTLS CA is available — callers MUST fail closed. */
	public static final class NoMtlsCaAvailable extends RuntimeException {
		public NoMtlsCaAvailable(String message) {
			super(message);
		}
	}

	/**
	 * Ensure the active internal mTLS CA exists (idempotent). Intended to run under
	 * a caller-held advisory lock (cold start). Only the {@code local} backend is
	 * auto-generated; a cloud X.509 CA is referenced via an operator-created
	 * {@code ca_config} (its key lives in the cloud).
	 */
	public Mono<Void> ensureProvisioned(String backend) {
		return caConfigs.findByCaKindAndRotationState(InternalMtlsCaFactory.CA_KIND, "active").hasElement()
				.flatMap(exists -> exists ? Mono.<Void>empty() : provision(backend));
	}

	private Mono<Void> provision(String backend) {
		if (!"local".equals(backend)) {
			return Mono.error(new IllegalStateException("cold start cannot auto-generate a '" + backend
					+ "' internal mTLS CA: create the ca_config referencing the externally-managed key"));
		}
		return Mono.fromCallable(() -> factory.create(InternalMtlsCaFactory.DEFAULT_NAME, "active"))
				.flatMap(provisioned -> caConfigs.save(provisioned.config())
						.then(caKeyMaterials.save(provisioned.material())).then());
	}

	/** Load the active internal mTLS CA backend, or fail closed. */
	public Mono<X509CaBackend> activeBackend() {
		return caConfigs.findByCaKindAndRotationState(InternalMtlsCaFactory.CA_KIND, "active")
				.switchIfEmpty(Mono.error(new NoMtlsCaAvailable("no active internal mTLS CA (fail closed)")))
				.flatMap(config -> caKeyMaterials.findByCaConfigId(config.id())
						.switchIfEmpty(Mono.error(
								new NoMtlsCaAvailable("internal mTLS CA key material missing for " + config.name())))
						.map(material -> (X509CaBackend) factory.load(config, material)));
	}

	/**
	 * Load the active internal mTLS CA, provisioning it first (race-safely, under the
	 * cold-start advisory lock) if absent. Used by the gRPC server startup.
	 */
	public Mono<X509CaBackend> loadOrProvision(String backend) {
		return activeBackend()
				.onErrorResume(NoMtlsCaAvailable.class, absent -> provisionUnderLock(backend).then(activeBackend()));
	}

	private Mono<Void> provisionUnderLock(String backend) {
		// lock_timeout so a wedged peer fails the boot rather than hanging forever.
		Mono<Void> body = db.sql("SET LOCAL lock_timeout = '15s'").fetch().rowsUpdated()
				.then(db.sql("SELECT pg_advisory_xact_lock(:k)").bind("k", COLD_START_LOCK).fetch().rowsUpdated())
				.then(ensureProvisioned(backend));
		return tx.transactional(body).then();
	}
}
