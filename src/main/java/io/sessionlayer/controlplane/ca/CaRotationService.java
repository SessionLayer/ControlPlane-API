package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * CA rotation without fleet downtime (FR-CA-7): overlap-then-drain over the S2
 * {@code ca_config.rotation_state} ({@code incoming → active → outgoing →
 * expired}) with the partial-unique active-per-kind index as a backstop. During
 * an overlap the trusted set (what nodes trust via {@code TrustedUserCAKeys})
 * contains the incoming (pre-published), active and outgoing CA keys, so no
 * in-flight or new session is rejected; {@code expired} keys drop out of trust.
 *
 * <p>
 * Emergency rotation is paired with locking + default-deny; locking is Session
 * Ten — the seam is here (rotation is independent of the lock primitive), not
 * the lock implementation.
 */
@Service
public class CaRotationService {

	/** Rotation states that are currently trusted by nodes (expired is dropped). */
	private static final Set<String> TRUSTED_STATES = Set.of("incoming", "active", "outgoing");

	private final CaConfigRepository caConfigs;
	private final CaKeyMaterialRepository caKeyMaterials;
	private final LocalCaFactory localCaFactory;
	private final TransactionalOperator tx;

	public CaRotationService(CaConfigRepository caConfigs, CaKeyMaterialRepository caKeyMaterials,
			LocalCaFactory localCaFactory, TransactionalOperator tx) {
		this.caConfigs = caConfigs;
		this.caKeyMaterials = caKeyMaterials;
		this.localCaFactory = localCaFactory;
		this.tx = tx;
	}

	/**
	 * The set of CA public keys nodes should trust for a kind right now
	 * ({@code TrustedUserCAKeys} content) — incoming + active + outgoing, so an
	 * overlap window never drops a valid signer.
	 */
	public Mono<List<String>> trustedCaKeys(String kind) {
		return caConfigs.findByCaKind(kind).filter(c -> TRUSTED_STATES.contains(c.rotationState()))
				.concatMap(config -> caKeyMaterials.findByCaConfigId(config.id())
						.map(material -> localCaFactory.publicAuthorizedKey(config, material)))
				.collectList();
	}

	/**
	 * Begin a rotation: generate a new <b>incoming</b> local CA of the kind
	 * (pre-published).
	 */
	public Mono<CaConfig> beginRotation(String kind, String newName) {
		Mono<CaConfig> body = Mono.fromCallable(() -> localCaFactory.create(kind, newName, "incoming")).flatMap(
				p -> caConfigs.save(p.config()).flatMap(saved -> caKeyMaterials.save(p.material()).thenReturn(saved)));
		return tx.transactional(body).single();
	}

	/**
	 * Promote: demote the current active CA to <b>outgoing</b> then promote the
	 * incoming CA to <b>active</b> — in that order so the unique active-per-kind
	 * index is never momentarily violated. No node is offline: both remain trusted.
	 */
	public Mono<Void> promote(String kind) {
		Mono<Void> body = demote(kind, "active", "outgoing").then(promoteFirst(kind, "incoming", "active"));
		return tx.transactional(body).then();
	}

	/**
	 * Drain: move outgoing CAs to <b>expired</b> (dropped from the trusted set).
	 */
	public Mono<Void> drain(String kind) {
		Mono<Void> body = caConfigs.findByCaKind(kind).filter(c -> "outgoing".equals(c.rotationState()))
				.concatMap(c -> caConfigs.save(withState(c, "expired"))).then();
		return tx.transactional(body).then();
	}

	private Mono<Void> demote(String kind, String from, String to) {
		return caConfigs.findByCaKindAndRotationState(kind, from).flatMap(c -> caConfigs.save(withState(c, to))).then();
	}

	private Mono<Void> promoteFirst(String kind, String from, String to) {
		return caConfigs.findByCaKind(kind).filter(c -> from.equals(c.rotationState())).next()
				.switchIfEmpty(Mono.error(new IllegalStateException("no " + from + " " + kind + " CA to promote")))
				.flatMap(c -> caConfigs.save(withState(c, to))).then();
	}

	private static CaConfig withState(CaConfig c, String state) {
		return new CaConfig(c.id(), c.name(), c.caKind(), c.backend(), c.keyReference(), c.algorithm(), state,
				c.origin(), c.version(), c.createdAt(), c.updatedAt());
	}
}
