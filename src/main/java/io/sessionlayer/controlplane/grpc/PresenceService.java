package io.sessionlayer.controlplane.grpc;

import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Presence;
import io.sessionlayer.controlplane.data.runtime.PresenceRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.grpc.v1.PresenceGrpc;
import io.sessionlayer.controlplane.grpc.v1.PresenceHeartbeatRequest;
import io.sessionlayer.controlplane.grpc.v1.PresenceHeartbeatResponse;
import io.sessionlayer.controlplane.grpc.v1.PresenceReleaseRequest;
import io.sessionlayer.controlplane.grpc.v1.PresenceReleaseResponse;
import io.sessionlayer.controlplane.ha.HaProperties;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.time.Instant;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * The HA ownership WRITE path (Design §10.2/§10.3; FR-HA-2/5). A Gateway that
 * holds a node's live agent control channel heartbeats here to claim/refresh
 * ownership, and releases it on drain so a standby claims immediately. This is
 * the mTLS-required tier: the OWNER is the authenticated mTLS peer — never a
 * request field — so a Gateway can only claim, refresh, or release ownership
 * for itself. Auto-binds via the {@code List<BindableService>} injection in
 * {@code GrpcMtlsServer}.
 *
 * <p>
 * Ownership is recorded and returned as the owner's
 * {@code gateway_identity.name}, resolved from the authenticated
 * {@code gatewayId}. The name — not the id — is the routing/relay key the rest
 * of the HA plane speaks: the read path ({@code Authorize}
 * {@code owning_gateway_id}) hands it back so the ingress can compare it to its
 * own name, the owner subscribes to {@code sl.dialback.<name>}, and its
 * agent-facing serverAuth leaf carries that name as its dNSName (S14). Storing
 * the id here would make every cross-Gateway route miss.
 *
 * <p>
 * The monotonic {@code nonce} is the anti-stale-ownership fencing token. This
 * service never writes a lower nonce: a takeover is always {@code current + 1},
 * and a concurrent claim that trips the {@code @Version} optimistic lock (or
 * the {@code presence_nonce_monotonic} DB trigger backstop) is <b>rejected as a
 * failed RPC</b> — the caller fails closed to "not owner" rather than
 * clobbering a higher nonce (FR-HA-5, per the {@code Presence} contract).
 */
@Service
public class PresenceService extends PresenceGrpc.PresenceImplBase {

	private final PresenceRepository presence;
	private final GatewayIdentityRepository gatewayIdentities;
	private final HaProperties haProperties;
	private final MtlsProperties mtlsProperties;
	private final TransactionalOperator tx;

	public PresenceService(PresenceRepository presence, GatewayIdentityRepository gatewayIdentities,
			HaProperties haProperties, MtlsProperties mtlsProperties, TransactionalOperator tx) {
		this.presence = presence;
		this.gatewayIdentities = gatewayIdentities;
		this.haProperties = haProperties;
		this.mtlsProperties = mtlsProperties;
		this.tx = tx;
	}

	@Override
	public void heartbeat(PresenceHeartbeatRequest request, StreamObserver<PresenceHeartbeatResponse> observer) {
		// Read the authenticated peer on the gRPC handler thread (the Context is not
		// carried onto the reactive schedulers), exactly as AuthorizationService does.
		UUID caller = MtlsContext.peer().gatewayId();
		Mono<PresenceHeartbeatResponse> result = heartbeat(caller, request.getNodeId(), request.getGatewayAddr());
		ReactiveBridge.forward(result, observer, mtlsProperties.getRpcTimeout(), "Presence.Heartbeat");
	}

	@Override
	public void release(PresenceReleaseRequest request, StreamObserver<PresenceReleaseResponse> observer) {
		UUID caller = MtlsContext.peer().gatewayId();
		Mono<PresenceReleaseResponse> result = release(caller, request.getNodeId());
		ReactiveBridge.forward(result, observer, mtlsProperties.getRpcTimeout(), "Presence.Release");
	}

	private Mono<PresenceHeartbeatResponse> heartbeat(UUID caller, String nodeIdField, String gatewayAddr) {
		if (caller == null) {
			// A non-Gateway (e.g. agent) mTLS peer cannot own a node — fail closed.
			return Mono.error(new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
					"gateway identity required"));
		}
		UUID nodeId = parseUuid(nodeIdField);
		if (nodeId == null) {
			return Mono.error(
					new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT, "invalid node id"));
		}
		if (gatewayAddr == null || gatewayAddr.isBlank()) {
			// gateway_addr is NOT NULL and is what a peer ingress is told to expect the
			// relay dial-back from; a claim without one is meaningless.
			return Mono.error(new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
					"gateway address required"));
		}
		return ownerName(caller).flatMap(owner -> {
			Instant now = Instant.now();
			Instant staleBefore = now.minus(haProperties.getPresenceStaleness());

			Mono<Presence> applied = presence.findById(nodeId).flatMap(existing -> {
				if (owner.equals(existing.owningGateway())) {
					return refresh(existing, gatewayAddr, now);
				}
				if (existing.lastSeen().isBefore(staleBefore)) {
					return takeover(existing, owner, gatewayAddr, now);
				}
				// A fresh owner that is not us: standby — no write, return the authoritative
				// owner so the caller learns it is not the owner.
				return Mono.just(existing);
			}).switchIfEmpty(claimFresh(nodeId, owner, gatewayAddr, now));

			return tx.transactional(applied)
					// A concurrent claim tripped the optimistic lock or the monotonic trigger:
					// the write was rejected, so fail the RPC (the Gateway treats that as "not
					// owner"). Never retry a lower-nonce write (FR-HA-5).
					.onErrorMap(PresenceService::isContention, contended -> contention())
					.map(state -> toResponse(state, owner));
		});
	}

	private Mono<PresenceReleaseResponse> release(UUID caller, String nodeIdField) {
		if (caller == null) {
			return Mono.error(new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
					"gateway identity required"));
		}
		UUID nodeId = parseUuid(nodeIdField);
		if (nodeId == null) {
			return Mono.error(
					new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT, "invalid node id"));
		}
		return ownerName(caller).flatMap(owner -> {
			Mono<Boolean> released = presence.findById(nodeId).flatMap(existing -> {
				if (!owner.equals(existing.owningGateway())) {
					return Mono.just(false); // idempotent no-op: caller is not the recorded owner
				}
				// Relinquish by ageing last_seen far into the past: owning_gateway is NOT NULL
				// so it cannot be cleared, and the nonce must not decrease — a stale last_seen
				// is the release signal, so the next heartbeat from any standby claims
				// (nonce+1)
				// immediately, closing the planned-drain failover window while preserving the
				// monotonic nonce chain.
				Presence relinquished = new Presence(existing.nodeId(), existing.owningGateway(),
						existing.gatewayAddr(), existing.nonce(), existing.nonceId(), Instant.EPOCH, existing.version(),
						existing.updatedAt());
				return presence.save(relinquished).thenReturn(true);
			}).defaultIfEmpty(false);

			return tx.transactional(released)
					// Lost the row to a concurrent claim: we did not relinquish (someone else now
					// owns it), so report not-released — fail-safe and truthful.
					.onErrorResume(PresenceService::isContention, contended -> Mono.just(false))
					.map(done -> PresenceReleaseResponse.newBuilder().setReleased(done).build());
		});
	}

	// The owner is the AUTHENTICATED peer's gateway_identity.name (the HA routing
	// key), resolved from its gatewayId — never a request field. An unknown
	// identity fails closed (cannot happen for a peer the interceptor
	// authenticated,
	// but a deleted/revoked identity must not own a node).
	private Mono<String> ownerName(UUID caller) {
		return gatewayIdentities.findById(caller).map(GatewayIdentity::name)
				.switchIfEmpty(Mono.error(new GatewayRequestException(GatewayRequestException.Reason.UNAUTHENTICATED,
						"gateway identity unknown")));
	}

	private Mono<Presence> refresh(Presence existing, String gatewayAddr, Instant now) {
		Presence refreshed = new Presence(existing.nodeId(), existing.owningGateway(), gatewayAddr, existing.nonce(),
				existing.nonceId(), now, existing.version(), existing.updatedAt());
		return presence.save(refreshed);
	}

	private Mono<Presence> takeover(Presence existing, String owner, String gatewayAddr, Instant now) {
		Presence claimed = new Presence(existing.nodeId(), owner, gatewayAddr, existing.nonce() + 1, UUID.randomUUID(),
				now, existing.version(), existing.updatedAt());
		return presence.save(claimed);
	}

	private Mono<Presence> claimFresh(UUID nodeId, String owner, String gatewayAddr, Instant now) {
		return presence.save(Presence.create(nodeId, owner, gatewayAddr, 1L, UUID.randomUUID(), now));
	}

	private static GatewayRequestException contention() {
		return new GatewayRequestException(GatewayRequestException.Reason.FAILED_PRECONDITION,
				"presence ownership contended");
	}

	private static PresenceHeartbeatResponse toResponse(Presence state, String caller) {
		return PresenceHeartbeatResponse.newBuilder().setOwningGatewayId(state.owningGateway())
				.setGatewayAddr(state.gatewayAddr()).setNonce(state.nonce()).setNonceId(state.nonceId().toString())
				.setLastSeenEpochMs(state.lastSeen().toEpochMilli())
				.setIsSelfOwner(caller.equals(state.owningGateway())).build();
	}

	private static boolean isContention(Throwable error) {
		return error instanceof OptimisticLockingFailureException || error instanceof DataIntegrityViolationException;
	}

	private static UUID parseUuid(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		try {
			return UUID.fromString(value);
		} catch (IllegalArgumentException notAUuid) {
			return null;
		}
	}
}
