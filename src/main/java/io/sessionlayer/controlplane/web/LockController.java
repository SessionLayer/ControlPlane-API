package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.LocksApi;
import io.sessionlayer.controlplane.api.model.CreateLockRequest;
import io.sessionlayer.controlplane.api.model.LockList;
import io.sessionlayer.controlplane.api.model.LockResource;
import io.sessionlayer.controlplane.api.model.LockTarget;
import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * The secured REST surface for the incident-response lock resource (Design
 * §8.3; FR-LOCK-1/2). Locks are an <b>API-only</b> runtime resource (never
 * reconciled). Each mutation is platform-RBAC gated ({@code lock:write}) +
 * audited and triggers the actively-pushed {@link LockFeedHub} deny-list;
 * listing needs {@code
 * lock:read}. The generic {@code 403} on an unauthorized/empty subject mirrors
 * {@link AuthController}.
 */
@RestController
public class LockController implements LocksApi {

	private final AccessLockRepository accessLocks;
	private final LockFeedHub lockFeedHub;
	private final AuditWriter audit;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final TransactionalOperator tx;

	public LockController(AccessLockRepository accessLocks, LockFeedHub lockFeedHub, AuditWriter audit,
			PlatformAuthorization platformAuthorization, CurrentAuthentication currentAuthentication,
			TransactionalOperator tx) {
		this.accessLocks = accessLocks;
		this.lockFeedHub = lockFeedHub;
		this.audit = audit;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
		this.tx = tx;
	}

	@Override
	public Mono<ResponseEntity<LockResource>> createLock(Mono<CreateLockRequest> createLockRequest,
			ServerWebExchange exchange) {
		return createLockRequest.flatMap(req -> withPermission(PlatformPermissions.LOCK_WRITE, subject -> {
			// Validate before touching the datastore; an invalid target/TTL/reason is a
			// 400 (LockExceptionHandler), never a persisted or pushed lock.
			LockIngestValidation.checkReason(req.getReason());
			var selector = LockIngestValidation.toSelector(req.getTarget());
			Integer ttlSeconds = LockIngestValidation.normalizeTtl(req.getTtlSeconds());
			Instant now = Instant.now();
			Instant expiresAt = ttlSeconds == null ? null : now.plusSeconds(ttlSeconds);
			AccessLock lock = AccessLock.create(selector, "strict", ttlSeconds, expiresAt, req.getReason(),
					subject.identity());
			Map<String, String> detail = new HashMap<>();
			detail.put("target", LockIngestValidation.summarize(selector));
			detail.put("reason", req.getReason());
			// Persist + audit atomically; publish only AFTER commit so a Gateway can never
			// be pushed a lock that a rolled-back transaction never stored.
			Mono<AccessLock> persisted = tx.transactional(accessLocks.save(lock).flatMap(saved -> audit
					.record(subject.identity(), saved.id().toString(), "lock.create", "success", null, null, detail)
					.thenReturn(saved)));
			return persisted.doOnNext(lockFeedHub::publishAdded)
					.map(saved -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(saved)));
		}));
	}

	@Override
	public Mono<ResponseEntity<LockList>> listLocks(ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.LOCK_READ, subject -> {
			Instant now = Instant.now();
			return accessLocks.findAll().filter(lock -> unexpired(lock, now)).map(LockController::toResource)
					.collectList().map(locks -> ResponseEntity.ok(new LockList(locks)));
		});
	}

	@Override
	public Mono<ResponseEntity<Void>> releaseLock(UUID lockId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.LOCK_WRITE, subject -> {
			// Idempotent: 204 whether or not the lock existed. The removal push is a no-op
			// on a Gateway that never held the id (drops by id), so a double-release is
			// harmless; a release NEVER resurrects an already torn-down session.
			Mono<Void> released = tx.transactional(accessLocks.deleteById(lockId).then(audit.record(subject.identity(),
					lockId.toString(), "lock.release", "success", null, null, Map.of())));
			return released.doOnSuccess(ignored -> lockFeedHub.publishRemoved(lockId))
					.thenReturn(ResponseEntity.noContent().<Void>build());
		});
	}

	private <T> Mono<ResponseEntity<T>> withPermission(String permission,
			Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject()
				.flatMap(subject -> platformAuthorization.authorize(subject, permission, null)
						.flatMap(decision -> decision.allowed()
								? action.apply(subject)
								: Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<T>build())))
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	private static boolean unexpired(AccessLock lock, Instant now) {
		return lock.expiresAt() == null || lock.expiresAt().isAfter(now);
	}

	private static LockResource toResource(AccessLock lock) {
		LockResource resource = new LockResource(lock.id(), toApiTarget(lock.targetSelector()), lock.reason(),
				toOffset(lock.createdAt()));
		resource.setExpiresAt(lock.expiresAt() == null ? null : toOffset(lock.expiresAt()));
		resource.setCreatedBy(lock.createdBy());
		return resource;
	}

	private static LockTarget toApiTarget(JsonNode selector) {
		LockTarget target = new LockTarget();
		if (selector == null || !selector.isObject()) {
			return target;
		}
		target.setIdentities(strings(selector, "identities"));
		target.setGroups(strings(selector, "groups"));
		target.setPrincipals(strings(selector, "principals"));
		target.setNodeLabels(strings(selector, "node_labels"));
		List<UUID> nodeIds = new ArrayList<>();
		for (String value : strings(selector, "node_ids")) {
			nodeIds.add(UUID.fromString(value));
		}
		target.setNodeIds(nodeIds);
		if (selector.path("all").asBoolean(false)) {
			target.setAll(true);
		}
		return target;
	}

	private static List<String> strings(JsonNode selector, String key) {
		List<String> values = new ArrayList<>();
		JsonNode array = selector.get(key);
		if (array != null && array.isArray()) {
			for (JsonNode element : array) {
				if (element.isString()) {
					values.add(element.stringValue());
				}
			}
		}
		return values;
	}

	private static OffsetDateTime toOffset(Instant instant) {
		return instant.atOffset(ZoneOffset.UTC);
	}
}
