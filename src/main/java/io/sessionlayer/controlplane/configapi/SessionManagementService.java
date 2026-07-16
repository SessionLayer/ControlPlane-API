package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * Read + teardown for RUNTIME SSH sessions ({@code runtime.ssh_session}, Design
 * §12A). List/get expose the decision snapshot; terminate reuses the S10
 * top-tier {@code Lock} deny path (§8.3/§8.4) rather than mutating session
 * state. The Gateway owns the session lifecycle, so this never writes the
 * {@code ssh_session} row.
 */
@Service
public class SessionManagementService {

	// Bounded so a terminate is a decisive teardown, not a standing ban: once it
	// expires the identity may reconnect under unchanged policy (§8.4).
	private static final int TERMINATE_TTL_SECONDS = 60;

	private final SshSessionRepository sessions;
	private final CursorPages cursorPages;
	private final AccessLockRepository accessLocks;
	private final LockFeedHub lockFeedHub;
	private final AuditWriter audit;
	private final TransactionalOperator tx;
	private final ObjectMapper objectMapper;

	public SessionManagementService(SshSessionRepository sessions, CursorPages cursorPages,
			AccessLockRepository accessLocks, LockFeedHub lockFeedHub, AuditWriter audit, TransactionalOperator tx,
			ObjectMapper objectMapper) {
		this.sessions = sessions;
		this.cursorPages = cursorPages;
		this.accessLocks = accessLocks;
		this.lockFeedHub = lockFeedHub;
		this.audit = audit;
		this.tx = tx;
		this.objectMapper = objectMapper;
	}

	public Mono<CursorPages.Page<SshSession>> list(String cursor, Integer limit, String identity, UUID nodeId,
			String accessModel, Boolean activeOnly) {
		Criteria criteria = Criteria.empty();
		if (identity != null) {
			criteria = criteria.and("identity").is(identity);
		}
		if (nodeId != null) {
			criteria = criteria.and("nodeId").is(nodeId);
		}
		if (accessModel != null) {
			criteria = criteria.and("accessModel").is(accessModel);
		}
		if (Boolean.TRUE.equals(activeOnly)) {
			criteria = criteria.and("endedAt").isNull();
		}
		return cursorPages.page(SshSession.class, criteria, cursor, limit, SshSession::id);
	}

	public Mono<SshSession> get(UUID id) {
		return sessions.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("session", id)));
	}

	public Mono<SshSession> terminate(UUID id, String actor, String reason) {
		return get(id).flatMap(session -> {
			Instant now = Instant.now();
			Instant expiresAt = now.plusSeconds(TERMINATE_TTL_SECONDS);
			// The wire Lock selector has no per-session facet, so teardown is
			// identity-scoped (it also affects that identity's other live sessions).
			var selector = objectMapper.createObjectNode();
			selector.putArray("identities").add(session.identity());
			String lockReason = reason == null || reason.isBlank() ? "operator terminate" : reason;
			AccessLock lock = AccessLock.create(selector, "strict", TERMINATE_TTL_SECONDS, expiresAt, lockReason,
					actor);
			Map<String, String> detail = Map.of("identity", session.identity());
			// Persist lock + audit atomically; push the deny only AFTER commit so a
			// Gateway can never be handed a lock a rolled-back transaction never stored.
			Mono<AccessLock> persisted = tx
					.transactional(
							accessLocks.save(lock)
									.flatMap(
											saved -> audit
													.record(actor, session.id().toString(), "session.terminate",
															"success", session.id(), session.nodeId(), detail)
													.thenReturn(saved)));
			return persisted.doOnNext(lockFeedHub::publishAdded).thenReturn(session);
		});
	}
}
