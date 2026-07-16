package io.sessionlayer.controlplane.recording;

import io.r2dbc.spi.Row;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformScope;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.recording.RecordingStore.PresignedAccess;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * Recording read + signed-URL replay/export (Part C, FR-AUD-5/FR-PADM-2). The
 * CP <b>never proxies recording bytes and cannot decrypt them</b>:
 * replay/export return a short-lived, single-object presigned GET (via the
 * pluggable {@link RecordingStore}) to the still-customer-key-encrypted object,
 * and every access is platform-RBAC-<b>scope</b>-gated + audited. List/get
 * expose only metadata (never bytes, never key material).
 */
@Service
public class RecordingAccessService {

	private final RecordingRefRepository recordings;
	private final SshSessionRepository sessions;
	private final NodeRepository nodes;
	private final RecordingStore recordingStore;
	private final PlatformAuthorization platformAuthorization;
	private final AuditEventStore audit;
	private final DatabaseClient db;
	private final RecordingAccessProperties properties;

	public RecordingAccessService(RecordingRefRepository recordings, SshSessionRepository sessions,
			NodeRepository nodes, RecordingStore recordingStore, PlatformAuthorization platformAuthorization,
			AuditEventStore audit, DatabaseClient db, RecordingAccessProperties properties) {
		this.recordings = recordings;
		this.sessions = sessions;
		this.nodes = nodes;
		this.recordingStore = recordingStore;
		this.platformAuthorization = platformAuthorization;
		this.audit = audit;
		this.db = db;
		this.properties = properties;
	}

	// The identity/node filters live on ssh_session, so list joins recording_ref to
	// its 1:1 session; keyset over recording_ref.id (UUIDv7, time-ordered) mirrors
	// CursorPages so a page is stable under concurrent inserts.
	public Mono<CursorPages.Page<RecordingSummary>> list(String cursor, Integer limit, UUID sessionId, String identity,
			UUID nodeId) {
		int pageSize = CursorPages.clamp(limit);
		UUID after = CursorPages.decodeCursor(cursor);
		StringBuilder sql = new StringBuilder(
				"""
						SELECT r.id, r.session_id, r.encryption_key_ref, r.hash_chain_head, r.worm_mode, r.size_bytes, \
						r.retention_until, r.legal_hold, r.status, r.format, r.pruned_at, r.created_at, \
						s.identity AS s_identity, s.node_id AS s_node_id, s.started_at AS s_started_at, s.ended_at AS s_ended_at \
						FROM runtime.recording_ref r JOIN runtime.ssh_session s ON s.id = r.session_id WHERE 1 = 1""");
		Map<String, Object> binds = new LinkedHashMap<>();
		if (sessionId != null) {
			sql.append(" AND r.session_id = :sessionId");
			binds.put("sessionId", sessionId);
		}
		if (identity != null) {
			sql.append(" AND s.identity = :identity");
			binds.put("identity", identity);
		}
		if (nodeId != null) {
			sql.append(" AND s.node_id = :nodeId");
			binds.put("nodeId", nodeId);
		}
		if (after != null) {
			sql.append(" AND r.id > :after");
			binds.put("after", after);
		}
		sql.append(" ORDER BY r.id ASC LIMIT :limit");
		binds.put("limit", pageSize + 1);

		DatabaseClient.GenericExecuteSpec spec = db.sql(sql.toString());
		for (Map.Entry<String, Object> bind : binds.entrySet()) {
			spec = spec.bind(bind.getKey(), bind.getValue());
		}
		return spec.map((row, meta) -> mapRow(row)).all().collectList().map(rows -> paginate(rows, pageSize));
	}

	public Mono<RecordingSummary> get(UUID recordingId) {
		return loadRef(recordingId).flatMap(ref -> sessions.findById(ref.sessionId())
				.map(session -> RecordingSummary.of(ref, session)).defaultIfEmpty(RecordingSummary.of(ref, null)));
	}

	public Mono<PresignedAccess> replay(PlatformSubject subject, UUID recordingId) {
		return issue(subject, recordingId, PlatformPermissions.RECORDING_REPLAY, "recording.replay");
	}

	public Mono<PresignedAccess> export(PlatformSubject subject, UUID recordingId) {
		return issue(subject, recordingId, PlatformPermissions.RECORDING_EXPORT, "recording.export");
	}

	// Replay/export are identical but for the permission + audited action. A caller
	// holding NEITHER a scoped nor unscoped grant is denied BEFORE any recording
	// lookup, so an unprivileged caller gets no 404/409/403 existence oracle and
	// the
	// probe is still audited. Denial (coarse or out-of-scope) completes EMPTY so
	// the
	// controller renders a bodiless 403 (the platform-RBAC no-disclosure idiom);
	// the
	// scoped deny is audited by authorize(). Among permission-holders, distinct
	// 404/409/403 is accepted (UUIDv7 ids + contract-documented).
	private Mono<PresignedAccess> issue(PlatformSubject subject, UUID recordingId, String permission,
			String auditAction) {
		return platformAuthorization.resolveScopeGrant(subject, permission).flatMap(grant -> {
			if (!grant.granted()) {
				return audit
						.record(subject.identity(), recordingId.toString(), auditAction, "denied", null, null,
								Map.of("reason", "not_granted"))
						.onErrorResume(e -> Mono.empty()).then(Mono.<PresignedAccess>empty());
			}
			return loadRef(recordingId)
					.flatMap(ref -> sessions.findById(ref.sessionId()).flatMap(session -> nodeLabels(session).flatMap(
							labels -> authorizeAndIssue(subject, permission, auditAction, ref, session, labels))));
		});
	}

	private Mono<PresignedAccess> authorizeAndIssue(PlatformSubject subject, String permission, String auditAction,
			RecordingRef ref, SshSession session, Map<String, String> labels) {
		PlatformScope scope = new PlatformScope(labels, session.identity(), Instant.now());
		return platformAuthorization.authorize(subject, permission, scope).flatMap(decision -> {
			if (!decision.allowed()) {
				return Mono.empty();
			}
			// Only a replayable object gets a URL, and this is checked AFTER authorize so
			// an out-of-scope caller learns nothing about the recording's state: a pruned
			// object is erased; a still-recording or failed capture has no complete object.
			// finalized + truncated stay replayable.
			if (ref.prunedAt() != null) {
				return Mono.error(ApiProblemException.conflict("recording object has been erased"));
			}
			if ("recording".equals(ref.status()) || "failed".equals(ref.status())) {
				return Mono.error(
						ApiProblemException.conflict("recording is not replayable (status " + ref.status() + ")"));
			}
			return recordingStore.presignDownload(ref.objectKey(), properties.getSignedUrlTtl())
					.flatMap(access -> auditAccess(subject, ref, session, auditAction).thenReturn(access));
		});
	}

	private Mono<Map<String, String>> nodeLabels(SshSession session) {
		if (session.nodeId() == null) {
			return Mono.just(Map.of());
		}
		return nodes.findById(session.nodeId()).map(Node::resolvedLabels).map(RecordingAccessService::labels)
				.defaultIfEmpty(Map.of());
	}

	private Mono<Void> auditAccess(PlatformSubject subject, RecordingRef ref, SshSession session, String action) {
		Map<String, String> detail = new LinkedHashMap<>();
		detail.put("identity", session.identity());
		if (ref.wormMode() != null) {
			detail.put("worm_mode", ref.wormMode());
		}
		return audit.record(subject.identity(), ref.id().toString(), action, "success", ref.sessionId(),
				session.nodeId(), detail);
	}

	private Mono<RecordingRef> loadRef(UUID recordingId) {
		return recordings.findById(recordingId)
				.switchIfEmpty(Mono.error(ApiProblemException.notFound("recording", recordingId)));
	}

	private static Map<String, String> labels(JsonNode resolvedLabels) {
		if (resolvedLabels == null || !resolvedLabels.isObject()) {
			return Map.of();
		}
		Map<String, String> labels = new LinkedHashMap<>();
		for (Map.Entry<String, JsonNode> entry : resolvedLabels.properties()) {
			if (entry.getValue().isString()) {
				labels.put(entry.getKey(), entry.getValue().stringValue());
			}
		}
		return labels;
	}

	private CursorPages.Page<RecordingSummary> paginate(List<RecordingSummary> rows, int pageSize) {
		boolean more = rows.size() > pageSize;
		List<RecordingSummary> items = more ? new ArrayList<>(rows.subList(0, pageSize)) : rows;
		String next = more ? CursorPages.encodeCursor(items.get(items.size() - 1).id()) : null;
		return new CursorPages.Page<>(items, next);
	}

	private static RecordingSummary mapRow(Row row) {
		return new RecordingSummary(row.get("id", UUID.class), row.get("session_id", UUID.class),
				row.get("s_identity", String.class), row.get("s_node_id", UUID.class), row.get("format", String.class),
				row.get("status", String.class), row.get("worm_mode", String.class), row.get("size_bytes", Long.class),
				row.get("hash_chain_head", String.class), row.get("encryption_key_ref", String.class),
				Boolean.TRUE.equals(row.get("legal_hold", Boolean.class)),
				instant(row.get("retention_until", OffsetDateTime.class)),
				instant(row.get("pruned_at", OffsetDateTime.class)),
				instant(row.get("s_started_at", OffsetDateTime.class)),
				instant(row.get("s_ended_at", OffsetDateTime.class)),
				instant(row.get("created_at", OffsetDateTime.class)));
	}

	private static Instant instant(OffsetDateTime value) {
		return value == null ? null : value.toInstant();
	}
}
