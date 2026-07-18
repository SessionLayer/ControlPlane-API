package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformDecision;
import io.sessionlayer.controlplane.platform.PlatformScope;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.recording.RecordingStore.PresignedAccess;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.ApiProblemType;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.RowsFetchSpec;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tools.jackson.databind.node.JsonNodeFactory;

/**
 * Proves the {@link RecordingStore} seam is real (owner requirement): the CP's
 * replay + governance-delete paths run entirely through the pluggable interface
 * — swapping in a second {@link InMemoryRecordingStore} double — never against
 * the concrete S3 store. Also pins the WORM rules the double enforces
 * (compliance un-deletable, legal hold + already-pruned blocked) and the
 * ≥12-month retention default.
 */
class RecordingStoreSeamTest {

	private final RecordingRefRepository recordings = mock(RecordingRefRepository.class);
	private final SshSessionRepository sessions = mock(SshSessionRepository.class);
	private final NodeRepository nodes = mock(NodeRepository.class);
	private final PlatformAuthorization authorization = mock(PlatformAuthorization.class);
	private final AuditEventStore audit = mock(AuditEventStore.class);
	private final DatabaseClient db = mock(DatabaseClient.class);
	private final InMemoryRecordingStore store = new InMemoryRecordingStore();

	private final RecordingAccessService access = new RecordingAccessService(recordings, sessions, nodes, store,
			authorization, audit, db, new RecordingAccessProperties());
	private final RecordingRetentionService retention = new RecordingRetentionService(recordings, sessions, store,
			audit, db);

	private final PlatformSubject admin = new PlatformSubject("admin", List.of());

	private RecordingRef governanceRef(UUID id, UUID sessionId, String objectKey) {
		return RecordingRef.begin(id, sessionId, objectKey, "kms://customer-1", "governance",
				Instant.now().plusSeconds(86_400));
	}

	private RecordingRef finalizedRef(UUID id, UUID sessionId, String objectKey) {
		return governanceRef(id, sessionId, objectKey).finalized(null, null, null, null, "finalized");
	}

	private SshSession session(UUID sessionId, UUID nodeId) {
		return sessionStartedAt(sessionId, nodeId, Instant.now());
	}

	private SshSession sessionStartedAt(UUID sessionId, UUID nodeId, Instant startedAt) {
		SshSession base = SshSession.create("alice", null, null, "deploy", null, null, "standing", List.of("shell"),
				null, null, null, null, null, null, startedAt);
		return new SshSession(sessionId, base.identity(), nodeId, null, base.principal(), null, null,
				base.accessModel(), base.capabilities(), null, null, null, null, null, null, startedAt, null, null,
				null, null, null);
	}

	private Node nodeWithLabels(String key, String value) {
		return Node.create("node-" + UUID.randomUUID(), null, JsonNodeFactory.instance.objectNode().put(key, value),
				"agent", "active", "healthy", null, null);
	}

	@Test
	void replayIssuesTheDoublesSignedUrlThroughTheInterface() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		Node node = nodeWithLabels("env", "prod");
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		store.seed(objectKey);
		when(recordings.findById(id)).thenReturn(Mono.just(finalizedRef(id, sessionId, objectKey)));
		when(sessions.findById(sessionId)).thenReturn(Mono.just(session(sessionId, node.id())));
		when(nodes.findById(node.id())).thenReturn(Mono.just(node));
		when(authorization.resolveScopeGrant(any(), any()))
				.thenReturn(Mono.just(PlatformAuthorization.ScopeGrant.all()));
		when(authorization.authorize(any(), any(), any()))
				.thenReturn(Mono.just(new PlatformDecision(true, PlatformDecision.Reason.ALLOWED, null, null)));
		when(audit.record(any(AuditRecord.class))).thenReturn(Mono.empty());

		PresignedAccess presigned = access.replay(admin, id).block();

		assertThat(presigned.url()).isEqualTo(InMemoryRecordingStore.BASE_URL + objectKey);
		assertThat(presigned.method()).isEqualTo("GET");
		long now = Instant.now().getEpochSecond();
		assertThat(presigned.expiresAtEpochSeconds()).isBetween(now + 240, now + 360);
		// S20: the replay audit carries the session-scoped dimensions (correlation_id,
		// access_model, node_labels) so a (node-label-scoped) correlation_id search
		// reaches the replay — not just the connect (F-audit-chainscope-1).
		ArgumentCaptor<AuditRecord> auditRecord = ArgumentCaptor.forClass(AuditRecord.class);
		verify(audit).record(auditRecord.capture());
		AuditRecord recorded = auditRecord.getValue();
		assertThat(recorded.actor()).isEqualTo("admin");
		assertThat(recorded.subject()).isEqualTo(id.toString());
		assertThat(recorded.action()).isEqualTo("recording.replay");
		assertThat(recorded.outcome()).isEqualTo("success");
		assertThat(recorded.sessionId()).isEqualTo(sessionId);
		assertThat(recorded.correlationId()).isEqualTo(sessionId); // standing session
		assertThat(recorded.accessModel()).isEqualTo("standing");
		assertThat(recorded.nodeLabels()).containsEntry("env", "prod");
	}

	// F-recording-worm-version-1 (HIGH): replay/export pin the FINALIZED object
	// version, so a later shadow PUT to the same key (by a compromised CP/Gateway)
	// can't be served (§15 crown-jewels: Object Lock protects a version, not a
	// key).
	@Test
	void replayPinsTheFinalizedObjectVersion() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		Node node = nodeWithLabels("env", "prod");
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		String versionId = "v-FINALIZED-0001";
		store.seed(objectKey);
		RecordingRef finalized = governanceRef(id, sessionId, objectKey).finalized("sha256:head", "sha256:digest",
				versionId, 10L, "finalized");
		when(recordings.findById(id)).thenReturn(Mono.just(finalized));
		when(sessions.findById(sessionId)).thenReturn(Mono.just(session(sessionId, node.id())));
		when(nodes.findById(node.id())).thenReturn(Mono.just(node));
		when(authorization.resolveScopeGrant(any(), any()))
				.thenReturn(Mono.just(PlatformAuthorization.ScopeGrant.all()));
		when(authorization.authorize(any(), any(), any()))
				.thenReturn(Mono.just(new PlatformDecision(true, PlatformDecision.Reason.ALLOWED, null, null)));
		when(audit.record(any(AuditRecord.class))).thenReturn(Mono.empty());

		PresignedAccess presigned = access.replay(admin, id).block();

		// The GET is PINNED to the finalized version id (a null/unversioned GET would
		// serve whatever is "current" — the shadow-PUT vector this fix closes).
		assertThat(presigned.url()).isEqualTo(InMemoryRecordingStore.BASE_URL + objectKey + "?versionId=" + versionId);
	}

	// F-recording-scope-time-1 (MEDIUM): the replay scope's time facet is evaluated
	// against the SESSION's time (which recordings), not the wall-clock at request
	// time
	// — matching audit-search's occurred_at, so an incident-window-scoped auditor
	// can't
	// replay an out-of-window session during the window.
	@Test
	void replayScopeTimeIsTheSessionTimeNotWallClock() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		Node node = nodeWithLabels("env", "prod");
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		Instant sessionStart = Instant.now().minus(java.time.Duration.ofDays(90));
		store.seed(objectKey);
		when(recordings.findById(id)).thenReturn(Mono.just(finalizedRef(id, sessionId, objectKey)));
		when(sessions.findById(sessionId)).thenReturn(Mono.just(sessionStartedAt(sessionId, node.id(), sessionStart)));
		when(nodes.findById(node.id())).thenReturn(Mono.just(node));
		when(authorization.resolveScopeGrant(any(), any()))
				.thenReturn(Mono.just(PlatformAuthorization.ScopeGrant.all()));
		ArgumentCaptor<PlatformScope> scope = ArgumentCaptor.forClass(PlatformScope.class);
		when(authorization.authorize(any(), any(), scope.capture()))
				.thenReturn(Mono.just(new PlatformDecision(true, PlatformDecision.Reason.ALLOWED, null, null)));
		when(audit.record(any(AuditRecord.class))).thenReturn(Mono.empty());

		access.replay(admin, id).block();

		// The scope's evaluation time is the session start (90 days ago), not ~now.
		assertThat(scope.getValue().at()).isEqualTo(sessionStart);
	}

	// F-recording-prune-confirm-1 (MEDIUM): a FAILED object delete must NOT report
	// a
	// false erasure — the claim is rolled back (so the row is re-pruned) and the
	// failure is audited, and the error surfaces (never a false 204).
	@Test
	void aFailedObjectDeleteRollsBackTheClaimAndAuditsTheFailure() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		RecordingStore failing = mock(RecordingStore.class);
		when(failing.deleteObject(any(), any())).thenReturn(Mono.error(new IllegalStateException("object store down")));
		RecordingRetentionService failingRetention = new RecordingRetentionService(recordings, sessions, failing, audit,
				db);
		when(recordings.findById(id)).thenReturn(Mono.just(governanceRef(id, sessionId, objectKey)));
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		stubClaim(objectKey, "governance", sessionId);

		// The error is surfaced (no false success), not swallowed into a 204.
		StepVerifier.create(failingRetention.governanceDelete("custodian", id)).expectError(IllegalStateException.class)
				.verify();

		// The delete was attempted, the failure was audited (outcome "error"), and a
		// second db.sql (the compensating UNCLAIM) ran so the row is re-selectable.
		verify(failing).deleteObject(eq(objectKey), eq("governance"));
		verify(audit).record(eq("custodian"), eq(id.toString()), eq("recording.delete"), eq("error"), eq(sessionId),
				any(), any());
		verify(db, org.mockito.Mockito.atLeast(2)).sql(anyString());
	}

	@Test
	void governanceDeleteRemovesTheObjectThroughTheInterfaceAndAudits() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		store.seed(objectKey);
		when(recordings.findById(id)).thenReturn(Mono.just(governanceRef(id, sessionId, objectKey)));
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		stubClaim(objectKey, "governance", sessionId); // the atomic claim UPDATE ... RETURNING

		retention.governanceDelete("custodian", id).block();

		assertThat(store.contains(objectKey)).isFalse();
		verify(audit).record(eq("custodian"), eq(id.toString()), eq("recording.delete"), eq("success"), eq(sessionId),
				any(), any());
	}

	// Stub the DatabaseClient atomic-claim UPDATE...RETURNING to yield one claimed
	// row
	// so the delete path proceeds through the RecordingStore double. The mapper is
	// the
	// real (row,meta)->Claimed function; a hand-rolled RowsFetchSpec avoids nested
	// Mockito stubbing during answer evaluation.
	@SuppressWarnings("unchecked")
	private void stubClaim(String objectKey, String wormMode, UUID sessionId) {
		DatabaseClient.GenericExecuteSpec spec = mock(DatabaseClient.GenericExecuteSpec.class);
		when(db.sql(anyString())).thenReturn(spec);
		when(spec.bind(anyString(), any())).thenReturn(spec);
		// The compensating UNCLAIM UPDATE (on a failed object delete) runs
		// fetch().rowsUpdated().
		org.springframework.r2dbc.core.FetchSpec<java.util.Map<String, Object>> fetchSpec = mock(
				org.springframework.r2dbc.core.FetchSpec.class);
		when(spec.fetch()).thenReturn(fetchSpec);
		when(fetchSpec.rowsUpdated()).thenReturn(Mono.just(1L));
		Row row = mock(Row.class);
		when(row.get("object_key", String.class)).thenReturn(objectKey);
		when(row.get("worm_mode", String.class)).thenReturn(wormMode);
		when(row.get("session_id", UUID.class)).thenReturn(sessionId);
		when(spec.map(any(BiFunction.class))).thenAnswer(invocation -> {
			BiFunction<Row, RowMetadata, Object> mapper = invocation.getArgument(0);
			Object claimed = mapper.apply(row, null);
			return new RowsFetchSpec<Object>() {
				@Override
				public Mono<Object> one() {
					return Mono.just(claimed);
				}

				@Override
				public Mono<Object> first() {
					return Mono.just(claimed);
				}

				@Override
				public Flux<Object> all() {
					return Flux.just(claimed);
				}
			};
		});
	}

	@Test
	void complianceObjectIsRefusedAndNeverDeleted() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		store.seed(objectKey);
		RecordingRef compliance = RecordingRef.begin(id, sessionId, objectKey, "kms://customer-1", "compliance",
				Instant.now().plusSeconds(86_400));
		when(recordings.findById(id)).thenReturn(Mono.just(compliance));

		StepVerifier.create(retention.governanceDelete("custodian", id))
				.expectErrorSatisfies(
						error -> assertThat(((ApiProblemException) error).type()).isEqualTo(ApiProblemType.CONFLICT))
				.verify();
		assertThat(store.contains(objectKey)).isTrue();
	}

	@Test
	void legalHeldObjectIsRefusedAndNeverDeleted() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		store.seed(objectKey);
		RecordingRef held = governanceRef(id, sessionId, objectKey).withLegalHold(true, "litigation");
		when(recordings.findById(id)).thenReturn(Mono.just(held));

		StepVerifier.create(retention.governanceDelete("custodian", id))
				.expectErrorSatisfies(
						error -> assertThat(((ApiProblemException) error).type()).isEqualTo(ApiProblemType.CONFLICT))
				.verify();
		assertThat(store.contains(objectKey)).isTrue();
	}

	@Test
	void alreadyPrunedGovernanceDeleteIsAnIdempotentNoOp() {
		UUID id = UUID.randomUUID();
		UUID sessionId = UUID.randomUUID();
		String objectKey = "recordings/" + sessionId + "/" + id + ".cast.enc";
		store.seed(objectKey);
		RecordingRef pruned = governanceRef(id, sessionId, objectKey).pruned("governance", "someone", Instant.now());
		when(recordings.findById(id)).thenReturn(Mono.just(pruned));

		StepVerifier.create(retention.governanceDelete("custodian", id)).verifyComplete();
		assertThat(store.contains(objectKey)).isTrue();
	}

	@Test
	void retentionDefaultIsAtLeastTwelveMonths() {
		assertThat(OperatorSettings.defaults().recordingRetentionDays()).isGreaterThanOrEqualTo(365);
	}

	@Test
	void cpConfigHoldsOnlyTheCustomerPublicKeyNoPrivateKey() {
		// The CP CANNOT decrypt a recording: operator_settings carries only the
		// customer
		// PUBLIC key (DER SPKI); there is no private-/secret-key field anywhere in the
		// config surface, so the replay/export URLs can only ever point at ciphertext.
		List<String> components = java.util.Arrays.stream(OperatorSettings.class.getRecordComponents())
				.map(java.lang.reflect.RecordComponent::getName).toList();
		assertThat(components).contains("recordingCustomerPublicKey");
		assertThat(components).noneMatch(name -> {
			String lower = name.toLowerCase(java.util.Locale.ROOT);
			return lower.contains("privatekey") || lower.contains("privkey") || lower.contains("secretkey");
		});
	}
}
