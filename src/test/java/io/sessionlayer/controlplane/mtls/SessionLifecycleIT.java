package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.ExtendSessionLeaseRequest;
import io.sessionlayer.controlplane.grpc.v1.ExtendSessionLeaseResponse;
import io.sessionlayer.controlplane.grpc.v1.NotifySessionEndRequest;
import io.sessionlayer.controlplane.grpc.v1.NotifySessionEndResponse;
import io.sessionlayer.controlplane.grpc.v1.SessionEndReason;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Session 25 Part E (CP side) — the exact-lease lifecycle RPCs.
 * {@code NotifySessionEnd} releases the concurrency lease promptly on any
 * teardown (independent of FinalizeRecording), stamps
 * {@code ended_at}/{@code end_reason}, is idempotent, caller-bound (a Gateway
 * can never free another's slot) and race-safe with the finalize path.
 * {@code ExtendSessionLease} re-stamps a live lease's expiry to the
 * SERVER-authoritative window so a RunToTtl session outliving
 * {@code grant_expiry} still occupies its slot; it never shortens a lease and
 * refuses ended sessions / released leases / foreign callers.
 */
class SessionLifecycleIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String SOURCE_IP = "203.0.113.21";

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private SessionLeaseRepository sessionLeases;
	@Autowired
	private AuditEventStore auditStore;

	@Test
	void notifySessionEndReleasesTheLeaseAndStampsTheSessionIdempotently() {
		String identity = "end-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-end-" + unique());
		UUID sessionId = UUID.randomUUID();
		assertThat(authorize(gateway, identity, nodeId, sessionId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(countLive(identity)).isEqualTo(1);

		NotifySessionEndResponse first = notifyEnd(gateway, sessionId, SessionEndReason.SESSION_END_REASON_CLOSED);
		assertThat(first.getReleased()).isTrue();
		assertThat(countLive(identity)).isZero();
		SshSession session = sshSessions.findById(sessionId).block();
		assertThat(session.endedAt()).isNotNull();
		assertThat(session.endReason()).isEqualTo("closed");

		// The lifecycle end joined the session's correlation chain.
		var events = auditStore.search(new AuditQuery(null, identity, "session.end", "success", null, null, null, null,
				null, null, null, Map.of(), null, List.of(), null, 50)).block().items();
		assertThat(events).anySatisfy(e -> assertThat(e.sessionId()).isEqualTo(sessionId));

		// Idempotent repeat: no error, nothing further released, no duplicate audit.
		NotifySessionEndResponse repeat = notifyEnd(gateway, sessionId, SessionEndReason.SESSION_END_REASON_CLOSED);
		assertThat(repeat.getReleased()).isFalse();
		long endEvents = auditStore
				.search(new AuditQuery(null, identity, "session.end", "success", null, null, null, null, null, null,
						null, Map.of(), null, List.of(), null, 50))
				.block().items().stream().filter(e -> sessionId.equals(e.sessionId())).count();
		assertThat(endEvents).isEqualTo(1);
	}

	@Test
	void theEndReasonVocabularyIsStored() {
		String identity = "end-reason-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-endreason-" + unique());
		UUID sessionId = UUID.randomUUID();
		authorize(gateway, identity, nodeId, sessionId);

		notifyEnd(gateway, sessionId, SessionEndReason.SESSION_END_REASON_IDLE_TIMEOUT);
		assertThat(sshSessions.findById(sessionId).block().endReason()).isEqualTo("idle_timeout");
	}

	// The ownership gate: only the session's brokering gateway may end/extend it.
	// A foreign (fully authenticated) Gateway gets the generic denial and
	// releases/extends NOTHING.
	@Test
	void aForeignGatewayIsRefusedAndReleasesNothing() {
		String identity = "foreign-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway owner = enroll("gw-owner-" + unique());
		EnrolledGateway foreign = enroll("gw-foreign-" + unique());
		UUID sessionId = UUID.randomUUID();
		authorize(owner, identity, nodeId, sessionId);

		assertThatThrownBy(() -> notifyEnd(foreign, sessionId, SessionEndReason.SESSION_END_REASON_CLOSED))
				.isInstanceOfSatisfying(StatusRuntimeException.class,
						e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED));
		assertThat(countLive(identity)).isEqualTo(1);
		assertThat(sshSessions.findById(sessionId).block().endedAt()).isNull();

		assertThatThrownBy(() -> extend(foreign, sessionId)).isInstanceOfSatisfying(StatusRuntimeException.class,
				e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED));

		// An unknown session is the SAME generic denial (no existence disclosure).
		assertThatThrownBy(() -> notifyEnd(owner, UUID.randomUUID(), SessionEndReason.SESSION_END_REASON_CLOSED))
				.isInstanceOfSatisfying(StatusRuntimeException.class,
						e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED));
	}

	// The AuthInterceptor tier gate: only Handshake/Negotiate + the two Enroll
	// methods are bootstrap-reachable; EVERY other method — the new lifecycle
	// RPCs included — requires a valid client cert chained to the internal CA. A
	// caller with no client certificate is refused UNAUTHENTICATED before any
	// handler runs (and can therefore never release or extend anything).
	@Test
	void theLifecycleRpcsRequireAClientCertificate() {
		String identity = "nocert-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-nocert-" + unique());
		UUID sessionId = UUID.randomUUID();
		authorize(gateway, identity, nodeId, sessionId);

		SslContext noClientCert = MtlsTestSupport.clientSslContext(caCertificate(), null, null);
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), noClientCert);
		try {
			var stub = AuthorizationGrpc.newBlockingStub(channel);
			assertThatThrownBy(() -> stub.notifySessionEnd(NotifySessionEndRequest.newBuilder()
					.setSessionId(sessionId.toString()).setReason(SessionEndReason.SESSION_END_REASON_CLOSED).build()))
					.isInstanceOfSatisfying(StatusRuntimeException.class,
							e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED));
			assertThatThrownBy(() -> stub.extendSessionLease(
					ExtendSessionLeaseRequest.newBuilder().setSessionId(sessionId.toString()).build()))
					.isInstanceOfSatisfying(StatusRuntimeException.class,
							e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED));
		} finally {
			shutdown(channel);
		}
		// Nothing was released by the refused calls.
		assertThat(countLive(identity)).isEqualTo(1);
	}

	// Race-safety with the recording finalize path (sequential equivalent of the
	// race: finalize's end-stamp + lease release already happened; the notify is
	// a harmless no-op).
	@Test
	void notifyAfterTheFinalizePathAlreadyEndedTheSessionIsANoOp() {
		String identity = "race-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-race-" + unique());
		UUID sessionId = UUID.randomUUID();
		authorize(gateway, identity, nodeId, sessionId);

		// Exactly what RecordingRegistrationService.endSession does at finalize.
		Instant now = Instant.now();
		SshSession session = sshSessions.findById(sessionId).block();
		sshSessions.save(session.ended(now, "closed")).block();
		sessionLeases.releaseBySessionId(sessionId, now).block();

		NotifySessionEndResponse response = notifyEnd(gateway, sessionId, SessionEndReason.SESSION_END_REASON_ERROR);
		assertThat(response.getReleased()).isFalse();
		// The finalize-side reason stands (first writer wins; the repeat is a no-op).
		assertThat(sshSessions.findById(sessionId).block().endReason()).isEqualTo("closed");
	}

	@Test
	void extendRestampsALeaseThatWouldHaveExpiredSoItKeepsCounting() {
		String identity = "extend-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-extend-" + unique());
		UUID sessionId = UUID.randomUUID();
		authorize(gateway, identity, nodeId, sessionId);

		// Simulate a RunToTtl session that outlived grant_expiry: its lease window
		// has lapsed (unreleased but expired), so it no longer counts.
		db.sql("UPDATE runtime.session_lease SET expires_at = now() - interval '1 second' WHERE session_id = :sid")
				.bind("sid", sessionId).fetch().rowsUpdated().block();
		assertThat(countLive(identity)).isZero();

		ExtendSessionLeaseResponse response = extend(gateway, sessionId);
		long delta = response.getExpiresAtEpochSeconds() - Instant.now().getEpochSecond();
		assertThat(delta).isBetween(850L, 910L); // the PT15M server-authoritative window

		// The still-running session occupies its slot again (no under-count).
		assertThat(countLive(identity)).isEqualTo(1);
		SessionLease lease = sessionLeases.findBySessionId(sessionId).block();
		assertThat(lease.expiresAt().getEpochSecond()).isEqualTo(response.getExpiresAtEpochSeconds());
	}

	// The re-stamp can only EXTEND the counted window (GREATEST): an early call
	// against a lease with more remaining life than the extension window never
	// shortens it (which would silently under-count later).
	@Test
	void extendNeverShortensALease() {
		String identity = "extend-long-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-extlong-" + unique());
		UUID sessionId = UUID.randomUUID();
		authorize(gateway, identity, nodeId, sessionId);

		Instant before = sessionLeases.findBySessionId(sessionId).block().expiresAt(); // grant TTL, 1h out
		extend(gateway, sessionId);
		Instant after = sessionLeases.findBySessionId(sessionId).block().expiresAt();
		assertThat(after).isEqualTo(before); // 1h remaining > the 15m window — untouched
	}

	@Test
	void extendIsRefusedForAnEndedSessionOrAReleasedLease() {
		String identity = "extend-refuse-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId);
		EnrolledGateway gateway = enroll("gw-extref-" + unique());

		// Ended session: FAILED_PRECONDITION (a legitimate owner, a state refusal).
		UUID ended = UUID.randomUUID();
		authorize(gateway, identity, nodeId, ended);
		notifyEnd(gateway, ended, SessionEndReason.SESSION_END_REASON_CLOSED);
		assertThatThrownBy(() -> extend(gateway, ended)).isInstanceOfSatisfying(StatusRuntimeException.class,
				e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION));

		// Live session whose lease was already released: same refusal, and the
		// release is never resurrected.
		UUID released = UUID.randomUUID();
		authorize(gateway, identity, nodeId, released);
		sessionLeases.releaseBySessionId(released, Instant.now()).block();
		assertThatThrownBy(() -> extend(gateway, released)).isInstanceOfSatisfying(StatusRuntimeException.class,
				e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION));
		assertThat(sessionLeases.findBySessionId(released).block().releasedAt()).isNotNull();
	}

	// ----------------------- helpers -----------------------

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, UUID sessionId) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal("deploy").setSourceIp(SOURCE_IP).setSessionId(sessionId.toString()).build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).authorize(request));
	}

	private NotifySessionEndResponse notifyEnd(EnrolledGateway gateway, UUID sessionId, SessionEndReason reason) {
		NotifySessionEndRequest request = NotifySessionEndRequest.newBuilder().setSessionId(sessionId.toString())
				.setReason(reason).build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).notifySessionEnd(request));
	}

	private ExtendSessionLeaseResponse extend(EnrolledGateway gateway, UUID sessionId) {
		ExtendSessionLeaseRequest request = ExtendSessionLeaseRequest.newBuilder().setSessionId(sessionId.toString())
				.build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).extendSessionLease(request));
	}

	private long countLive(String identity) {
		return sessionLeases.countLiveByIdentity(identity, Instant.now()).block();
	}

	private <T> T onChannel(EnrolledGateway gateway, java.util.function.Function<ManagedChannel, T> call) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return call.apply(channel);
		} finally {
			shutdown(channel);
		}
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, UUID nodeId) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, List.of("deploy"), 3600,
				List.of("shell"), "allow", "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
