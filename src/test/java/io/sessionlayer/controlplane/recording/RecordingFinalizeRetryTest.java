package io.sessionlayer.controlplane.recording;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * S25 F1 — the Gateway fires NotifySessionEnd and FinalizeRecording
 * concurrently at teardown; both stamp {@code ssh_session.ended_at}. A lost
 * {@code @Version} race inside finalize must NOT roll the whole finalize back
 * for good (the Gateway does not retry finalize → the recording would stay
 * permanently non-terminal): the tx retries once and the re-read sees the
 * session already ended, no-ops the stamp, and commits the terminal status.
 */
class RecordingFinalizeRetryTest {

	@Test
	void aLostEndStampRaceRetriesOnceAndStillFinalizes() {
		RecordingTokenService recordingTokens = mock(RecordingTokenService.class);
		OperatorSettingsRepository operatorSettings = mock(OperatorSettingsRepository.class);
		SshSessionRepository sshSessions = mock(SshSessionRepository.class);
		SessionLeaseRepository sessionLeases = mock(SessionLeaseRepository.class);
		RecordingRefRepository recordings = mock(RecordingRefRepository.class);
		NodeRepository nodes = mock(NodeRepository.class);
		RecordingStore worm = mock(RecordingStore.class);
		AuditEventStore audit = mock(AuditEventStore.class);
		TransactionalOperator tx = mock(TransactionalOperator.class);
		// The tx boundary is a passthrough here; the DB rollback semantics under
		// test are the RE-SUBSCRIPTION (retry re-runs the whole body).
		when(tx.transactional(any(Mono.class))).thenAnswer(invocation -> invocation.getArgument(0));

		UUID gatewayId = UUID.randomUUID();
		UUID recordingId = UUID.randomUUID();
		SshSession live = SshSession.create("alice", null, "node-a", "deploy", gatewayId, "gw-a", "standing",
				List.of("shell"), null, "rule", null, null, 0L, Instant.now().plusSeconds(3600), Instant.now());
		SshSession ended = live.ended(Instant.now(), "closed");
		RecordingRef ref = RecordingRef.begin(recordingId, live.id(), "recordings/x.cast.enc", "key-ref", "governance",
				Instant.now().plusSeconds(86400));

		when(recordings.findById(recordingId)).thenReturn(Mono.just(ref));
		// Attempt 1 reads the live session and loses the @Version race on the end
		// stamp; attempt 2 re-reads and sees NotifySessionEnd already ended it.
		when(sshSessions.findById(live.id())).thenReturn(Mono.just(live)).thenReturn(Mono.just(ended));
		when(sshSessions.save(any(SshSession.class)))
				.thenReturn(Mono.error(new OptimisticLockingFailureException("stale ssh_session version")));
		when(recordings.save(any(RecordingRef.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
		when(sessionLeases.releaseBySessionId(any(UUID.class), any(Instant.class))).thenReturn(Mono.just(0));
		when(audit.record(any(AuditRecord.class))).thenReturn(Mono.empty());

		RecordingRegistrationService service = new RecordingRegistrationService(recordingTokens, operatorSettings,
				sshSessions, sessionLeases, recordings, nodes, worm, audit, tx);

		StepVerifier.create(
				service.finalizeRecording(gatewayId, recordingId, "finalized", null, null, null, 42, null, null))
				.expectNext("finalized").verifyComplete();

		// One failed stamp attempt, then the retried body committed the terminal
		// status (recordings.save ran on both attempts).
		verify(sshSessions, times(1)).save(any(SshSession.class));
		verify(recordings, times(2)).save(any(RecordingRef.class));
	}
}
