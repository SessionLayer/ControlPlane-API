package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.api.model.CreateLockRequest;
import io.sessionlayer.controlplane.api.model.LockTarget;
import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformDecision;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * Unit-proves the lock controller wiring without a web server: an authorised
 * create persists, audits and TRIGGERS THE PUSH; a denied caller gets a generic
 * 403 and touches nothing; an invalid target fails closed before any datastore
 * write; a release is idempotent and pushes a removal.
 */
class LockControllerTest {

	private final AccessLockRepository accessLocks = mock(AccessLockRepository.class);
	private final LockFeedHub lockFeedHub = mock(LockFeedHub.class);
	private final AuditWriter audit = mock(AuditWriter.class);
	private final PlatformAuthorization platformAuthorization = mock(PlatformAuthorization.class);
	private final CurrentAuthentication currentAuthentication = mock(CurrentAuthentication.class);
	private final TransactionalOperator tx = mock(TransactionalOperator.class);

	private LockController controller;

	@BeforeEach
	@SuppressWarnings("unchecked")
	void setUp() {
		controller = new LockController(accessLocks, lockFeedHub, audit, platformAuthorization, currentAuthentication,
				tx);
		when(currentAuthentication.subject()).thenReturn(Mono.just(new PlatformSubject("admin", List.of())));
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		// Pass-through transaction: run the wrapped publisher directly.
		when(tx.transactional(any(Mono.class))).thenAnswer(invocation -> invocation.getArgument(0));
	}

	@Test
	void createPersistsAuditsAndPushes() {
		allowPermission();
		// Mimic the DB @CreatedDate population that a real save performs.
		when(accessLocks.save(any())).thenAnswer(invocation -> {
			AccessLock built = invocation.getArgument(0);
			return Mono.just(new AccessLock(built.id(), built.targetSelector(), built.mode(), built.ttlSeconds(),
					built.expiresAt(), built.reason(), built.createdBy(), 0L, Instant.now(), Instant.now()));
		});
		CreateLockRequest request = new CreateLockRequest(new LockTarget().identities(List.of("alice")), "incident");

		StepVerifier.create(controller.createLock(Mono.just(request), null)).assertNext(response -> {
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
			assertThat(response.getBody().getTarget().getIdentities()).containsExactly("alice");
			assertThat(response.getBody().getCreatedBy()).isEqualTo("admin");
		}).verifyComplete();

		verify(accessLocks).save(any(AccessLock.class));
		verify(lockFeedHub).publishAdded(any(AccessLock.class));
		verify(audit).record(eq("admin"), any(), eq("lock.create"), eq("success"), isNull(), isNull(), any());
	}

	@Test
	void aDeniedCallerGetsGenericForbiddenAndTouchesNothing() {
		when(platformAuthorization.authorize(any(), eq("lock:write"), isNull())).thenReturn(
				Mono.just(new PlatformDecision(false, PlatformDecision.Reason.NO_GRANTING_BINDING, null, null)));
		CreateLockRequest request = new CreateLockRequest(new LockTarget().all(true), "incident");

		StepVerifier.create(controller.createLock(Mono.just(request), null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
				.verifyComplete();

		verify(accessLocks, never()).save(any());
		verify(lockFeedHub, never()).publishAdded(any());
	}

	@Test
	void anInvalidTargetFailsClosedBeforeAnyWrite() {
		allowPermission();
		CreateLockRequest request = new CreateLockRequest(new LockTarget(), "incident"); // empty target

		StepVerifier.create(controller.createLock(Mono.just(request), null)).verifyError(LockValidationException.class);

		verify(accessLocks, never()).save(any());
		verify(lockFeedHub, never()).publishAdded(any());
	}

	@Test
	void releaseIsIdempotentAndPushesRemoval() {
		allowPermission();
		UUID lockId = UUID.randomUUID();
		when(accessLocks.deleteById(any(UUID.class))).thenReturn(Mono.empty());

		StepVerifier.create(controller.releaseLock(lockId, null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
				.verifyComplete();

		verify(lockFeedHub).publishRemoved(lockId);
		verify(audit).record(eq("admin"), eq(lockId.toString()), eq("lock.release"), eq("success"), isNull(), isNull(),
				any());
	}

	private void allowPermission() {
		when(platformAuthorization.authorize(any(), any(), isNull())).thenReturn(Mono.just(
				new PlatformDecision(true, PlatformDecision.Reason.ALLOWED, UUID.randomUUID(), "platform-admin")));
	}
}
