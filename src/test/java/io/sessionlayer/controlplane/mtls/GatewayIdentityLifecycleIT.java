package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.RenewGatewayIdentityRequest;
import io.sessionlayer.controlplane.grpc.v1.RenewGatewayIdentityResponse;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

/**
 * Part B — Gateway identity lifecycle (FR-BOOT-3, §8). Enrollment issues a
 * generation-0 identity and writes {@code gateway_identity}; the enrollment
 * token is single-use; renewal rotates the certificate and increments the
 * generation; a locked identity is refused; a generation mismatch is refused
 * and flagged.
 */
class GatewayIdentityLifecycleIT extends AbstractMtlsIT {

	@Test
	void enrollIssuesGenerationZeroAndWritesIdentity() {
		EnrolledGateway gateway = enroll("gw-enroll");
		assertThat(gateway.generation()).isZero();

		GatewayIdentity identity = gatewayIdentities.findById(gateway.gatewayId()).block();
		assertThat(identity).isNotNull();
		assertThat(identity.name()).isEqualTo("gw-enroll");
		assertThat(identity.generation()).isZero();
		assertThat(identity.status()).isEqualTo("active");
		assertThat(identity.joinMethod()).isEqualTo("token");
		assertThat(identity.mtlsIdentityRef()).isEqualTo("mtls:" + gateway.gatewayId());
		assertThat(identity.fingerprint()).isNotBlank();
	}

	@Test
	void enrollmentTokenIsSingleUse() {
		String token = enrollmentTokens.mint("gw-single-use", "test-operator").block();
		EnrolledGateway first = enrollWithToken("gw-single-use", token);
		assertThat(first.generation()).isZero();

		// Replaying the (now consumed) token is rejected.
		StatusRuntimeException replay = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-single-use-2", token));
		assertThat(replay.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void enrollErrorIsIndistinguishableForAlreadyEnrolledAndInvalidToken() {
		// M1: a bootstrap-tier (no-client-cert) peer must not be able to enumerate
		// fleet
		// gateway names — "already enrolled" and "invalid token" must be
		// indistinguishable.
		// Case A — a VALID token, but the name is already enrolled.
		enroll("gw-oracle");
		String freshToken = enrollmentTokens.mint("gw-oracle", "test-operator").block();
		StatusRuntimeException alreadyEnrolled = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-oracle", freshToken));
		// Case B — a FREE name, but an invalid token.
		StatusRuntimeException invalidToken = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-oracle-free", "not-a-real-token"));

		// Identical status code AND description (no enumeration oracle, NFR-2/§15).
		assertThat(alreadyEnrolled.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		assertThat(invalidToken.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		assertThat(alreadyEnrolled.getStatus().getDescription()).isEqualTo(invalidToken.getStatus().getDescription());

		// And the fresh single-use token was NOT burned by the already-enrolled probe
		// (M1).
		Long unconsumed = db.sql(
				"SELECT count(*) FROM runtime.gateway_enrollment_token WHERE gateway_name = 'gw-oracle' AND consumed_at IS NULL")
				.map(row -> row.get(0, Long.class)).one().block();
		assertThat(unconsumed).isEqualTo(1L);
	}

	@Test
	void renewRotatesCertificateAndIncrementsGeneration() {
		EnrolledGateway gateway = enroll("gw-renew");
		String beforeFingerprint = gatewayIdentities.findById(gateway.gatewayId()).block().fingerprint();

		RenewGatewayIdentityResponse renewed = renew(gateway, "gw-renew", 0);
		assertThat(renewed.getGeneration()).isEqualTo(1);

		GatewayIdentity after = gatewayIdentities.findById(gateway.gatewayId()).block();
		assertThat(after.generation()).isEqualTo(1);
		assertThat(after.fingerprint()).isNotEqualTo(beforeFingerprint); // rotated
	}

	@Test
	void lockedIdentityIsRefusedForRenew() {
		EnrolledGateway gateway = enroll("gw-locked");
		// Honor the DB status (the lock push is S10; here we enforce the refusal).
		db.sql("UPDATE runtime.gateway_identity SET status = 'locked' WHERE id = :id").bind("id", gateway.gatewayId())
				.fetch().rowsUpdated().block();

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> renew(gateway, "gw-locked", 0));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void generationMismatchIsRefusedAndFlagged() {
		EnrolledGateway gateway = enroll("gw-genmismatch");

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> renew(gateway, "gw-genmismatch", 5)); // declares the wrong current generation
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION);

		// The mismatch was flagged as a security event in the audit stream (§8.2).
		Long flagged = db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.renew.generation_mismatch' "
						+ "AND actor = 'gw-genmismatch'")
				.map(row -> row.get(0, Long.class)).one().block();
		assertThat(flagged).isGreaterThanOrEqualTo(1L);
	}

	private RenewGatewayIdentityResponse renew(EnrolledGateway gateway, String name, long currentGeneration) {
		KeyPair newKey = MtlsTestSupport.generateEcKeyPair();
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return GatewayIdentityGrpc.newBlockingStub(channel)
					.renewGatewayIdentity(RenewGatewayIdentityRequest.newBuilder()
							.setPkcs10Csr(ByteString.copyFrom(MtlsTestSupport.csr(newKey, name)))
							.setCurrentGeneration(currentGeneration).build());
		} finally {
			shutdown(channel);
		}
	}
}
