package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import io.sessionlayer.controlplane.ca.wire.SshReader;
import io.sessionlayer.controlplane.grpc.v1.HostCertSigningGrpc;
import io.sessionlayer.controlplane.grpc.v1.SignGatewayHostCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.SignGatewayHostCertificateResponse;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * S16 Part C — {@code SignGatewayHostCertificate}: the OUTER host certificate a
 * Gateway presents on the ProxyJump host-cert MITM path so a stock OpenSSH
 * client accepts it as the target node with NO TOFU. mTLS is REQUIRED; the RPC
 * is NOT session-bound, so the caller's Gateway mTLS identity (active +
 * unlocked) is the sole authority. The CP chooses the {@code key_id}; the
 * caller supplies only the host public key and the (validated) host principals.
 */
class GatewayHostCertificateIT extends AbstractMtlsIT {

	@Autowired
	private CaRotationService caRotation;

	@Test
	void signsAHostCertForTheRequestedPrincipalsChainingToTheHostCa() throws Exception {
		String name = "gw-hostcert-" + unique();
		EnrolledGateway gateway = enroll(name);
		KeyPair hostKey = MtlsTestSupport.generateEcKeyPair();
		List<String> principals = List.of("web-01", "web-01.ssh.corp");

		SignGatewayHostCertificateResponse response = signHostCert(gateway,
				MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) hostKey.getPublic()), principals);

		assertThat(response.getCertificateLine()).startsWith("ecdsa-sha2-nistp256-cert-v01@openssh.com");
		HostCert cert = parseHostCert(response.getCertificateBlob().toByteArray());
		// It IS a host cert (the embedded type field = 2), for exactly the requested
		// principals, keyed to the gateway name for the node-local audit trail.
		assertThat(cert.type()).isEqualTo(2L);
		assertThat(cert.principals()).containsExactlyElementsOf(principals);
		assertThat(cert.keyId()).isEqualTo("gateway-host:" + name);

		// Chains to the HOST CA: the cert's signature key is a trusted host-CA key AND
		// the CA signature verifies (OpenSSH @cert-authority trust — no TOFU).
		List<byte[]> trustedHostCa = caRotation.trustedCaKeys("host").block().stream()
				.map(line -> Base64.getDecoder().decode(line.trim().split("\\s+")[1])).toList();
		assertThat(trustedHostCa).anySatisfy(ca -> assertThat(ca).isEqualTo(cert.caKeyBlob()));
		assertThat(verifyHostSignature(cert.tbs(), cert.signature(), cert.caKeyBlob())).isTrue();

		// Validity is backdated for skew and bounded by the (short) host-cert TTL.
		assertThat(response.getValidAfterEpochSeconds()).isLessThan(Instant.now().getEpochSecond());
		assertThat(response.getValidBeforeEpochSeconds()).isGreaterThan(Instant.now().getEpochSecond());

		Long audited = db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.host_cert.sign' "
						+ "AND outcome = 'success' AND actor = :actor")
				.bind("actor", name).map(row -> row.get(0, Long.class)).one().block();
		assertThat(audited).isEqualTo(1L);
	}

	@Test
	void refusesALockedGatewayIdentity() {
		String name = "gw-hostcert-locked-" + unique();
		EnrolledGateway gateway = enroll(name);
		lockIdentity(gateway, "locked");
		byte[] hostKey = MtlsTestSupport
				.opensshPublicKeyBlob((ECPublicKey) MtlsTestSupport.generateEcKeyPair().getPublic());

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> signHostCert(gateway, hostKey, List.of("web-01")));

		// The lock IS the revocation: no reissue; the outstanding host cert just
		// expires.
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		assertThat(deniedIssuances(name)).isEqualTo(1L);
	}

	@Test
	void rejectsEmptyPrincipals() {
		EnrolledGateway gateway = enroll("gw-hostcert-noprin-" + unique());
		byte[] hostKey = MtlsTestSupport
				.opensshPublicKeyBlob((ECPublicKey) MtlsTestSupport.generateEcKeyPair().getPublic());

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> signHostCert(gateway, hostKey, List.of()));

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
	}

	@Test
	void rejectsABlankPrincipal() {
		EnrolledGateway gateway = enroll("gw-hostcert-blank-" + unique());
		byte[] hostKey = MtlsTestSupport
				.opensshPublicKeyBlob((ECPublicKey) MtlsTestSupport.generateEcKeyPair().getPublic());

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> signHostCert(gateway, hostKey, List.of("web-01", "  ")));

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
	}

	@Test
	void refusesACallerWithNoClientCertificate() {
		byte[] hostKey = MtlsTestSupport
				.opensshPublicKeyBlob((ECPublicKey) MtlsTestSupport.generateEcKeyPair().getPublic());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(),
				MtlsTestSupport.clientSslContext(caCertificate(), null, null));
		try {
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> HostCertSigningGrpc.newBlockingStub(channel)
							.signGatewayHostCertificate(SignGatewayHostCertificateRequest.newBuilder()
									.setHostPublicKey(ByteString.copyFrom(hostKey)).addHostPrincipals("web-01")
									.build()));

			// Not a bootstrap-tier RPC: the interceptor refuses it before the handler.
			assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		} finally {
			shutdown(channel);
		}
	}

	private SignGatewayHostCertificateResponse signHostCert(EnrolledGateway gateway, byte[] hostKeyBlob,
			List<String> principals) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return HostCertSigningGrpc.newBlockingStub(channel)
					.signGatewayHostCertificate(SignGatewayHostCertificateRequest.newBuilder()
							.setHostPublicKey(ByteString.copyFrom(hostKeyBlob)).addAllHostPrincipals(principals)
							.build());
		} finally {
			shutdown(channel);
		}
	}

	private void lockIdentity(EnrolledGateway gateway, String status) {
		db.sql("UPDATE runtime.gateway_identity SET status = :status WHERE id = :id").bind("status", status)
				.bind("id", gateway.gatewayId()).fetch().rowsUpdated().block();
	}

	private Long deniedIssuances(String name) {
		return db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.host_cert.sign' "
						+ "AND outcome = 'denied' AND actor = :actor")
				.bind("actor", name).map(row -> row.get(0, Long.class)).one().block();
	}

	// A minimal OpenSSH ecdsa host-cert parser (field layout per
	// PROTOCOL.certkeys),
	// enough to assert the type/principals/key-id and to verify the CA signature.
	private record HostCert(long type, String keyId, List<String> principals, byte[] caKeyBlob, byte[] tbs,
			byte[] signature) {
	}

	private static HostCert parseHostCert(byte[] blob) {
		SshReader reader = new SshReader(blob);
		reader.readStringUtf8(); // cert-type name
		reader.readString(); // nonce
		reader.readString(); // curve
		reader.readString(); // Q
		reader.readUint64(); // serial
		long type = reader.readUint32();
		String keyId = reader.readStringUtf8();
		byte[] principalsField = reader.readString();
		reader.readUint64(); // valid after
		reader.readUint64(); // valid before
		reader.readString(); // critical options
		reader.readString(); // extensions
		reader.readString(); // reserved
		byte[] caKeyBlob = reader.readString(); // signature key
		int tbsLength = reader.position();
		byte[] signature = reader.readString();
		List<String> principals = new ArrayList<>();
		SshReader principalReader = new SshReader(principalsField);
		while (principalReader.hasRemaining()) {
			principals.add(principalReader.readStringUtf8());
		}
		return new HostCert(type, keyId, principals, caKeyBlob, java.util.Arrays.copyOfRange(blob, 0, tbsLength),
				signature);
	}

	private static boolean verifyHostSignature(byte[] tbs, byte[] signatureField, byte[] caKeyBlob) throws Exception {
		ECPublicKey caKey = SshEcdsaPublicKeys.parse(caKeyBlob);
		SshReader signature = new SshReader(signatureField);
		signature.readStringUtf8(); // signature algorithm
		SshReader inner = new SshReader(signature.readString());
		BigInteger r = inner.readMpint();
		BigInteger s = inner.readMpint();
		Signature verifier = Signature.getInstance("SHA256withECDSA");
		verifier.initVerify(caKey);
		verifier.update(tbs);
		return verifier.verify(EcdsaSignatures.toDer(new EcdsaSignatures.RS(r, s)));
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
