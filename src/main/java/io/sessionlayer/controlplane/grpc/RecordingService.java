package io.sessionlayer.controlplane.grpc;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.GatewayRequestException.Reason;
import io.sessionlayer.controlplane.grpc.v1.BeginRecordingRequest;
import io.sessionlayer.controlplane.grpc.v1.BeginRecordingResponse;
import io.sessionlayer.controlplane.grpc.v1.CustomerKey;
import io.sessionlayer.controlplane.grpc.v1.FinalizeRecordingRequest;
import io.sessionlayer.controlplane.grpc.v1.FinalizeRecordingResponse;
import io.sessionlayer.controlplane.grpc.v1.KeySealAlgorithm;
import io.sessionlayer.controlplane.grpc.v1.RecordingContext;
import io.sessionlayer.controlplane.grpc.v1.RecordingGrpc;
import io.sessionlayer.controlplane.grpc.v1.RecordingStatus;
import io.sessionlayer.controlplane.grpc.v1.RequestUploadRequest;
import io.sessionlayer.controlplane.grpc.v1.RequestUploadResponse;
import io.sessionlayer.controlplane.grpc.v1.UploadCredential;
import io.sessionlayer.controlplane.grpc.v1.WormMode;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import io.sessionlayer.controlplane.recording.FileTransferAuditEntry;
import io.sessionlayer.controlplane.recording.RecordingRegistration;
import io.sessionlayer.controlplane.recording.RecordingRegistrationService;
import io.sessionlayer.controlplane.recording.RecordingRequestContext;
import io.sessionlayer.controlplane.recording.RecordingStore.PresignedAccess;
import io.sessionlayer.controlplane.recording.TunnelAuditEntry;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * gRPC server for {@code Recording} (Design §12/§15). mTLS-required tier — the
 * {@link AuthInterceptor} resolves the calling Gateway; {@code BeginRecording}
 * additionally consumes the single-use recording token (the per-request
 * authority), {@code FinalizeRecording} is authorized by the caller owning the
 * recording's session. Delegates to {@link RecordingRegistrationService} and
 * maps the domain result onto the wire; proto never leaks into the service
 * layer.
 */
@Service
public class RecordingService extends RecordingGrpc.RecordingImplBase {

	private final RecordingRegistrationService registration;
	private final MtlsProperties properties;

	public RecordingService(RecordingRegistrationService registration, MtlsProperties properties) {
		this.registration = registration;
		this.properties = properties;
	}

	@Override
	public void beginRecording(BeginRecordingRequest request, StreamObserver<BeginRecordingResponse> observer) {
		MtlsPeer peer = MtlsContext.peer();
		UUID caller = peer == null ? null : peer.gatewayId();
		// The advisory context is parsed in a deferred callable so a set-but-malformed
		// UUID surfaces reactively as one generic fail-closed error (§15).
		Mono<BeginRecordingResponse> result = Mono.fromCallable(() -> toContext(request))
				.flatMap(context -> registration.beginRecording(caller, request.getRecordingToken(), context))
				.map(RecordingService::toResponse);
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "BeginRecording");
	}

	@Override
	public void requestUpload(RequestUploadRequest request, StreamObserver<RequestUploadResponse> observer) {
		MtlsPeer peer = MtlsContext.peer();
		UUID caller = peer == null ? null : peer.gatewayId();
		// A blank/malformed id parses to null, which the service rejects (fail closed).
		Mono<RequestUploadResponse> result = registration.requestUpload(caller, parseUuid(request.getRecordingId()))
				.map(upload -> RequestUploadResponse.newBuilder().setUpload(toUpload(upload)).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "RequestUpload");
	}

	@Override
	public void finalizeRecording(FinalizeRecordingRequest request,
			StreamObserver<FinalizeRecordingResponse> observer) {
		MtlsPeer peer = MtlsContext.peer();
		UUID caller = peer == null ? null : peer.gatewayId();
		Mono<FinalizeRecordingResponse> result = Mono.fromCallable(() -> {
			UUID recordingId = parseUuid(request.getRecordingId());
			String status = toStatus(request.getStatus());
			if (recordingId == null || status == null) {
				throw new GatewayRequestException(Reason.INVALID_ARGUMENT, "invalid recording request");
			}
			return new FinalizeArgs(recordingId, status);
		}).flatMap(args -> registration
				.finalizeRecording(caller, args.recordingId(), args.status(), request.getHashChainHead(),
						request.getContentDigest(), request.getObjectVersionId(), request.getByteLen(),
						toEntries(request), toTunnelEntries(request))
				.map(stored -> FinalizeRecordingResponse.newBuilder().setStatus(fromStatus(stored)).build()));
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "FinalizeRecording");
	}

	private record FinalizeArgs(UUID recordingId, String status) {
	}

	private static RecordingRequestContext toContext(BeginRecordingRequest request) {
		if (!request.hasContext()) {
			return RecordingRequestContext.EMPTY;
		}
		RecordingContext ctx = request.getContext();
		return new RecordingRequestContext(optionalUuid(ctx.getSessionId()), optionalUuid(ctx.getNodeId()),
				ctx.getPrincipal().isBlank() ? null : ctx.getPrincipal());
	}

	private static BeginRecordingResponse toResponse(RecordingRegistration reg) {
		CustomerKey customerKey = CustomerKey.newBuilder().setKeyRef(reg.customerKey().keyRef())
				.setPublicKey(ByteString.copyFrom(reg.customerKey().publicKey()))
				.setAlgorithm(toAlgorithm(reg.customerKey().algorithm())).build();
		return BeginRecordingResponse.newBuilder().setRecordingId(reg.recordingId().toString())
				.setObjectKey(reg.objectKey()).setWormMode(toWormMode(reg.wormMode())).setCustomerKey(customerKey)
				.build();
	}

	private static UploadCredential toUpload(PresignedAccess upload) {
		return UploadCredential.newBuilder().setUrl(upload.url()).setMethod(upload.method())
				.putAllRequiredHeaders(upload.requiredHeaders())
				.setExpiresAtEpochSeconds(upload.expiresAtEpochSeconds()).build();
	}

	private static List<FileTransferAuditEntry> toEntries(FinalizeRecordingRequest request) {
		return request.getSftpAuditList().stream().map(fta -> new FileTransferAuditEntry(fta.getOperation(),
				fta.getPath(), fta.getDirection(), fta.getSize(), fta.getSha256())).toList();
	}

	private static List<TunnelAuditEntry> toTunnelEntries(FinalizeRecordingRequest request) {
		return request.getTunnelAuditList().stream().map(ta -> new TunnelAuditEntry(ta.getCapability(),
				ta.getDirection(), ta.getTarget(), ta.getBytesIn(), ta.getBytesOut(), ta.getDurationSeconds()))
				.toList();
	}

	private static WormMode toWormMode(String mode) {
		return switch (mode) {
			case "compliance" -> WormMode.WORM_MODE_COMPLIANCE;
			case "governance" -> WormMode.WORM_MODE_GOVERNANCE;
			default -> WormMode.WORM_MODE_UNSPECIFIED;
		};
	}

	private static KeySealAlgorithm toAlgorithm(String algorithm) {
		return switch (algorithm) {
			case "ecies_p256" -> KeySealAlgorithm.KEY_SEAL_ALGORITHM_ECIES_P256_HKDF_SHA256_AES256GCM;
			case "rsa_oaep_sha256" -> KeySealAlgorithm.KEY_SEAL_ALGORITHM_RSA_OAEP_SHA256;
			default -> KeySealAlgorithm.KEY_SEAL_ALGORITHM_UNSPECIFIED;
		};
	}

	private static String toStatus(RecordingStatus status) {
		return switch (status) {
			case RECORDING_STATUS_FINALIZED -> "finalized";
			case RECORDING_STATUS_TRUNCATED -> "truncated";
			case RECORDING_STATUS_FAILED -> "failed";
			default -> null; // UNSPECIFIED / UNRECOGNIZED → fail closed at the service
		};
	}

	private static RecordingStatus fromStatus(String status) {
		return switch (status) {
			case "finalized" -> RecordingStatus.RECORDING_STATUS_FINALIZED;
			case "truncated" -> RecordingStatus.RECORDING_STATUS_TRUNCATED;
			case "failed" -> RecordingStatus.RECORDING_STATUS_FAILED;
			default -> RecordingStatus.RECORDING_STATUS_UNSPECIFIED;
		};
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

	// A set-but-malformed advisory UUID cannot match the token, so fail closed.
	private static UUID optionalUuid(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		try {
			return UUID.fromString(value);
		} catch (IllegalArgumentException notAUuid) {
			throw new GatewayRequestException(Reason.PERMISSION_DENIED, "recording request refused");
		}
	}
}
