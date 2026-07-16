package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.CasApi;
import io.sessionlayer.controlplane.api.model.CaAlgorithm;
import io.sessionlayer.controlplane.api.model.CaBackend;
import io.sessionlayer.controlplane.api.model.CaKind;
import io.sessionlayer.controlplane.api.model.CaPage;
import io.sessionlayer.controlplane.api.model.CaResource;
import io.sessionlayer.controlplane.api.model.CaRotationState;
import io.sessionlayer.controlplane.api.model.CreateCaRequest;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.RotateCaRequest;
import io.sessionlayer.controlplane.api.model.UpdateCaRequest;
import io.sessionlayer.controlplane.configapi.CaConfigService;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * CRUD + rotation for certificate authorities (`config.ca_config`,
 * FR-CA-1/4/7). Reads/writes need {@code ca:manage}; rotate needs
 * {@code ca:rotate}. Every mutation is audited + pre-commit-validated by
 * {@link CaConfigService}; create and rotate are idempotency-key guarded. The
 * response NEVER carries private key material — {@link CaResource} maps config
 * fields only.
 */
@RestController
public class CaController implements CasApi {

	private final CaConfigService cas;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public CaController(CaConfigService cas, PlatformAccess access, IdempotencyService idempotency) {
		this.cas = cas;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<CaPage>> listCas(String cursor, Integer limit, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas.list(cursor, limit)
						.map(page -> ResponseEntity.ok(new CaPage(page.items().stream().map(this::toResource).toList())
								.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> createCa(Mono<CreateCaRequest> createCaRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return createCaRequest.flatMap(req -> access.withPermission(PlatformPermissions.CA_MANAGE, subject -> {
			Mono<ResponseEntity<CaResource>> action = cas
					.create(subject.identity(), req.getName(), req.getCaKind().getValue(), req.getBackend().getValue(),
							req.getKeyReference(), algorithm(req.getAlgorithm()))
					.map(ca -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(ca)));
			return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
					ApiConversions.path(exchange), req, CaResource.class, action);
		}));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> getCa(UUID caId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas.get(caId).map(ca -> ResponseEntity.ok(toResource(ca))));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> updateCa(UUID caId, Mono<UpdateCaRequest> updateCaRequest,
			ServerWebExchange exchange) {
		return updateCaRequest.flatMap(req -> access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas
						.update(caId, subject.identity(), req.getVersion(), req.getBackend().getValue(),
								req.getKeyReference(), req.getAlgorithm().getValue())
						.map(ca -> ResponseEntity.ok(toResource(ca)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteCa(UUID caId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas.delete(caId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> rotateCa(UUID caId, String idempotencyKey,
			Mono<RotateCaRequest> rotateCaRequest, ServerWebExchange exchange) {
		// The body is optional; normalise it so the idempotency fingerprint is stable.
		return rotateCaRequest.defaultIfEmpty(new RotateCaRequest())
				.flatMap(req -> access.withPermission(PlatformPermissions.CA_ROTATE, subject -> {
					Mono<ResponseEntity<CaResource>> action = cas.rotate(caId, subject.identity())
							.map(ca -> ResponseEntity.ok(toResource(ca)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, CaResource.class, action);
				}));
	}

	private CaResource toResource(CaConfig ca) {
		CaResource resource = new CaResource(ca.id(), ca.name(), CaKind.fromValue(ca.caKind()),
				CaBackend.fromValue(ca.backend()), ca.keyReference(), CaAlgorithm.fromValue(ca.algorithm()),
				CaRotationState.fromValue(ca.rotationState()), Origin.fromValue(ca.origin()), ca.version());
		resource.setCreatedAt(ApiConversions.toOffset(ca.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(ca.updatedAt()));
		return resource;
	}

	private static String algorithm(CaAlgorithm algorithm) {
		return algorithm == null ? "ecdsa-p256" : algorithm.getValue();
	}
}
