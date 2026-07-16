package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.CapabilityDefsApi;
import io.sessionlayer.controlplane.api.model.Capability;
import io.sessionlayer.controlplane.api.model.CapabilityDefPage;
import io.sessionlayer.controlplane.api.model.CapabilityDefResource;
import io.sessionlayer.controlplane.api.model.CreateCapabilityDefRequest;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.UpdateCapabilityDefRequest;
import io.sessionlayer.controlplane.configapi.CapabilityDefConfigService;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.data.config.CapabilityDef;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * CRUD for the requestable-capability catalogue (`config.capability_def`,
 * Design §12A). All operations need {@code settings:write}. The {@code name} is
 * a fixed capability enum (immutable); only {@code description} is mutable.
 * Every mutation is audited by {@link CapabilityDefConfigService}; creates are
 * idempotency-key guarded.
 */
@RestController
public class CapabilityDefController implements CapabilityDefsApi {

	private final CapabilityDefConfigService capabilities;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public CapabilityDefController(CapabilityDefConfigService capabilities, PlatformAccess access,
			IdempotencyService idempotency) {
		this.capabilities = capabilities;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<CapabilityDefPage>> listCapabilityDefs(String cursor, Integer limit,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> capabilities.list(cursor, limit)
						.map(page -> ResponseEntity
								.ok(new CapabilityDefPage(page.items().stream().map(this::toResource).toList())
										.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<CapabilityDefResource>> createCapabilityDef(
			Mono<CreateCapabilityDefRequest> createCapabilityDefRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return createCapabilityDefRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> {
					Mono<ResponseEntity<CapabilityDefResource>> action = capabilities
							.create(subject.identity(), req.getName().getValue(), req.getDescription())
							.map(def -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(def)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, CapabilityDefResource.class, action);
				}));
	}

	@Override
	public Mono<ResponseEntity<CapabilityDefResource>> getCapabilityDef(UUID capabilityDefId,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> capabilities.get(capabilityDefId).map(def -> ResponseEntity.ok(toResource(def))));
	}

	@Override
	public Mono<ResponseEntity<CapabilityDefResource>> updateCapabilityDef(UUID capabilityDefId,
			Mono<UpdateCapabilityDefRequest> updateCapabilityDefRequest, ServerWebExchange exchange) {
		return updateCapabilityDefRequest.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> capabilities
						.update(capabilityDefId, subject.identity(), req.getVersion(), req.getDescription())
						.map(def -> ResponseEntity.ok(toResource(def)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteCapabilityDef(UUID capabilityDefId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> capabilities
				.delete(capabilityDefId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private CapabilityDefResource toResource(CapabilityDef def) {
		CapabilityDefResource resource = new CapabilityDefResource(def.id(), Capability.fromValue(def.name()),
				Origin.fromValue(def.origin()), def.version());
		resource.setDescription(def.description());
		resource.setCreatedAt(ApiConversions.toOffset(def.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(def.updatedAt()));
		return resource;
	}
}
