package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.RoleBindingsApi;
import io.sessionlayer.controlplane.api.model.CreateRoleBindingRequest;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.RoleBindingPage;
import io.sessionlayer.controlplane.api.model.RoleBindingResource;
import io.sessionlayer.controlplane.api.model.SubjectKind;
import io.sessionlayer.controlplane.api.model.UpdateRoleBindingRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.RoleBindingConfigService;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * CRUD for platform role bindings (`config.role_binding`, FR-PADM-2). Reads
 * need {@code rbac:read}; writes need {@code rbac:write}. Every mutation is
 * audited + pre-commit-validated by {@link RoleBindingConfigService}; creates
 * are idempotency-key guarded. Follows {@link RuleController}.
 */
@RestController
public class RoleBindingController implements RoleBindingsApi {

	private final RoleBindingConfigService bindings;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;
	private final ObjectMapper mapper;

	public RoleBindingController(RoleBindingConfigService bindings, PlatformAccess access,
			IdempotencyService idempotency, ObjectMapper mapper) {
		this.bindings = bindings;
		this.access = access;
		this.idempotency = idempotency;
		this.mapper = mapper;
	}

	@Override
	public Mono<ResponseEntity<RoleBindingPage>> listRoleBindings(String cursor, Integer limit,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ, subject -> bindings.list(cursor, limit)
				.map(page -> ResponseEntity.ok(new RoleBindingPage(page.items().stream().map(this::toResource).toList())
						.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<RoleBindingResource>> createRoleBinding(
			Mono<CreateRoleBindingRequest> createRoleBindingRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return createRoleBindingRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.RBAC_WRITE, subject -> {
					Mono<ResponseEntity<RoleBindingResource>> action = bindings
							.create(subject.identity(), req.getRoleId(), req.getSubjectKind().getValue(),
									req.getSubject(), ApiConversions.toJsonOrNull(mapper, req.getScope()))
							.map(binding -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(binding)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, RoleBindingResource.class, action);
				}));
	}

	@Override
	public Mono<ResponseEntity<RoleBindingResource>> getRoleBinding(UUID bindingId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> bindings.get(bindingId).map(binding -> ResponseEntity.ok(toResource(binding))));
	}

	@Override
	public Mono<ResponseEntity<RoleBindingResource>> updateRoleBinding(UUID bindingId,
			Mono<UpdateRoleBindingRequest> updateRoleBindingRequest, ServerWebExchange exchange) {
		return updateRoleBindingRequest.flatMap(req -> access.withPermission(PlatformPermissions.RBAC_WRITE,
				subject -> bindings
						.update(bindingId, subject.identity(), req.getVersion(),
								ApiConversions.toJsonOrNull(mapper, req.getScope()))
						.map(binding -> ResponseEntity.ok(toResource(binding)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteRoleBinding(UUID bindingId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_WRITE, subject -> bindings
				.delete(bindingId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private RoleBindingResource toResource(RoleBinding binding) {
		RoleBindingResource resource = new RoleBindingResource(binding.id(), binding.roleId(),
				SubjectKind.fromValue(binding.subjectKind()), binding.subject(), Origin.fromValue(binding.origin()),
				binding.version());
		resource.setScope(ApiConversions.toMap(mapper, binding.scope()));
		resource.setCreatedAt(ApiConversions.toOffset(binding.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(binding.updatedAt()));
		return resource;
	}
}
