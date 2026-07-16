package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.RolesApi;
import io.sessionlayer.controlplane.api.model.CreateRoleRequest;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.PlatformPermission;
import io.sessionlayer.controlplane.api.model.RolePage;
import io.sessionlayer.controlplane.api.model.RoleResource;
import io.sessionlayer.controlplane.api.model.UpdateRoleRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.RoleConfigService;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * CRUD for platform-RBAC roles (`config.platform_role`, FR-PADM-1). Reads need
 * {@code rbac:read}; writes need {@code rbac:write}. Every mutation is audited
 * + pre-commit-validated by {@link RoleConfigService}; creates are
 * idempotency-key guarded. Follows {@link RuleController}.
 */
@RestController
public class RoleController implements RolesApi {

	private final RoleConfigService roles;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public RoleController(RoleConfigService roles, PlatformAccess access, IdempotencyService idempotency) {
		this.roles = roles;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<RolePage>> listRoles(String cursor, Integer limit, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> roles.list(cursor, limit).map(
						page -> ResponseEntity.ok(new RolePage(page.items().stream().map(this::toResource).toList())
								.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<RoleResource>> createRole(Mono<CreateRoleRequest> createRoleRequest,
			String idempotencyKey, ServerWebExchange exchange) {
		return createRoleRequest.flatMap(req -> access.withPermission(PlatformPermissions.RBAC_WRITE, subject -> {
			Mono<ResponseEntity<RoleResource>> action = roles
					.create(subject.identity(), req.getName(), permissionValues(req.getPermissions()),
							req.getDescription())
					.map(role -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(role)));
			return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
					ApiConversions.path(exchange), req, RoleResource.class, action);
		}));
	}

	@Override
	public Mono<ResponseEntity<RoleResource>> getRole(UUID roleId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> roles.get(roleId).map(role -> ResponseEntity.ok(toResource(role))));
	}

	@Override
	public Mono<ResponseEntity<RoleResource>> updateRole(UUID roleId, Mono<UpdateRoleRequest> updateRoleRequest,
			ServerWebExchange exchange) {
		return updateRoleRequest.flatMap(req -> access.withPermission(PlatformPermissions.RBAC_WRITE,
				subject -> roles.update(roleId, subject.identity(), req.getVersion(),
						permissionValues(req.getPermissions()), req.getDescription())
						.map(role -> ResponseEntity.ok(toResource(role)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteRole(UUID roleId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_WRITE,
				subject -> roles.delete(roleId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private RoleResource toResource(PlatformRole role) {
		RoleResource resource = new RoleResource(role.id(), role.name(), toPermissions(role.permissions()),
				Origin.fromValue(role.origin()), role.version());
		resource.setDescription(role.description());
		resource.setCreatedAt(ApiConversions.toOffset(role.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(role.updatedAt()));
		return resource;
	}

	private static List<String> permissionValues(List<PlatformPermission> permissions) {
		return permissions == null ? List.of() : permissions.stream().map(PlatformPermission::getValue).toList();
	}

	private static List<PlatformPermission> toPermissions(List<String> values) {
		return values == null ? List.of() : values.stream().map(PlatformPermission::fromValue).toList();
	}
}
