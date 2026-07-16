package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.ServiceAccountsApi;
import io.sessionlayer.controlplane.api.model.CreateServiceAccountRequest;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.ServiceAccountAuthMethod;
import io.sessionlayer.controlplane.api.model.ServiceAccountPage;
import io.sessionlayer.controlplane.api.model.ServiceAccountResource;
import io.sessionlayer.controlplane.api.model.UpdateServiceAccountRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.ServiceAccountConfigService;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * CRUD for service-account definitions (`config.service_account`, FR-AUTH-12).
 * Reads/writes need {@code user:manage}. Every mutation is audited +
 * pre-commit-validated by {@link ServiceAccountConfigService}; creates are
 * idempotency-key guarded. Distinct from the runtime
 * {@code /v1/service-accounts/{id}/credentials} (issue/revoke, AuthController)
 * — this is the definition and {@link ServiceAccountResource} NEVER carries a
 * secret.
 */
@RestController
public class ServiceAccountController implements ServiceAccountsApi {

	private final ServiceAccountConfigService accounts;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public ServiceAccountController(ServiceAccountConfigService accounts, PlatformAccess access,
			IdempotencyService idempotency) {
		this.accounts = accounts;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<ServiceAccountPage>> listServiceAccounts(String cursor, Integer limit,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.USER_MANAGE, subject -> accounts.list(cursor, limit).map(
				page -> ResponseEntity.ok(new ServiceAccountPage(page.items().stream().map(this::toResource).toList())
						.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<ServiceAccountResource>> createServiceAccount(
			Mono<CreateServiceAccountRequest> createServiceAccountRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return createServiceAccountRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.USER_MANAGE, subject -> {
					Mono<ResponseEntity<ServiceAccountResource>> action = accounts
							.create(subject.identity(), req.getName(), req.getDescription(),
									authMethod(req.getAuthMethod()), req.getKeyReference(), req.getTokenTtlSeconds())
							.map(account -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(account)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, ServiceAccountResource.class, action);
				}));
	}

	@Override
	public Mono<ResponseEntity<ServiceAccountResource>> getServiceAccount(UUID serviceAccountId,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.USER_MANAGE,
				subject -> accounts.get(serviceAccountId).map(account -> ResponseEntity.ok(toResource(account))));
	}

	@Override
	public Mono<ResponseEntity<ServiceAccountResource>> updateServiceAccount(UUID serviceAccountId,
			Mono<UpdateServiceAccountRequest> updateServiceAccountRequest, ServerWebExchange exchange) {
		return updateServiceAccountRequest.flatMap(req -> access.withPermission(PlatformPermissions.USER_MANAGE,
				subject -> accounts
						.update(serviceAccountId, subject.identity(), req.getVersion(), req.getDescription(),
								authMethod(req.getAuthMethod()), req.getKeyReference(), req.getTokenTtlSeconds())
						.map(account -> ResponseEntity.ok(toResource(account)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteServiceAccount(UUID serviceAccountId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.USER_MANAGE, subject -> accounts
				.delete(serviceAccountId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private ServiceAccountResource toResource(ServiceAccount account) {
		ServiceAccountResource resource = new ServiceAccountResource(account.id(), account.name(),
				ServiceAccountAuthMethod.fromValue(account.authMethod()), Origin.fromValue(account.origin()),
				account.version());
		resource.setDescription(account.description());
		resource.setKeyReference(account.keyReference());
		resource.setTokenTtlSeconds(account.tokenTtlSeconds());
		resource.setCreatedAt(ApiConversions.toOffset(account.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(account.updatedAt()));
		return resource;
	}

	// null (absent) is resolved by the service: default on create, preserve on
	// update.
	private static String authMethod(ServiceAccountAuthMethod authMethod) {
		return authMethod == null ? null : authMethod.getValue();
	}
}
