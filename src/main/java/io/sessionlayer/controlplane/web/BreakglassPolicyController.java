package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.BreakglassPoliciesApi;
import io.sessionlayer.controlplane.api.model.BreakglassAuthPath;
import io.sessionlayer.controlplane.api.model.BreakglassPolicyPage;
import io.sessionlayer.controlplane.api.model.BreakglassPolicyResource;
import io.sessionlayer.controlplane.api.model.CreateBreakglassPolicyRequest;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.UpdateBreakglassPolicyRequest;
import io.sessionlayer.controlplane.configapi.BreakglassPolicyConfigService;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.data.config.BreakglassPolicy;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * CRUD for break-glass policies (`config.breakglass_policy`, FR-ACC-6). All
 * operations need {@code breakglass:manage}. Omitted safety toggles fail SAFE:
 * {@code recordingStrict}/{@code reviewRequired} default true and the auth path
 * defaults to {@code fido2}. Every mutation is audited by
 * {@link BreakglassPolicyConfigService}; creates are idempotency-key guarded.
 */
@RestController
public class BreakglassPolicyController implements BreakglassPoliciesApi {

	private final BreakglassPolicyConfigService policies;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public BreakglassPolicyController(BreakglassPolicyConfigService policies, PlatformAccess access,
			IdempotencyService idempotency) {
		this.policies = policies;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<BreakglassPolicyPage>> listBreakglassPolicies(String cursor, Integer limit,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.BREAKGLASS_MANAGE, subject -> policies.list(cursor, limit).map(
				page -> ResponseEntity.ok(new BreakglassPolicyPage(page.items().stream().map(this::toResource).toList())
						.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<BreakglassPolicyResource>> createBreakglassPolicy(
			Mono<CreateBreakglassPolicyRequest> createBreakglassPolicyRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return createBreakglassPolicyRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.BREAKGLASS_MANAGE, subject -> {
					Mono<ResponseEntity<BreakglassPolicyResource>> action = policies
							.create(subject.identity(), req.getName(), orTrue(req.getRecordingStrict()),
									req.getAlertTarget(), orTrue(req.getReviewRequired()), authPath(req.getAuthPath()))
							.map(policy -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(policy)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, BreakglassPolicyResource.class, action);
				}));
	}

	@Override
	public Mono<ResponseEntity<BreakglassPolicyResource>> getBreakglassPolicy(UUID breakglassPolicyId,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.BREAKGLASS_MANAGE,
				subject -> policies.get(breakglassPolicyId).map(policy -> ResponseEntity.ok(toResource(policy))));
	}

	@Override
	public Mono<ResponseEntity<BreakglassPolicyResource>> updateBreakglassPolicy(UUID breakglassPolicyId,
			Mono<UpdateBreakglassPolicyRequest> updateBreakglassPolicyRequest, ServerWebExchange exchange) {
		return updateBreakglassPolicyRequest.flatMap(req -> access.withPermission(PlatformPermissions.BREAKGLASS_MANAGE,
				subject -> policies.update(breakglassPolicyId, subject.identity(), req.getVersion(),
						orTrue(req.getRecordingStrict()), req.getAlertTarget(), orTrue(req.getReviewRequired()),
						authPath(req.getAuthPath())).map(policy -> ResponseEntity.ok(toResource(policy)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteBreakglassPolicy(UUID breakglassPolicyId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.BREAKGLASS_MANAGE, subject -> policies
				.delete(breakglassPolicyId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private BreakglassPolicyResource toResource(BreakglassPolicy policy) {
		BreakglassPolicyResource resource = new BreakglassPolicyResource(policy.id(), policy.name(),
				policy.recordingStrict(), policy.alertTarget(), policy.reviewRequired(),
				BreakglassAuthPath.fromValue(policy.authPath()), Origin.fromValue(policy.origin()), policy.version());
		resource.setCreatedAt(ApiConversions.toOffset(policy.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(policy.updatedAt()));
		return resource;
	}

	// Omitted safety toggles default ON; the auth path defaults to fido2 (matching
	// the column default) so the entity's primitive/non-null fields never see null.
	private static boolean orTrue(Boolean flag) {
		return flag == null || flag;
	}

	private static String authPath(BreakglassAuthPath authPath) {
		return (authPath == null ? BreakglassAuthPath.FIDO2 : authPath).getValue();
	}
}
