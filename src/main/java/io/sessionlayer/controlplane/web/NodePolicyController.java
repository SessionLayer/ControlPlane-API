package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.NodePoliciesApi;
import io.sessionlayer.controlplane.api.model.ConnectorKind;
import io.sessionlayer.controlplane.api.model.CreateNodePolicyRequest;
import io.sessionlayer.controlplane.api.model.NodePolicyPage;
import io.sessionlayer.controlplane.api.model.NodePolicyResource;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.UpdateNodePolicyRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.NodePolicyConfigService;
import io.sessionlayer.controlplane.data.config.NodePolicy;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * CRUD for node policies (`config.node_policy`, Design §12A). All operations
 * need {@code settings:write}. Every mutation is audited + pre-commit-validated
 * by {@link NodePolicyConfigService}; creates are idempotency-key guarded.
 */
@RestController
public class NodePolicyController implements NodePoliciesApi {

	private final NodePolicyConfigService policies;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;
	private final ObjectMapper mapper;

	public NodePolicyController(NodePolicyConfigService policies, PlatformAccess access, IdempotencyService idempotency,
			ObjectMapper mapper) {
		this.policies = policies;
		this.access = access;
		this.idempotency = idempotency;
		this.mapper = mapper;
	}

	@Override
	public Mono<ResponseEntity<NodePolicyPage>> listNodePolicies(String cursor, Integer limit,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> policies.list(cursor, limit)
				.map(page -> ResponseEntity.ok(new NodePolicyPage(page.items().stream().map(this::toResource).toList())
						.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<NodePolicyResource>> createNodePolicy(
			Mono<CreateNodePolicyRequest> createNodePolicyRequest, String idempotencyKey, ServerWebExchange exchange) {
		return createNodePolicyRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> {
					Mono<ResponseEntity<NodePolicyResource>> action = policies
							.create(subject.identity(), req.getName(), labelsJson(req.getDesiredLabels()),
									req.getConnectorKind().getValue(), req.getHostPinRef(), req.getHostCaRef())
							.map(policy -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(policy)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, NodePolicyResource.class, action);
				}));
	}

	@Override
	public Mono<ResponseEntity<NodePolicyResource>> getNodePolicy(UUID nodePolicyId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> policies.get(nodePolicyId).map(policy -> ResponseEntity.ok(toResource(policy))));
	}

	@Override
	public Mono<ResponseEntity<NodePolicyResource>> updateNodePolicy(UUID nodePolicyId,
			Mono<UpdateNodePolicyRequest> updateNodePolicyRequest, ServerWebExchange exchange) {
		return updateNodePolicyRequest.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> policies
						.update(nodePolicyId, subject.identity(), req.getVersion(), labelsJson(req.getDesiredLabels()),
								req.getConnectorKind().getValue(), req.getHostPinRef(), req.getHostCaRef())
						.map(policy -> ResponseEntity.ok(toResource(policy)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteNodePolicy(UUID nodePolicyId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> policies
				.delete(nodePolicyId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private NodePolicyResource toResource(NodePolicy policy) {
		NodePolicyResource resource = new NodePolicyResource(policy.id(), policy.name(), labels(policy.desiredLabels()),
				ConnectorKind.fromValue(policy.connectorKind()), Origin.fromValue(policy.origin()), policy.version());
		resource.setHostPinRef(policy.hostPinRef());
		resource.setHostCaRef(policy.hostCaRef());
		resource.setCreatedAt(ApiConversions.toOffset(policy.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(policy.updatedAt()));
		return resource;
	}

	private JsonNode labelsJson(Map<String, String> labels) {
		return labels == null ? mapper.createObjectNode() : mapper.valueToTree(labels);
	}

	@SuppressWarnings("unchecked")
	private Map<String, String> labels(JsonNode node) {
		return node == null || node.isNull() ? Map.of() : mapper.convertValue(node, Map.class);
	}
}
