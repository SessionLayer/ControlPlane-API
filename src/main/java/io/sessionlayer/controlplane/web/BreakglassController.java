package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.BreakglassApi;
import io.sessionlayer.controlplane.api.model.BreakglassActivationList;
import io.sessionlayer.controlplane.api.model.BreakglassActivationResource;
import io.sessionlayer.controlplane.api.model.BreakglassCredentialList;
import io.sessionlayer.controlplane.api.model.BreakglassCredentialResource;
import io.sessionlayer.controlplane.api.model.BreakglassOfflineCodeList;
import io.sessionlayer.controlplane.api.model.BreakglassOfflineCodeResource;
import io.sessionlayer.controlplane.api.model.IssueBreakglassOfflineCodesRequest;
import io.sessionlayer.controlplane.api.model.IssuedBreakglassOfflineCodes;
import io.sessionlayer.controlplane.api.model.RegisterBreakglassCredentialRequest;
import io.sessionlayer.controlplane.api.model.ReviewBreakglassActivationRequest;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.breakglass.BreakglassCredentialService;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivationRepository;
import io.sessionlayer.controlplane.data.runtime.BreakglassCredential;
import io.sessionlayer.controlplane.data.runtime.BreakglassOfflineCode;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The secured REST surface for break-glass management (Design §7; FR-ACC-6).
 * All routes are platform-RBAC gated ({@code breakglass:manage}) + audited:
 * register/ revoke FIDO2 credentials, issue/list single-use offline codes (raw
 * codes shown exactly once), and list + review activations (an unreviewed
 * activation is a standing signal). Only PUBLIC key material and code/token
 * HASHES are ever stored; a validation failure becomes an RFC-9457 400 via
 * {@link BreakglassExceptionHandler}.
 */
@RestController
public class BreakglassController implements BreakglassApi {

	private final BreakglassCredentialService credentials;
	private final BreakglassActivationRepository activations;
	private final AuditEventStore audit;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final ObjectMapper objectMapper;

	public BreakglassController(BreakglassCredentialService credentials, BreakglassActivationRepository activations,
			AuditEventStore audit, PlatformAuthorization platformAuthorization,
			CurrentAuthentication currentAuthentication, ObjectMapper objectMapper) {
		this.credentials = credentials;
		this.activations = activations;
		this.audit = audit;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
		this.objectMapper = objectMapper;
	}

	@Override
	public Mono<ResponseEntity<BreakglassCredentialResource>> registerBreakglassCredential(
			Mono<RegisterBreakglassCredentialRequest> body, ServerWebExchange exchange) {
		return body.flatMap(req -> withPermission(PlatformPermissions.BREAKGLASS_MANAGE,
				subject -> credentials
						.register(req.getPublicKey(), req.getIdentity(), req.getAllowedPrincipals(),
								nodeSelector(req.getNodeIds()), toInstant(req.getExpiresAt()), subject.identity())
						.map(saved -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(saved)))));
	}

	@Override
	public Mono<ResponseEntity<BreakglassCredentialList>> listBreakglassCredentials(ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.BREAKGLASS_MANAGE,
				subject -> credentials.list().map(BreakglassController::toResource).collectList()
						.map(list -> ResponseEntity.ok(new BreakglassCredentialList(list))));
	}

	@Override
	public Mono<ResponseEntity<Void>> revokeBreakglassCredential(UUID credentialId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.BREAKGLASS_MANAGE, subject -> credentials
				.revoke(credentialId, subject.identity()).thenReturn(ResponseEntity.noContent().<Void>build()));
	}

	@Override
	public Mono<ResponseEntity<IssuedBreakglassOfflineCodes>> issueBreakglassOfflineCodes(
			Mono<IssueBreakglassOfflineCodesRequest> body, ServerWebExchange exchange) {
		return body.flatMap(req -> withPermission(PlatformPermissions.BREAKGLASS_MANAGE, subject -> credentials
				.issueOfflineCodes(req.getIdentity(), req.getAllowedPrincipals(), nodeSelector(req.getNodeIds()),
						req.getSourceCidr(), req.getCount(), toInt(req.getTtlSeconds()), subject.identity())
				.map(issued -> ResponseEntity.status(HttpStatus.CREATED).body(new IssuedBreakglassOfflineCodes(
						issued.ids(), issued.rawCodes(), toOffset(issued.expiresAt()))))));
	}

	@Override
	public Mono<ResponseEntity<BreakglassOfflineCodeList>> listBreakglassOfflineCodes(ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.BREAKGLASS_MANAGE,
				subject -> credentials.listOfflineCodes().map(BreakglassController::toResource).collectList()
						.map(list -> ResponseEntity.ok(new BreakglassOfflineCodeList(list))));
	}

	@Override
	public Mono<ResponseEntity<BreakglassActivationList>> listBreakglassActivations(String reviewStatus,
			ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.BREAKGLASS_MANAGE,
				subject -> activationsFiltered(reviewStatus).map(BreakglassController::toResource).collectList()
						.map(list -> ResponseEntity.ok(new BreakglassActivationList(list))));
	}

	@Override
	public Mono<ResponseEntity<BreakglassActivationResource>> reviewBreakglassActivation(UUID activationId,
			Mono<ReviewBreakglassActivationRequest> body, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.BREAKGLASS_MANAGE,
				subject -> note(body).flatMap(note -> activations.findById(activationId).flatMap(activation -> {
					BreakglassActivation reviewed = activation.reviewed(subject.identity(), Instant.now());
					Map<String, String> detail = new java.util.HashMap<>();
					detail.put("activation_id", activationId.toString());
					if (!note.isBlank()) {
						detail.put("note", note);
					}
					return activations.save(reviewed)
							.then(audit.record(subject.identity(), reviewed.identity(), "breakglass.review", "success",
									null, reviewed.targetNodeId(), detail))
							.thenReturn(ResponseEntity.ok(toResource(reviewed)));
				}).defaultIfEmpty(ResponseEntity.notFound().build())));
	}

	private reactor.core.publisher.Flux<BreakglassActivation> activationsFiltered(String reviewStatus) {
		return reviewStatus == null || reviewStatus.isBlank()
				? activations.findAll()
				: activations.findByReviewStatus(reviewStatus);
	}

	private static Mono<String> note(Mono<ReviewBreakglassActivationRequest> body) {
		return body.map(req -> req.getNote() == null ? "" : req.getNote()).defaultIfEmpty("");
	}

	private ObjectNode nodeSelector(List<UUID> nodeIds) {
		if (nodeIds == null || nodeIds.isEmpty()) {
			return null; // fleet-scoped
		}
		ObjectNode selector = objectMapper.createObjectNode();
		ArrayNode ids = selector.putArray("node_ids");
		nodeIds.forEach(id -> ids.add(id.toString()));
		return selector;
	}

	private <T> Mono<ResponseEntity<T>> withPermission(String permission,
			Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject()
				.flatMap(subject -> platformAuthorization.authorize(subject, permission, null)
						.flatMap(decision -> decision.allowed()
								? action.apply(subject)
								: Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<T>build())))
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	private static BreakglassCredentialResource toResource(BreakglassCredential credential) {
		BreakglassCredentialResource resource = new BreakglassCredentialResource(credential.id(),
				credential.keyFingerprint(), credential.identity(),
				credential.allowedPrincipals() == null ? List.of() : credential.allowedPrincipals(),
				toOffset(credential.createdAt()));
		resource.setSkApplication(credential.skApplication());
		resource.setNodeIds(nodeIdsOf(credential.nodeSelector()));
		resource.setExpiresAt(toOffset(credential.expiresAt()));
		resource.setRevokedAt(toOffset(credential.revokedAt()));
		resource.setCreatedBy(credential.createdBy());
		return resource;
	}

	private static BreakglassOfflineCodeResource toResource(BreakglassOfflineCode code) {
		BreakglassOfflineCodeResource resource = new BreakglassOfflineCodeResource(code.id(), code.identity(),
				toOffset(code.expiresAt()), code.used());
		resource.setAllowedPrincipals(code.allowedPrincipals() == null ? List.of() : code.allowedPrincipals());
		resource.setSourceCidr(code.sourceCidr());
		resource.setUsedAt(toOffset(code.usedAt()));
		resource.setRevokedAt(toOffset(code.revokedAt()));
		resource.setCreatedBy(code.createdBy());
		resource.setCreatedAt(toOffset(code.createdAt()));
		return resource;
	}

	private static BreakglassActivationResource toResource(BreakglassActivation activation) {
		BreakglassActivationResource resource = new BreakglassActivationResource(activation.id(),
				activation.principal(), activation.reason(),
				BreakglassActivationResource.ReviewStatusEnum.fromValue(activation.reviewStatus()),
				toOffset(activation.activatedAt()));
		resource.setIdentity(activation.identity());
		resource.setAlertRef(activation.alertRef());
		resource.setBreakglassPolicyName(activation.breakglassPolicyName());
		resource.setReviewer(activation.reviewer());
		resource.setSourceIp(activation.sourceIp());
		resource.setTargetNodeId(activation.targetNodeId());
		resource.setCredentialRef(activation.credentialRef());
		resource.setReviewedAt(toOffset(activation.reviewedAt()));
		return resource;
	}

	private static List<UUID> nodeIdsOf(JsonNode selector) {
		List<UUID> ids = new ArrayList<>();
		if (selector != null && selector.isObject()) {
			JsonNode array = selector.get("node_ids");
			if (array != null && array.isArray()) {
				for (JsonNode element : array) {
					if (element.isString()) {
						try {
							ids.add(UUID.fromString(element.stringValue()));
						} catch (IllegalArgumentException ignored) {
							// a malformed stored id is simply omitted from the projection
						}
					}
				}
			}
		}
		return ids;
	}

	private static Integer toInt(Long value) {
		return value == null ? null : Math.toIntExact(value);
	}

	private static Instant toInstant(OffsetDateTime value) {
		return value == null ? null : value.toInstant();
	}

	private static OffsetDateTime toOffset(Instant instant) {
		return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
	}
}
