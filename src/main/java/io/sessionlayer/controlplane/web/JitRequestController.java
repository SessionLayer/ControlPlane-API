package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.JitRequestsApi;
import io.sessionlayer.controlplane.api.model.JitApproval;
import io.sessionlayer.controlplane.api.model.JitApprovalLevel;
import io.sessionlayer.controlplane.api.model.JitDecisionRequest;
import io.sessionlayer.controlplane.api.model.JitRequestList;
import io.sessionlayer.controlplane.api.model.JitRequestResource;
import io.sessionlayer.controlplane.api.model.JitRequestSubmission;
import io.sessionlayer.controlplane.data.runtime.JitRequest;
import io.sessionlayer.controlplane.jit.JitLifecycleService;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * The secured REST surface for the JIT access model (Design §7; FR-ACC-2/3/4).
 * Submitting a request is open to any authenticated principal (the requester is
 * the authenticated caller, never a body field); approve/deny/revoke are
 * platform-RBAC gated ({@code request:approve}). Self-approval is impossible —
 * enforced in {@link JitLifecycleService}. Every action is audited there; a
 * state-machine error becomes an RFC-9457 problem via
 * {@link JitExceptionHandler}.
 */
@RestController
public class JitRequestController implements JitRequestsApi {

	private final JitLifecycleService jit;
	private final io.sessionlayer.controlplane.data.runtime.JitRequestRepository requests;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;

	public JitRequestController(JitLifecycleService jit,
			io.sessionlayer.controlplane.data.runtime.JitRequestRepository requests,
			PlatformAuthorization platformAuthorization, CurrentAuthentication currentAuthentication) {
		this.jit = jit;
		this.requests = requests;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
	}

	@Override
	public Mono<ResponseEntity<JitRequestResource>> submitJitRequest(Mono<JitRequestSubmission> submission,
			ServerWebExchange exchange) {
		return submission.flatMap(req -> authenticated(subject -> jit
				.submit(subject.identity(), req.getTargetNodeId(), req.getPrincipal(),
						req.getCapabilities() == null ? List.of() : req.getCapabilities(), req.getReason())
				.map(saved -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(saved)))));
	}

	@Override
	public Mono<ResponseEntity<JitRequestList>> listJitRequests(String state, String requester,
			ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.REQUEST_APPROVE,
				subject -> filtered(state, requester).map(JitRequestController::toResource).collectList()
						.map(list -> ResponseEntity.ok(new JitRequestList(list))));
	}

	@Override
	public Mono<ResponseEntity<JitRequestResource>> getJitRequest(UUID jitRequestId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.REQUEST_APPROVE, subject -> requests.findById(jitRequestId)
				.map(r -> ResponseEntity.ok(toResource(r))).defaultIfEmpty(ResponseEntity.notFound().build()));
	}

	@Override
	public Mono<ResponseEntity<JitRequestResource>> approveJitRequest(UUID jitRequestId, Mono<JitDecisionRequest> body,
			ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.REQUEST_APPROVE,
				subject -> reason(body)
						.flatMap(reason -> jit.approve(jitRequestId, subject.identity(), subject.groups(), reason)
								.map(r -> ResponseEntity.ok(toResource(r)))));
	}

	@Override
	public Mono<ResponseEntity<JitRequestResource>> denyJitRequest(UUID jitRequestId, Mono<JitDecisionRequest> body,
			ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.REQUEST_APPROVE,
				subject -> reason(body)
						.flatMap(reason -> jit.deny(jitRequestId, subject.identity(), subject.groups(), reason)
								.map(r -> ResponseEntity.ok(toResource(r)))));
	}

	@Override
	public Mono<ResponseEntity<JitRequestResource>> revokeJitRequest(UUID jitRequestId, Mono<JitDecisionRequest> body,
			ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.REQUEST_APPROVE, subject -> reason(body).flatMap(reason -> jit
				.revoke(jitRequestId, subject.identity(), reason).map(r -> ResponseEntity.ok(toResource(r)))));
	}

	private reactor.core.publisher.Flux<JitRequest> filtered(String state, String requester) {
		if (requester != null && !requester.isBlank()) {
			return requests.findByRequester(requester)
					.filter(r -> state == null || state.isBlank() || state.equals(r.state()));
		}
		if (state != null && !state.isBlank()) {
			return requests.findByState(state);
		}
		return requests.findAll();
	}

	private static Mono<String> reason(Mono<JitDecisionRequest> body) {
		return body.map(req -> req.getReason() == null ? "" : req.getReason()).defaultIfEmpty("");
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

	// Submit needs only authentication (any platform principal may request access).
	private <T> Mono<ResponseEntity<T>> authenticated(Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject().flatMap(action)
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	private static JitRequestResource toResource(JitRequest request) {
		JitRequestResource resource = new JitRequestResource(request.id(), request.requester(), request.principal(),
				request.reason(), request.state(), toOffset(request.requestedAt()));
		resource.setTargetNodeId(request.targetNodeId());
		resource.setTargetNodeName(request.targetNodeName());
		resource.setCapabilities(request.capabilities() == null ? List.of() : request.capabilities());
		resource.setJitPolicyName(request.jitPolicyName());
		resource.setApprovalChain(approvalLevels(request.approvalChain()));
		resource.setApprovals(approvals(request.approvals()));
		resource.setApprovalDeadline(toOffset(request.approvalDeadline()));
		resource.setGrantExpiresAt(toOffset(request.grantExpiresAt()));
		resource.setDecidedAt(toOffset(request.decidedAt()));
		resource.setDecidedBy(request.decidedBy());
		return resource;
	}

	private static List<JitApprovalLevel> approvalLevels(JsonNode chain) {
		List<JitApprovalLevel> levels = new ArrayList<>();
		if (chain != null && chain.isArray()) {
			for (JsonNode level : chain) {
				JitApprovalLevel out = new JitApprovalLevel().value(text(level, "value"));
				String kind = text(level, "kind");
				if ("email".equals(kind) || "oidc_group".equals(kind)) {
					out.setKind(JitApprovalLevel.KindEnum.fromValue(kind));
				}
				levels.add(out);
			}
		}
		return levels;
	}

	private static List<JitApproval> approvals(JsonNode approvals) {
		List<JitApproval> out = new ArrayList<>();
		if (approvals != null && approvals.isArray()) {
			for (JsonNode entry : approvals) {
				out.add(new JitApproval().approver(text(entry, "approver"))
						.level(entry.has("level") ? entry.get("level").asInt() : null).decision(text(entry, "decision"))
						.reason(text(entry, "reason")).at(text(entry, "at")));
			}
		}
		return out;
	}

	private static String text(JsonNode node, String field) {
		JsonNode value = node == null ? null : node.get(field);
		return value != null && value.isString() ? value.stringValue() : null;
	}

	private static OffsetDateTime toOffset(Instant instant) {
		return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
	}
}
