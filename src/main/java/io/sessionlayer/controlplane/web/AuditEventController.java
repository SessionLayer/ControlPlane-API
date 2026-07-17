package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.AuditEventsApi;
import io.sessionlayer.controlplane.api.model.AccessModel;
import io.sessionlayer.controlplane.api.model.AuditEventPage;
import io.sessionlayer.controlplane.api.model.AuditEventResource;
import io.sessionlayer.controlplane.api.model.Capability;
import io.sessionlayer.controlplane.audit.AuditEventSearchService;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditPage;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.audit.AuditScopeMatcher;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformAuthorization.ScopeGrant;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
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
 * Correlated audit-stream search + get ({@code runtime.audit_event}, Design
 * §12.2; FR-AUD-8/9). {@code audit:read}-gated but <b>scope-filtered</b>, not
 * scope-blocked: a node-label/user/time-scoped auditor sees only in-scope rows
 * rather than a {@code 403} ({@link PlatformAuthorization#resolveScopeGrant}).
 * Read-only over the stream — the tamper-evidence chain stays verifiable; the
 * only write is the FR-PADM-3 audit of the access itself
 * ({@link AuditEventSearchService}).
 *
 * <p>
 * Every filter/scope dimension is populated by the connect/JIT/break-glass/
 * recording/session producers (S20 write-path backfill, FR-AUD-8/9): the
 * snapshot columns {@code source_ip}, {@code access_model},
 * {@code capabilities}, {@code node_labels} and {@code correlation_id} are
 * searchable, and one {@code correlation_id} reconstructs a whole approve →
 * connect → run → replay chain. The RBAC node-label scope filter therefore now
 * genuinely narrows.
 */
@RestController
public class AuditEventController implements AuditEventsApi {

	private final AuditEventSearchService search;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final ObjectMapper objectMapper;
	private final AuditSearchProperties properties;

	public AuditEventController(AuditEventSearchService search, PlatformAuthorization platformAuthorization,
			CurrentAuthentication currentAuthentication, ObjectMapper objectMapper, AuditSearchProperties properties) {
		this.search = search;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
		this.objectMapper = objectMapper;
		this.properties = properties;
	}

	@Override
	public Mono<ResponseEntity<AuditEventPage>> searchAuditEvents(String cursor, Integer limit, String actor,
			String subject, String action, String outcome, UUID sessionId, UUID nodeId, String sourceIp,
			OffsetDateTime from, OffsetDateTime to, Capability capability, AccessModel accessModel,
			List<String> nodeLabel, UUID correlationId, ServerWebExchange exchange) {
		return currentAuthentication.subject().flatMap(caller -> platformAuthorization
				.resolveScopeGrant(caller, PlatformPermissions.AUDIT_READ).flatMap(grant -> {
					if (!grant.granted()) {
						return forbidden();
					}
					Window window = resolveWindow(from == null ? null : from.toInstant(),
							to == null ? null : to.toInstant());
					AuditQuery query = new AuditQuery(actor, subject, action, outcome, sessionId, nodeId, sourceIp,
							window.from(), window.to(), capability == null ? null : capability.getValue(),
							accessModel == null ? null : accessModel.getValue(), parseLabels(nodeLabel), correlationId,
							scopeGrants(grant), cursor, CursorPages.clamp(limit));
					return search.search(query, caller.identity()).map(page -> ResponseEntity.ok(toPage(page)));
				})).switchIfEmpty(forbidden());
	}

	@Override
	public Mono<ResponseEntity<AuditEventResource>> getAuditEvent(UUID auditEventId, ServerWebExchange exchange) {
		return currentAuthentication.subject().flatMap(caller -> platformAuthorization
				.resolveScopeGrant(caller, PlatformPermissions.AUDIT_READ).flatMap(grant -> {
					if (!grant.granted()) {
						return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<AuditEventResource>build());
					}
					return search.get(auditEventId, caller.identity())
							.flatMap(event -> grant.unrestricted() || AuditScopeMatcher.inScope(event, grant.scopes())
									? Mono.just(ResponseEntity.ok(toResource(event)))
									: notFound())
							.switchIfEmpty(notFound());
				})).switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<AuditEventResource>build()));
	}

	private static List<JsonNode> scopeGrants(ScopeGrant grant) {
		return grant.unrestricted() ? List.of() : grant.scopes();
	}

	// Out-of-scope and absent are the SAME response so a scoped caller can't probe
	// for the existence of an event outside its scope (FR-AUD-8, no disclosure).
	private static Mono<ResponseEntity<AuditEventResource>> notFound() {
		return Mono.just(ResponseEntity.notFound().<AuditEventResource>build());
	}

	private static Mono<ResponseEntity<AuditEventPage>> forbidden() {
		return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<AuditEventPage>build());
	}

	private static Map<String, String> parseLabels(List<String> nodeLabel) {
		if (nodeLabel == null || nodeLabel.isEmpty()) {
			return Map.of();
		}
		Map<String, String> labels = new LinkedHashMap<>();
		for (String pair : nodeLabel) {
			int eq = pair == null ? -1 : pair.indexOf('=');
			if (eq > 0) {
				labels.put(pair.substring(0, eq), pair.substring(eq + 1));
			}
		}
		return labels;
	}

	// Bound the scan (SESSION §8): give every search a lower time bound so the
	// partitioned audit_event table can prune. An explicit range wider than the max
	// is rejected (422 — a semantic bound on well-formed input); an unfiltered
	// search
	// defaults to the recent window; a range within the max passes through
	// unchanged
	// (no surprise for the auditor).
	private Window resolveWindow(Instant from, Instant to) {
		Duration max = properties.getMaxWindow();
		if (from != null && to != null) {
			if (Duration.between(from, to).compareTo(max) > 0) {
				throw tooWide(max);
			}
			return new Window(from, to);
		}
		Instant now = Instant.now();
		if (from != null) {
			if (Duration.between(from, now).compareTo(max) > 0) {
				throw tooWide(max);
			}
			return new Window(from, null); // open to now, already bounded below by from
		}
		if (to != null) {
			return new Window(to.minus(max), to); // bound the backward side to the max window
		}
		return new Window(now.minus(properties.getDefaultWindow()), null);
	}

	private static ApiProblemException tooWide(Duration max) {
		return ApiProblemException.validation("audit search time window exceeds the maximum of " + max);
	}

	private record Window(Instant from, Instant to) {
	}

	private AuditEventPage toPage(AuditPage page) {
		return new AuditEventPage(page.items().stream().map(this::toResource).toList()).nextCursor(page.nextCursor());
	}

	private AuditEventResource toResource(AuditEvent event) {
		AuditEventResource resource = new AuditEventResource(event.id(), ApiConversions.toOffset(event.occurredAt()),
				event.actor(), event.action(), event.outcome());
		resource.setSubject(event.subject());
		resource.setSessionId(event.sessionId());
		resource.setNodeId(event.nodeId());
		resource.setCorrelationId(event.correlationId());
		resource.setSourceIp(event.sourceIp());
		// FR-AUD-8 completeness: expose the capability + node-label dimensions the
		// auditor can already filter on, so a returned event is readable, not just
		// searchable (access_model remains in detail).
		resource.setCapabilities(event.capabilities());
		resource.setNodeLabels(labelMap(event.nodeLabels()));
		resource.setDetail(ApiConversions.toMap(objectMapper, event.detail()));
		return resource;
	}

	private static Map<String, String> labelMap(JsonNode node) {
		if (node == null || !node.isObject()) {
			return null;
		}
		Map<String, String> labels = new LinkedHashMap<>();
		for (Map.Entry<String, JsonNode> entry : node.properties()) {
			if (entry.getValue() != null && entry.getValue().isString()) {
				labels.put(entry.getKey(), entry.getValue().stringValue());
			}
		}
		return labels;
	}
}
