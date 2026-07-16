package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;
import tools.jackson.databind.node.JsonNodeFactory;

/**
 * The FR-AUD-8 / SESSION §8 audit-search time-window bound (F8): an unfiltered
 * search is pruned to a recent default window (so the partitioned
 * {@code audit_event} table can prune), an explicit range within the maximum is
 * honored verbatim, and a range wider than the maximum is rejected
 * ({@code 422} — a semantic bound on well-formed input). Uses small test windows
 * so the bounds are exercised against rows in the current partition.
 */
@TestPropertySource(properties = {"sessionlayer.audit.search.default-window=PT1H",
		"sessionlayer.audit.search.max-window=PT2H"})
class AuditSearchWindowIT extends AbstractConfigApiIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Test
	void unfilteredSearchIsBoundedToTheDefaultWindow() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		AuditEvent recent = seed("w-" + tag, run, Instant.now().minus(Duration.ofMinutes(10)));
		seed("w-" + tag, run, Instant.now().minus(Duration.ofMinutes(90))); // outside the 1h default window

		String token = tokenWith("svc-window-default-" + run, PlatformPermissions.AUDIT_READ);
		// No from/to: the default window prunes to recent, so the 90-min-old row is
		// gone.
		client.get().uri("/v1/audit-events?correlationId=" + run).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.items.length()").isEqualTo(1).jsonPath("$.items[0].id")
				.isEqualTo(recent.id().toString());
	}

	@Test
	void explicitRangeWithinMaxIsHonoredVerbatim() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		seed("w-" + tag, run, Instant.now().minus(Duration.ofMinutes(10)));
		seed("w-" + tag, run, Instant.now().minus(Duration.ofMinutes(90)));

		String token = tokenWith("svc-window-range-" + run, PlatformPermissions.AUDIT_READ);
		OffsetDateTime from = OffsetDateTime.ofInstant(Instant.now().minus(Duration.ofMinutes(100)), ZoneOffset.UTC);
		OffsetDateTime to = OffsetDateTime.ofInstant(Instant.now(), ZoneOffset.UTC);
		// Span ~100 min <= max (2h): an explicit in-range query is NOT re-bounded to
		// the
		// default window, so both rows come back (no surprise for the auditor).
		client.get()
				.uri(uri -> uri.path("/v1/audit-events").queryParam("correlationId", run.toString())
						.queryParam("from", from.toString()).queryParam("to", to.toString()).build())
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().expectBody()
				.jsonPath("$.items.length()").isEqualTo(2);
	}

	@Test
	void rangeWiderThanMaxIsRejected() {
		String token = tokenWith("svc-window-toowide-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		OffsetDateTime from = OffsetDateTime.ofInstant(Instant.now().minus(Duration.ofHours(3)), ZoneOffset.UTC);
		OffsetDateTime to = OffsetDateTime.ofInstant(Instant.now(), ZoneOffset.UTC);
		// Span 3h > max (2h) -> rejected before any DB access. 422 (VALIDATION), not
		// 400:
		// the request is well-formed but violates a semantic bound — matching the
		// repo's
		// convention (malformed=400, semantic pre-commit rejection=422; see
		// ApiProblemType).
		client.get()
				.uri(uri -> uri.path("/v1/audit-events").queryParam("from", from.toString())
						.queryParam("to", to.toString()).build())
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isEqualTo(422);
	}

	private AuditEvent seed(String actor, UUID correlationId, Instant occurredAt) {
		AuditEvent event = AuditEvent.create(occurredAt.truncatedTo(ChronoUnit.MICROS), actor, null, "window.probe",
				"success", correlationId, null, null, null, null, null, null, JSON.objectNode());
		return auditEvents.save(event).block();
	}
}
