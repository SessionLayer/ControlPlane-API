package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@code GET /v1/audit-events} search + get end to end (FR-AUD-8/9,
 * FR-PADM-2/3): every filter dimension, RBAC scope-filtering
 * (node-label/user/time/unrestricted and the no-grant {@code 403}), the
 * correlated stream, keyset pagination, and the read-only-over-the-chain
 * invariant. Shares the {@link AbstractConfigApiIT} singleton container, so
 * every assertion isolates its own rows by a per-test
 * {@code correlationId}/{@code sessionId} (the append-only stream cannot be
 * reset).
 */
class AuditEventSearchIT extends AbstractConfigApiIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	// Relative to now (hours ago) so seeded events always fall inside the default
	// audit-search window (F8) regardless of the wall-clock date the suite runs on.
	private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MICROS);
	private static final Instant T1 = NOW.minus(Duration.ofHours(4));
	private static final Instant T2 = NOW.minus(Duration.ofHours(3));
	private static final Instant T3 = NOW.minus(Duration.ofHours(2));
	private static final Instant T4 = NOW.minus(Duration.ofHours(1));

	@Autowired
	private AuditEventStore store;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private ServiceAccountRepository serviceAccounts;
	@Autowired
	private MachineIdentityService machineIdentity;
	@Autowired
	private PlatformRoleRepository roles;
	@Autowired
	private RoleBindingRepository bindings;

	@Test
	void eachFilterDimensionReturnsTheMatchingRows() {
		UUID run = UUID.randomUUID();
		UUID s1 = UUID.randomUUID();
		UUID s2 = UUID.randomUUID();
		UUID n1 = UUID.randomUUID();
		UUID n2 = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		AuditEvent e1 = seed("alice-" + tag, "subj1-" + tag, "act.one", "success", run, s1, n1, "10.0.0.1", "standing",
				List.of("shell"), labels("env", "prod", "region", "us"), T1);
		AuditEvent e2 = seed("bob-" + tag, "subj2-" + tag, "act.two", "denied", run, s2, n2, "10.0.0.2", "jit",
				List.of("exec"), labels("env", "dev"), T2);
		AuditEvent e3 = seed("alice-" + tag, "subj3-" + tag, "act.two", "success", run, s1, n1, "10.0.0.1",
				"breakglass", List.of("shell", "sftp"), labels("env", "prod"), T3);

		String token = tokenWith("svc-audit-dims-" + run, PlatformPermissions.AUDIT_READ);

		assertThat(ids(query(token, "correlationId", run.toString()))).containsExactlyInAnyOrder(e1.id(), e2.id(),
				e3.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "actor", "alice-" + tag)))
				.containsExactlyInAnyOrder(e1.id(), e3.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "subject", "subj2-" + tag)))
				.containsExactly(e2.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "action", "act.two")))
				.containsExactlyInAnyOrder(e2.id(), e3.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "outcome", "denied"))).containsExactly(e2.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "sessionId", s2.toString())))
				.containsExactly(e2.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "nodeId", n1.toString())))
				.containsExactlyInAnyOrder(e1.id(), e3.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "sourceIp", "10.0.0.2"))).containsExactly(e2.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "capability", "exec"))).containsExactly(e2.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "accessModel", "breakglass")))
				.containsExactly(e3.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "nodeLabel", "env=prod")))
				.containsExactlyInAnyOrder(e1.id(), e3.id());
		assertThat(
				ids(query(token, "correlationId", run.toString(), "nodeLabel", "env=prod", "nodeLabel", "region=us")))
				.containsExactly(e1.id());
		// occurred_at >= from (inclusive) and < to (exclusive), matching the SQL.
		assertThat(ids(query(token, "correlationId", run.toString(), "from", T2.toString())))
				.containsExactlyInAnyOrder(e2.id(), e3.id());
		assertThat(ids(query(token, "correlationId", run.toString(), "to", T2.toString()))).containsExactly(e1.id());
	}

	@Test
	void nodeLabelScopedAuditorSeesOnlyInScopeUnscopedSeesAll() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		AuditEvent prod = seed("u-" + tag, null, "scope.probe", "success", run, null, null, null, null, null,
				labels("env", "prod"), T1);
		AuditEvent dev = seed("u-" + tag, null, "scope.probe", "success", run, null, null, null, null, null,
				labels("env", "dev"), T1);

		ObjectNode scope = JSON.objectNode();
		scope.set("node_labels", JSON.objectNode().put("env", "prod"));
		String scoped = scopedToken("svc-audit-lblscope-" + run, scope, PlatformPermissions.AUDIT_READ);
		assertThat(ids(query(scoped, "correlationId", run.toString()))).containsExactly(prod.id());

		String unscoped = tokenWith("svc-audit-all-" + run, PlatformPermissions.AUDIT_READ);
		assertThat(ids(query(unscoped, "correlationId", run.toString()))).containsExactlyInAnyOrder(prod.id(),
				dev.id());
	}

	@Test
	void userScopedAuditorMatchesActorOrSubject() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		String alice = "alice-" + tag;
		AuditEvent byActor = seed(alice, "someone", "scope.user", "success", run, null, null, null, null, null, null,
				T1);
		AuditEvent bySubject = seed("carol-" + tag, alice, "scope.user", "success", run, null, null, null, null, null,
				null, T2);
		AuditEvent unrelated = seed("bob-" + tag, "bob-" + tag, "scope.user", "success", run, null, null, null, null,
				null, null, T3);

		ObjectNode scope = JSON.objectNode();
		scope.set("users", JSON.arrayNode().add(alice));
		String scoped = scopedToken("svc-audit-userscope-" + run, scope, PlatformPermissions.AUDIT_READ);
		assertThat(ids(query(scoped, "correlationId", run.toString()))).containsExactlyInAnyOrder(byActor.id(),
				bySubject.id());
		assertThat(ids(query(scoped, "correlationId", run.toString()))).doesNotContain(unrelated.id());
	}

	@Test
	void timeScopedAuditorSeesOnlyTheWindow() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		AuditEvent before = seed("u-" + tag, null, "scope.time", "success", run, null, null, null, null, null, null,
				T1);
		AuditEvent inside = seed("u-" + tag, null, "scope.time", "success", run, null, null, null, null, null, null,
				T3);

		ObjectNode time = JSON.objectNode();
		time.put("not_before", T2.toString());
		time.put("not_after", T4.toString());
		ObjectNode scope = JSON.objectNode();
		scope.set("time", time);
		String scoped = scopedToken("svc-audit-timescope-" + run, scope, PlatformPermissions.AUDIT_READ);
		assertThat(ids(query(scoped, "correlationId", run.toString()))).containsExactly(inside.id());
		assertThat(ids(query(scoped, "correlationId", run.toString()))).doesNotContain(before.id());
	}

	@Test
	void degenerateScopeMatchesNothingAndSearchAndGetAgree() {
		// A present-but-degenerate scope facet ({"node_labels":{}}) constrains nothing,
		// so it must cover NOTHING (fail closed). The search predicate (AuditSearchSql)
		// and the single-event scope check (PlatformScopes.covers via
		// AuditScopeMatcher)
		// MUST agree — else a scoped auditor reads via GET /{id} an event the search
		// hid.
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		AuditEvent event = seed("u-" + tag, null, "scope.degenerate", "success", run, null, null, null, null, null,
				labels("env", "prod"), T3);

		ObjectNode scope = JSON.objectNode();
		scope.set("node_labels", JSON.objectNode()); // empty object => no effective constraint
		String scoped = scopedToken("svc-audit-degenerate-" + run, scope, PlatformPermissions.AUDIT_READ);
		assertThat(ids(query(scoped, "correlationId", run.toString()))).isEmpty();
		assertThat(getStatus(scoped, event.id())).isEqualTo(404);

		// The event genuinely exists — an unrestricted auditor gets it — so the scoped
		// 404 is a scope denial, not a missing row.
		String unrestricted = tokenWith("svc-audit-degen-all-" + run, PlatformPermissions.AUDIT_READ);
		assertThat(getStatus(unrestricted, event.id())).isEqualTo(200);
	}

	@Test
	void noAuditReadBindingIsForbidden() {
		UUID run = UUID.randomUUID();
		String none = tokenWith("svc-audit-none-" + run);
		client.get().uri("/v1/audit-events").header("Authorization", "Bearer " + none).exchange().expectStatus()
				.isForbidden();
		// A binding for a DIFFERENT permission also does not admit audit search.
		String other = tokenWith("svc-audit-other-" + run, PlatformPermissions.LOCK_READ);
		client.get().uri("/v1/audit-events").header("Authorization", "Bearer " + other).exchange().expectStatus()
				.isForbidden();
	}

	// GET /v1/audit-events/{id} (implemented on main; not a 501): a scoped caller
	// whose grant COVERS the event reads it (200); an absent id is an
	// indistinguishable 404 for a permitted caller; no audit:read grant is 403.
	@Test
	void getByIdHonoursScopeAbsenceAndGrant() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		AuditEvent event = seed("u-" + tag, null, "scope.get", "success", run, null, null, null, null, null,
				labels("env", "prod"), T3);

		ObjectNode inScope = JSON.objectNode();
		inScope.set("node_labels", JSON.objectNode().put("env", "prod"));
		String scoped = scopedToken("svc-audit-getins-" + run, inScope, PlatformPermissions.AUDIT_READ);
		assertThat(getStatus(scoped, event.id())).isEqualTo(200);

		String all = tokenWith("svc-audit-getabsent-" + run, PlatformPermissions.AUDIT_READ);
		assertThat(getStatus(all, UUID.randomUUID())).isEqualTo(404);

		String none = tokenWith("svc-audit-getnograntget-" + run);
		assertThat(getStatus(none, event.id())).isEqualTo(403);
	}

	// FR-AUD-8 completeness: an auditor can filter by capability/node-label, so a
	// returned event must also PROJECT them (not just source_ip/correlation_id).
	@Test
	void returnedEventProjectsCapabilitiesAndNodeLabels() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		seed("u-" + tag, null, "proj.dims", "success", run, null, null, null, "standing", List.of("shell", "sftp"),
				labels("env", "prod"), T3);

		String token = tokenWith("svc-audit-proj-" + run, PlatformPermissions.AUDIT_READ);
		JsonNode item = items(query(token, "correlationId", run.toString())).get(0);

		List<String> caps = new ArrayList<>();
		item.get("capabilities").forEach(c -> caps.add(c.asString()));
		assertThat(caps).containsExactlyInAnyOrder("shell", "sftp");
		assertThat(item.get("nodeLabels").get("env").asString()).isEqualTo("prod");
	}

	@Test
	void correlatedStreamReconstructsApproveConnectRunReplay() {
		// The primary correlation key in this codebase is session_id — connect/run/
		// sftp/recording.* all carry it (correlation_id is used where an event sets
		// it).
		// A session_id search returns the whole SSH+admin path for one session.
		UUID session = UUID.randomUUID();
		String tag = session.toString().substring(0, 8);
		seed("actor-" + tag, "actor-" + tag, "request.approve", "success", null, session, null, null, "jit", null, null,
				T1);
		seed("actor-" + tag, null, "session.connect", "success", null, session, null, "10.0.0.9", "jit", null, null,
				T2);
		seed("actor-" + tag, null, "session.run", "success", null, session, null, null, "jit", List.of("shell"), null,
				T3);
		seed("auditor-" + tag, "actor-" + tag, "recording.replay", "success", null, session, null, null, null, null,
				null, T4);

		String token = tokenWith("svc-audit-corr-" + session, PlatformPermissions.AUDIT_READ);
		List<JsonNode> items = items(query(token, "sessionId", session.toString()));
		assertThat(items).hasSize(4);
		// The query is newest-first by id; sorting the path by occurred_at reconstructs
		// the chronological approve -> connect -> run -> replay sequence.
		List<String> chronological = items.stream().sorted((a, b) -> occurredAt(a).compareTo(occurredAt(b)))
				.map(i -> i.get("action").asString()).toList();
		assertThat(chronological).containsExactly("request.approve", "session.connect", "session.run",
				"recording.replay");
	}

	@Test
	void searchAndGetLeaveTheChainVerifiableAndHeadUnchanged() {
		// Seed genuine CHAINED rows through the store so there is a real head to pin.
		for (int i = 0; i < 3; i++) {
			store.record("chain-probe", null, "readonly.probe", "success", UUID.randomUUID(), null,
					Map.of("i", Integer.toString(i))).block();
		}
		assertThat(store.verifyChain().block().valid()).isTrue();
		String headBefore = chainHead();

		AuditQuery all = new AuditQuery(null, null, null, null, null, null, null, null, null, null, null, Map.of(),
				null, List.of(), null, 50);
		for (int i = 0; i < 3; i++) {
			store.search(all).block();
			store.findById(UUID.randomUUID()).block();
		}
		// The pure read path mutates nothing: same valid chain, same head.
		assertThat(store.verifyChain().block().valid()).isTrue();
		assertThat(chainHead()).isEqualTo(headBefore);

		// Going through the endpoint appends one audit.search (FR-PADM-3) — a
		// legitimate
		// new link that keeps the chain verifiable (it never rewrites an existing row).
		String token = tokenWith("svc-audit-ro-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		client.get().uri("/v1/audit-events?limit=1").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk();
		assertThat(store.verifyChain().block().valid()).isTrue();
	}

	@Test
	void paginationIsNewestFirstKeysetAndMalformedCursorIs400() {
		UUID run = UUID.randomUUID();
		String tag = run.toString().substring(0, 8);
		List<UUID> seeded = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			seeded.add(seed("page-" + tag, null, "page.probe", "success", run, null, null, null, null, null, null, T1)
					.id());
		}
		List<UUID> expected = seeded.stream().sorted((a, b) -> b.compareTo(a)).toList(); // newest-first (id DESC)

		String token = tokenWith("svc-audit-page-" + run, PlatformPermissions.AUDIT_READ);
		List<UUID> paged = new ArrayList<>();
		String cursor = null;
		int pages = 0;
		do {
			JsonNode page = cursor == null
					? query(token, "correlationId", run.toString(), "limit", "2")
					: query(token, "correlationId", run.toString(), "limit", "2", "cursor", cursor);
			paged.addAll(ids(page));
			cursor = page.hasNonNull("nextCursor") ? page.get("nextCursor").asString() : null;
			pages++;
		} while (cursor != null && pages < 10);
		assertThat(paged).containsExactlyElementsOf(expected);
		assertThat(pages).isEqualTo(3); // 2 + 2 + 1

		client.get().uri("/v1/audit-events?cursor=notacursor").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isBadRequest();
	}

	// ----------------------- helpers -----------------------

	private AuditEvent seed(String actor, String subject, String action, String outcome, UUID correlationId,
			UUID sessionId, UUID nodeId, String sourceIp, String accessModel, List<String> capabilities,
			JsonNode nodeLabels, Instant occurredAt) {
		AuditEvent event = AuditEvent.create(occurredAt, actor, subject, action, outcome, correlationId, sessionId,
				nodeId, nodeLabels, sourceIp, accessModel, capabilities, JSON.objectNode());
		return auditEvents.save(event).block();
	}

	private static JsonNode labels(String... kv) {
		ObjectNode node = JSON.objectNode();
		for (int i = 0; i + 1 < kv.length; i += 2) {
			node.put(kv[i], kv[i + 1]);
		}
		return node;
	}

	private JsonNode query(String token, String... params) {
		var result = client.get().uri(uri -> {
			uri.path("/v1/audit-events");
			for (int i = 0; i + 1 < params.length; i += 2) {
				uri.queryParam(params[i], params[i + 1]);
			}
			return uri.build();
		}).header("Authorization", "Bearer " + token).exchange().expectBody().returnResult();
		byte[] body = result.getResponseBody();
		if (result.getStatus().value() != 200) {
			throw new AssertionError("query " + java.util.Arrays.toString(params) + " -> " + result.getStatus()
					+ " body=" + (body == null ? "" : new String(body, java.nio.charset.StandardCharsets.UTF_8)));
		}
		return objectMapper.readTree(body);
	}

	private int getStatus(String token, UUID id) {
		return client.get().uri("/v1/audit-events/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectBody().returnResult().getStatus().value();
	}

	private List<JsonNode> items(JsonNode page) {
		List<JsonNode> items = new ArrayList<>();
		page.get("items").forEach(items::add);
		return items;
	}

	private List<UUID> ids(JsonNode page) {
		return items(page).stream().map(i -> UUID.fromString(i.get("id").asString())).toList();
	}

	private static Instant occurredAt(JsonNode item) {
		return OffsetDateTime.parse(item.get("occurredAt").asString()).toInstant();
	}

	private String chainHead() {
		List<AuditEvent> chain = auditEvents.findChainOrdered().collectList().block();
		return chain.isEmpty() ? null : chain.get(chain.size() - 1).recordHash();
	}

	private String scopedToken(String saName, JsonNode scope, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		PlatformRole role = roles
				.save(PlatformRole.create("role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
				.block();
		bindings.save(RoleBinding.create(role.id(), "user", saName, scope, "default")).block();
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
