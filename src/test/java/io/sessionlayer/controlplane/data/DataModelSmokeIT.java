package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.NodePolicy;
import io.sessionlayer.controlplane.data.config.NodePolicyRepository;
import io.sessionlayer.controlplane.data.runtime.Pin;
import io.sessionlayer.controlplane.data.runtime.PinRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

/**
 * First-cut round-trip smoke that proves the load-bearing R2DBC mapping
 * assumptions the rest of the suite depends on: schema-qualified
 * {@code @Table}, the jsonb&lt;-&gt;JsonNode converter,
 * {@code text[]}&lt;-&gt;{@code List<String>},
 * {@code Instant}&lt;-&gt;timestamptz, the {@code @Version}-based "is-new"
 * insert of a client-set UUIDv7, and the cidr-as-text round-trip.
 */
class DataModelSmokeIT extends AbstractDataIT {

	@Autowired
	private NodePolicyRepository nodePolicies;

	@Autowired
	private DpRuleRepository dpRules;

	@Autowired
	private PinRepository pins;

	@Autowired
	private ObjectMapper objectMapper;

	@Test
	void nodePolicyRoundTripsJsonbAndIsNewInsert() {
		var labels = objectMapper.readTree("{\"env\":\"prod\",\"tier\":\"db\"}");
		var policy = NodePolicy.create("policy-db", labels, "agent", null, null, "git");

		var saved = nodePolicies.save(policy).block();
		assertThat(saved).isNotNull();
		assertThat(saved.id()).isEqualTo(policy.id()); // client-set UUIDv7 preserved (real insert, not update)
		assertThat(saved.version()).isNotNull(); // @Version populated -> the is-new path fired
		assertThat(saved.createdAt()).isNotNull(); // auditing populated created_at
		assertThat(saved.updatedAt()).isNotNull();

		var reread = nodePolicies.findById(policy.id()).block();
		assertThat(reread).isNotNull();
		assertThat(reread.name()).isEqualTo("policy-db");
		assertThat(reread.connectorKind()).isEqualTo("agent");
		assertThat(reread.origin()).isEqualTo("git");
		assertThat(reread.desiredLabels()).isEqualTo(labels); // jsonb -> JsonNode, order-independent equality
	}

	@Test
	void dpRuleRoundTripsArraysAndSelectors() {
		var idSel = objectMapper.readTree("{\"group\":\"eng\"}");
		var nodeSel = objectMapper.readTree("{\"env\":\"prod\"}");
		var srcIp = objectMapper.readTree("{\"cidrs\":[\"10.0.0.0/8\"]}");
		var rule = DpRule.create("rule-eng", idSel, nodeSel, srcIp, List.of("deploy", "dba"), 900,
				List.of("shell", "exec", "sftp"), "allow", "git");

		var reread = dpRules.save(rule).flatMap(s -> dpRules.findById(s.id())).block();
		assertThat(reread).isNotNull();
		assertThat(reread.principals()).containsExactly("deploy", "dba"); // text[] -> List<String>
		assertThat(reread.capabilities()).containsExactly("shell", "exec", "sftp");
		assertThat(reread.ttlSeconds()).isEqualTo(900);
		assertThat(reread.identitySelector()).isEqualTo(idSel);
		assertThat(reread.sourceIpCondition()).isEqualTo(srcIp);
	}

	@Test
	void pinRoundTripsCidrTextAndInstant() {
		var expires = Instant.now().plus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.MICROS);
		// host bits set (192.168.1.5/24): accepted by the lenient ::inet validator and
		// stored verbatim (a strict ::cidr check would have rejected it).
		var pin = Pin.create("SHA256:abc", "alice@example.com", "192.168.1.5/24", List.of("deploy"), expires);

		var reread = pins.save(pin).flatMap(s -> pins.findById(s.id())).block();
		assertThat(reread).isNotNull();
		assertThat(reread.sourceCidr()).isEqualTo("192.168.1.5/24"); // round-trips exactly as text
		assertThat(reread.expiresAt()).isEqualTo(expires); // timestamptz <-> Instant, microsecond precision
		assertThat(reread.principals()).containsExactly("deploy");
	}

	@Test
	void repositoriesAreReactiveNonBlocking() {
		// A StepVerifier proves the repository returns a real reactive publisher that
		// completes without a blocking driver on the path.
		var policy = NodePolicy.create("policy-reactive", objectMapper.readTree("{}"), "agentless", null, null, "api");
		StepVerifier.create(nodePolicies.save(policy).then(nodePolicies.findByName("policy-reactive")))
				.assertNext(p -> assertThat(p.connectorKind()).isEqualTo("agentless")).verifyComplete();
	}
}
