package io.sessionlayer.controlplane.jit;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.jit.JitApprovalChain.Level;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Pure logic of the JIT approval chain (FR-ACC-3/4): level parsing/matching,
 * ordering, and the append shape.
 */
class JitApprovalChainTest {

	private final ObjectMapper mapper = new ObjectMapper();

	@Test
	void parsesLevels() {
		List<Level> levels = JitApprovalChain.levels(chain("email", "boss@corp", "oidc_group", "secops"));
		assertThat(levels).containsExactly(new Level("email", "boss@corp"), new Level("oidc_group", "secops"));
	}

	@Test
	void emailLevelMatchesIdentityOnly() {
		Level level = new Level("email", "boss@corp");
		assertThat(JitApprovalChain.matches(level, "boss@corp", List.of())).isTrue();
		assertThat(JitApprovalChain.matches(level, "other@corp", List.of("boss@corp"))).isFalse();
	}

	@Test
	void groupLevelMatchesMembership() {
		Level level = new Level("oidc_group", "secops");
		assertThat(JitApprovalChain.matches(level, "any@corp", List.of("secops", "eng"))).isTrue();
		assertThat(JitApprovalChain.matches(level, "any@corp", List.of("eng"))).isFalse();
	}

	@Test
	void unknownLevelKindMatchesNoOne() {
		assertThat(JitApprovalChain.matches(new Level("magic", "x"), "x", List.of("x"))).isFalse();
	}

	@Test
	void approvedCountAndActingTrackDistinctApprovers() {
		ArrayNode approvals = JitApprovalChain.append(mapper, null, "a@corp", 0, "approve", "ok", Instant.now());
		assertThat(JitApprovalChain.approvedCount(approvals)).isEqualTo(1);
		assertThat(JitApprovalChain.hasActed(approvals, "a@corp")).isTrue();
		assertThat(JitApprovalChain.hasActed(approvals, "b@corp")).isFalse();

		ArrayNode two = JitApprovalChain.append(mapper, approvals, "b@corp", 1, "approve", null, Instant.now());
		assertThat(JitApprovalChain.approvedCount(two)).isEqualTo(2);
	}

	@Test
	void denyDoesNotCountAsAnApproval() {
		ArrayNode approvals = JitApprovalChain.append(mapper, null, "a@corp", 0, "deny", "no", Instant.now());
		assertThat(JitApprovalChain.approvedCount(approvals)).isZero();
		assertThat(JitApprovalChain.hasActed(approvals, "a@corp")).isTrue();
	}

	private ArrayNode chain(String... kindValue) {
		ArrayNode chain = mapper.createArrayNode();
		for (int i = 0; i + 1 < kindValue.length; i += 2) {
			ObjectNode level = mapper.createObjectNode();
			level.put("kind", kindValue[i]);
			level.put("value", kindValue[i + 1]);
			chain.add(level);
		}
		return chain;
	}
}
