package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.api.model.LockTarget;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ObjectNode;

/**
 * Lock ingest validation (D5) + the canonical target_selector jsonb it emits.
 */
class LockIngestValidationTest {

	@Test
	void aRecognisedTargetProducesCanonicalPluralSelector() {
		UUID nodeId = UUID.randomUUID();
		LockTarget target = new LockTarget().identities(List.of("alice")).groups(List.of("admins"))
				.principals(List.of("deploy")).nodeLabels(List.of("env=prod")).nodeIds(List.of(nodeId));

		ObjectNode selector = LockIngestValidation.toSelector(target);

		assertThat(selector.get("identities").get(0).stringValue()).isEqualTo("alice");
		assertThat(selector.get("groups").get(0).stringValue()).isEqualTo("admins");
		assertThat(selector.get("principals").get(0).stringValue()).isEqualTo("deploy");
		assertThat(selector.get("node_labels").get(0).stringValue()).isEqualTo("env=prod");
		assertThat(selector.get("node_ids").get(0).stringValue()).isEqualTo(nodeId.toString());
	}

	@Test
	void anEmptyTargetIsRejected() {
		assertThatThrownBy(() -> LockIngestValidation.toSelector(new LockTarget()))
				.isInstanceOf(LockValidationException.class).hasMessageContaining("at least one facet");
	}

	@Test
	void aGlobalLockRequiresExplicitAll() {
		// all:false with no facet is still empty → rejected (never an implicit global).
		assertThatThrownBy(() -> LockIngestValidation.toSelector(new LockTarget().all(false)))
				.isInstanceOf(LockValidationException.class);
		// all:true is the intentional fleet-wide lock.
		assertThat(LockIngestValidation.toSelector(new LockTarget().all(true)).get("all").booleanValue()).isTrue();
	}

	@Test
	void aBlankFacetValueIsRejected() {
		assertThatThrownBy(() -> LockIngestValidation.toSelector(new LockTarget().identities(List.of("  "))))
				.isInstanceOf(LockValidationException.class).hasMessageContaining("blank");
	}

	@Test
	void aMalformedNodeLabelIsRejected() {
		assertThatThrownBy(() -> LockIngestValidation.toSelector(new LockTarget().nodeLabels(List.of("noequals"))))
				.isInstanceOf(LockValidationException.class).hasMessageContaining("key=value");
		assertThatThrownBy(() -> LockIngestValidation.toSelector(new LockTarget().nodeLabels(List.of("=orphan"))))
				.isInstanceOf(LockValidationException.class);
	}

	@Test
	void ttlMustBePositiveWhenPresent() {
		assertThat(LockIngestValidation.normalizeTtl(null)).isNull();
		assertThat(LockIngestValidation.normalizeTtl(3600L)).isEqualTo(3600);
		assertThatThrownBy(() -> LockIngestValidation.normalizeTtl(0L)).isInstanceOf(LockValidationException.class);
		assertThatThrownBy(() -> LockIngestValidation.normalizeTtl(-5L)).isInstanceOf(LockValidationException.class);
	}

	@Test
	void anOversizeFacetIsRejected() {
		List<String> tooMany = java.util.stream.IntStream.rangeClosed(1, 257).mapToObj(i -> "id" + i).toList();
		assertThatThrownBy(() -> LockIngestValidation.toSelector(new LockTarget().identities(tooMany)))
				.isInstanceOf(LockValidationException.class).hasMessageContaining("too many");
	}

	@Test
	void anOversizeFacetValueIsRejected() {
		String huge = "x".repeat(513);
		assertThatThrownBy(() -> LockIngestValidation.toSelector(new LockTarget().identities(List.of(huge))))
				.isInstanceOf(LockValidationException.class).hasMessageContaining("too long");
	}

	@Test
	void tooManyTotalEntriesAcrossFacetsIsRejected() {
		List<String> full = java.util.stream.IntStream.rangeClosed(1, 256).mapToObj(i -> "v" + i).toList();
		LockTarget target = new LockTarget().identities(full).groups(full).principals(full)
				.nodeLabels(full.stream().map(v -> "k=" + v).toList()).nodeIds(List.of(UUID.randomUUID()));
		assertThatThrownBy(() -> LockIngestValidation.toSelector(target)).isInstanceOf(LockValidationException.class)
				.hasMessageContaining("too many entries");
	}

	@Test
	void reasonMustBePresentAndBounded() {
		LockIngestValidation.checkReason("incident-123"); // ok
		assertThatThrownBy(() -> LockIngestValidation.checkReason(null)).isInstanceOf(LockValidationException.class);
		assertThatThrownBy(() -> LockIngestValidation.checkReason("  ")).isInstanceOf(LockValidationException.class);
		assertThatThrownBy(() -> LockIngestValidation.checkReason("x".repeat(4097)))
				.isInstanceOf(LockValidationException.class).hasMessageContaining("at most");
	}

	@Test
	void summarizeListsFacetsWithoutSecrets() {
		ObjectNode selector = LockIngestValidation.toSelector(new LockTarget().identities(List.of("a", "b")).all(true));
		assertThat(LockIngestValidation.summarize(selector)).contains("identities:2").contains("all");
	}
}
