package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.authz.Selectors;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/**
 * Pre-commit shape validation for the jsonb selectors a config resource stores
 * (FR-API-5). A selector the S5 evaluator ({@link Selectors}) cannot parse
 * would otherwise persist and later fail-closed on the connect path (dp_rule)
 * or — worse — throw on the JIT-request submit path. We reject it here as a
 * {@code 422} by running it through the SAME evaluator with dummy inputs, so
 * the CRUD surface accepts exactly the selector shapes the evaluator accepts.
 */
final class SelectorValidation {

	private SelectorValidation() {
	}

	static void identitySelector(JsonNode selector) {
		if (selector == null) {
			return;
		}
		try {
			Selectors.identityMatches(selector, "validate", List.of());
		} catch (RuntimeException bad) {
			throw ApiProblemException.validation("identitySelector is not a valid selector: " + bad.getMessage());
		}
	}

	static void labelSelector(JsonNode selector, String field) {
		if (selector == null) {
			return;
		}
		try {
			Selectors.labelMatches(selector, Map.of());
		} catch (RuntimeException bad) {
			throw ApiProblemException.validation(field + " is not a valid node-label selector: " + bad.getMessage());
		}
	}

	static void sourceIpCondition(JsonNode condition) {
		if (condition == null) {
			return;
		}
		try {
			Selectors.sourceIpPasses(condition, "127.0.0.1");
		} catch (RuntimeException bad) {
			throw ApiProblemException.validation("sourceIpCondition is not a valid condition: " + bad.getMessage());
		}
	}
}
