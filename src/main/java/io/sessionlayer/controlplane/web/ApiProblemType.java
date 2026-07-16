package io.sessionlayer.controlplane.web;

import org.springframework.http.HttpStatusCode;

/**
 * The RFC 9457 problem {@code type} vocabulary for the config/runtime
 * management API (FR-API-1/5). Each carries a stable {@code type} URI (an
 * identifier, not a live endpoint), a title, and the HTTP status. Semantic
 * (pre-commit) config rejections are {@link #VALIDATION} ({@code 422});
 * malformed requests are {@link #MALFORMED} ({@code 400}). Status is a raw code
 * resolved via {@link HttpStatusCode#valueOf(int)} so it matches
 * assertions/clients regardless of the 422 reason-phrase rename
 * (UNPROCESSABLE_ENTITY vs _CONTENT).
 */
public enum ApiProblemType {

	VALIDATION("validation-error", 422, "Invalid configuration"), MALFORMED("malformed-request", 400,
			"Malformed request"), NOT_FOUND("not-found", 404, "Resource not found"), CONFLICT("conflict", 409,
					"Conflict"), IDEMPOTENCY_CONFLICT("idempotency-key-conflict", 422,
							"Idempotency-Key reuse conflict"), NOT_IMPLEMENTED("not-implemented", 501,
									"Not implemented");

	private static final String BASE = "https://docs.sessionlayer.example/problems/";

	private final String slug;
	private final int statusCode;
	private final String title;

	ApiProblemType(String slug, int statusCode, String title) {
		this.slug = slug;
		this.statusCode = statusCode;
		this.title = title;
	}

	public String typeUri() {
		return BASE + slug;
	}

	public HttpStatusCode status() {
		return HttpStatusCode.valueOf(statusCode);
	}

	public String title() {
		return title;
	}
}
