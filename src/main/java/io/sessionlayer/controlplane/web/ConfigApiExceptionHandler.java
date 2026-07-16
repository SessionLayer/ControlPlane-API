package io.sessionlayer.controlplane.web;

import java.net.URI;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders {@link ApiProblemException} from the Session 17 management
 * controllers as RFC 9457 {@code application/problem+json} (FR-API-1). Handles
 * only that one app-specific type, so it never changes any other endpoint's
 * error handling (mirrors the scoped {@link NodeExceptionHandler}). The
 * {@code type} URI disambiguates the machine-readable problem class.
 */
@RestControllerAdvice
class ConfigApiExceptionHandler {

	@ExceptionHandler(ApiProblemException.class)
	ResponseEntity<ProblemDetail> onApiProblem(ApiProblemException failure) {
		ApiProblemType type = failure.type();
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(type.status(), failure.getMessage());
		problem.setType(URI.create(type.typeUri()));
		problem.setTitle(type.title());
		return ResponseEntity.status(type.status()).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}
}
