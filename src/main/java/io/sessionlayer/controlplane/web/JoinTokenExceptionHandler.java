package io.sessionlayer.controlplane.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders {@link JoinTokenValidationException} from {@link JoinTokenController}
 * as an RFC-9457 {@code 400} ({@code application/problem+json}). Scoped to the
 * join-token controller so it leaves every other endpoint's error handling
 * untouched (mirrors {@link LockExceptionHandler}).
 */
@RestControllerAdvice(assignableTypes = JoinTokenController.class)
class JoinTokenExceptionHandler {

	@ExceptionHandler(JoinTokenValidationException.class)
	ResponseEntity<ProblemDetail> onInvalidRequest(JoinTokenValidationException failure) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, failure.getMessage());
		problem.setTitle("Invalid join token request");
		return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}
}
