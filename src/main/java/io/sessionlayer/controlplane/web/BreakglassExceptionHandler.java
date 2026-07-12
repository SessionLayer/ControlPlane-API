package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.breakglass.BreakglassCredentialService.InvalidBreakglassException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders {@link InvalidBreakglassException} from {@link BreakglassController}
 * as an RFC-9457 {@code 400} ({@code application/problem+json}). Scoped to the
 * break-glass controller so every other endpoint's error handling is untouched
 * (mirrors {@link JoinTokenExceptionHandler}).
 */
@RestControllerAdvice(assignableTypes = BreakglassController.class)
class BreakglassExceptionHandler {

	@ExceptionHandler(InvalidBreakglassException.class)
	ResponseEntity<ProblemDetail> onInvalidRequest(InvalidBreakglassException failure) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, failure.getMessage());
		problem.setTitle("Invalid break-glass request");
		return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}
}
