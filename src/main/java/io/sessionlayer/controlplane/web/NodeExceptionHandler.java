package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.node.NodeRequestException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders {@link NodeRequestException} from {@link NodeController} as an
 * RFC-9457 problem ({@code 400}/{@code 404}/{@code 409}). Scoped to the node
 * controller so it leaves every other endpoint's error handling untouched
 * (mirrors {@link JoinTokenExceptionHandler}).
 */
@RestControllerAdvice(assignableTypes = NodeController.class)
class NodeExceptionHandler {

	@ExceptionHandler(NodeRequestException.class)
	ResponseEntity<ProblemDetail> onNodeRequest(NodeRequestException failure) {
		HttpStatus status = switch (failure.reason()) {
			case INVALID_ARGUMENT -> HttpStatus.BAD_REQUEST;
			case NOT_FOUND -> HttpStatus.NOT_FOUND;
			case CONFLICT -> HttpStatus.CONFLICT;
		};
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, failure.getMessage());
		problem.setTitle("Node request rejected");
		return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}
}
