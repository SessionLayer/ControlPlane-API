package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

/**
 * Default {@link AuditForwarder} reference implementation: ship each committed
 * audit event as a structured JSON line to a dedicated {@code audit.forward}
 * logger, which an operator points at their off-box log pipeline (§15/NFR-5).
 * Registered only when no other {@link AuditForwarder} bean is present, so a
 * deployment (or a test) can swap in a real connector / a no-op. The record
 * hash is included so a downstream consumer can chain-verify the mirrored
 * stream.
 */
@Configuration
public class LoggingAuditForwarder {

	// Method name must differ from the @Configuration class's own bean name
	// (loggingAuditForwarder) or the two definitions collide (override is disabled).
	@Bean
	@ConditionalOnMissingBean(AuditForwarder.class)
	AuditForwarder auditForwarder(ObjectMapper objectMapper) {
		return new StructuredLogForwarder(objectMapper);
	}

	static final class StructuredLogForwarder implements AuditForwarder {

		private static final Logger FORWARD = LoggerFactory.getLogger("audit.forward");

		private final ObjectMapper objectMapper;

		StructuredLogForwarder(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
		}

		@Override
		public Mono<Void> forward(AuditEvent event) {
			return Mono.fromRunnable(() -> {
				try {
					FORWARD.info("{}", objectMapper.writeValueAsString(event));
				} catch (JacksonException e) {
					FORWARD.warn("audit forward serialization failed for {}", event.id());
				}
			});
		}
	}
}
