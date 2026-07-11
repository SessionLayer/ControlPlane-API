package io.sessionlayer.controlplane.bootstrap;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

/**
 * Wires the first-admin bootstrap (FR-BOOT-2). The startup runner is
 * {@code LOWEST_PRECEDENCE}; the CA cold-start runner is unordered, so their
 * relative order is not guaranteed — correctness does <b>not</b> depend on it:
 * {@code BootstrapService.ensureSettings()} self-creates the operator-settings
 * singleton race-safely and the completion flip is a single-winner conditional
 * UPDATE. A stuck bootstrap crashes the boot (bounded block) rather than
 * hanging the pod, like cold start.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(BootstrapProperties.class)
public class BootstrapConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(BootstrapConfiguration.class);

	@Bean
	@Order(Ordered.LOWEST_PRECEDENCE)
	@ConditionalOnProperty(value = "sessionlayer.bootstrap.enabled", havingValue = "true", matchIfMissing = true)
	ApplicationRunner firstAdminBootstrapRunner(BootstrapService bootstrapService) {
		return args -> {
			LOG.info("first-admin bootstrap: evaluating (FR-BOOT-2)");
			bootstrapService.runAtStartup().block(Duration.ofSeconds(30));
		};
	}
}
