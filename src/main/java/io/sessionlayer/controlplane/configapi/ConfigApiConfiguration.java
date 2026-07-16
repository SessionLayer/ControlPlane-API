package io.sessionlayer.controlplane.configapi;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the Session 17 config-management API conventions
 * ({@code sessionlayer.idempotency.*}).
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(IdempotencyProperties.class)
class ConfigApiConfiguration {
}
