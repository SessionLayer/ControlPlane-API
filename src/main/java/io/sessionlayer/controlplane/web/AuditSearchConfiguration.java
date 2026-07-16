package io.sessionlayer.controlplane.web;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Registers {@link AuditSearchProperties} (the SESSION §8 audit-search window
 * bound).
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuditSearchProperties.class)
class AuditSearchConfiguration {
}
