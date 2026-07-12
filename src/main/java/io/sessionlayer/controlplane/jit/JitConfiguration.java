package io.sessionlayer.controlplane.jit;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the JIT access model: enables {@link JitProperties}. The lifecycle
 * service, approval-chain logic and expiry scheduler are component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JitProperties.class)
public class JitConfiguration {
}
