package io.sessionlayer.controlplane.node;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the Session Sixteen node lifecycle plane: enables
 * {@link NodeLifecycleProperties}. The {@link NodeLifecycleService} and the
 * {@code /v1/nodes} REST controller are component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(NodeLifecycleProperties.class)
public class NodeConfiguration {
}
