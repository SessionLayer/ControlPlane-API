package io.sessionlayer.controlplane.agent;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the Session Twelve Agent join plane: enables
 * {@link AgentJoinProperties}. The services, verifiers, the gRPC handler, and
 * the join-token REST controller are component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AgentJoinProperties.class)
public class AgentJoinConfiguration {
}
