package io.sessionlayer.controlplane.authz;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the Session Five authorization layer: enables
 * {@link AuthzProperties}. The engine, decision service, signer and platform
 * enforcement are component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuthzProperties.class)
public class AuthzConfiguration {
}
