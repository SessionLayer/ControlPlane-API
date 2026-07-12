package io.sessionlayer.controlplane.breakglass;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the break-glass access model: enables
 * {@link BreakglassProperties}. The resolution/credential/token services and
 * the alert sinks are component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(BreakglassProperties.class)
public class BreakglassConfiguration {
}
