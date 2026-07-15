package io.sessionlayer.controlplane.ha;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the Session Fifteen HA plane: enables {@link HaProperties}. The
 * {@code PresenceService} gRPC endpoint is component-scanned and auto-binds via
 * the {@code List<BindableService>} injection in the mTLS server.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(HaProperties.class)
public class HaConfiguration {
}
