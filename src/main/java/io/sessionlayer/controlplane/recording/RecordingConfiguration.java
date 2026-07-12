package io.sessionlayer.controlplane.recording;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the Session Nine recording layer: enables {@link WormProperties}.
 * The token service, WORM object store, registration service and gRPC adapter
 * are component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(WormProperties.class)
public class RecordingConfiguration {
}
