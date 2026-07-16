package io.sessionlayer.controlplane.recording;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the recording layer: enables {@link WormProperties} (S9 WORM
 * store) and {@link RecordingAccessProperties} (S18 replay/export signed-URL
 * TTL). The token service, WORM object store, registration/access/retention
 * services and gRPC adapter are component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({WormProperties.class, RecordingAccessProperties.class})
public class RecordingConfiguration {
}
