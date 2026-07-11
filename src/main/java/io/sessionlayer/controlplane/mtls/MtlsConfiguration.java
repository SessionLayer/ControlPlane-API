package io.sessionlayer.controlplane.mtls;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the mTLS plane: enables {@link MtlsProperties}. The server
 * ({@link GrpcMtlsServer}), the CA services and the gRPC handlers are
 * component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(MtlsProperties.class)
public class MtlsConfiguration {
}
