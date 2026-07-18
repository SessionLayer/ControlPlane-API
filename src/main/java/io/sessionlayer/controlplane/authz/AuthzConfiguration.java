package io.sessionlayer.controlplane.authz;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the Session Five authorization layer: enables
 * {@link AuthzProperties} (and, since Session Ten, {@link LockFeedProperties};
 * and, since Session 24, the FR-SESS-3 {@link SessionLimitProperties}). The
 * engine, decision service, signer and platform enforcement are
 * component-scanned.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({AuthzProperties.class, LockFeedProperties.class, SessionLimitProperties.class})
public class AuthzConfiguration {
}
