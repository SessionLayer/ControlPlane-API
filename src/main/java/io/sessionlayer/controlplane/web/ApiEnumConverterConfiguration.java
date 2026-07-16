package io.sessionlayer.controlplane.web;

import org.openapitools.configuration.EnumConverterConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Registers the generated OpenAPI {@code String}→enum converters so an enum
 * query parameter (the audit-search {@code capability}/{@code accessModel},
 * FR-AUD-8) binds by its contract VALUE (e.g. {@code exec}) rather than
 * Spring's default enum-constant name ({@code EXEC}). The generated
 * {@link EnumConverterConfiguration} sits outside the application's
 * component-scan base package, so it must be imported explicitly. First needed
 * by {@link AuditEventController}, but registers every generated enum converter
 * (harmless for endpoints that take the enum in a body, where Jackson already
 * uses {@code @JsonCreator}).
 */
@Configuration(proxyBeanMethods = false)
@Import(EnumConverterConfiguration.class)
class ApiEnumConverterConfiguration {
}
