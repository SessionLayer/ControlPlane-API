package io.sessionlayer.controlplane.data;

import io.r2dbc.postgresql.codec.Json;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.data.relational.core.mapping.NamingStrategy;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * R2DBC persistence wiring for the data model (see {@code docs/DATA-MODEL.md}
 * §3, §9).
 *
 * <ul>
 * <li><b>Auditing</b> ({@code @EnableR2dbcAuditing}) populates the bookkeeping
 * {@code createdAt}/{@code updatedAt}
 * ({@code @CreatedDate}/{@code @LastModifiedDate}) fields in-application, in
 * <b>UTC</b>, via {@link #auditingDateTimeProvider()} — so the persisted object
 * graph matches the row without a re-read, and timestamps are always UTC
 * (FR-BOOT-4).</li>
 * <li><b>jsonb converters</b> map Jackson {@link JsonNode} &lt;-&gt; the
 * driver's {@link Json} wrapper (binding a bare {@code String} to a
 * {@code jsonb} column fails). {@code timestamptz}/{@code uuid}/{@code text[]}
 * use native codecs and need no converter.</li>
 * <li><b>Snake-case columns</b> via {@link SnakeCaseNamingStrategy}.</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
@EnableR2dbcAuditing(dateTimeProviderRef = "auditingDateTimeProvider")
public class R2dbcConfig {

	/**
	 * UTC clock for auditing so {@code created_at}/{@code updated_at} are always
	 * UTC.
	 */
	@Bean
	public DateTimeProvider auditingDateTimeProvider() {
		return () -> Optional.of(Instant.now());
	}

	/** camelCase property -&gt; snake_case column mapping. */
	@Bean
	public NamingStrategy namingStrategy() {
		return new SnakeCaseNamingStrategy();
	}

	/**
	 * Register the jsonb &lt;-&gt; JsonNode converters (Postgres dialect store
	 * converters included).
	 */
	@Bean
	public R2dbcCustomConversions r2dbcCustomConversions(ObjectMapper objectMapper) {
		return R2dbcCustomConversions.of(PostgresDialect.INSTANCE,
				List.of(new JsonNodeWritingConverter(objectMapper), new JsonNodeReadingConverter(objectMapper)));
	}

	/** {@link JsonNode} -&gt; {@code jsonb} (write). */
	@WritingConverter
	static final class JsonNodeWritingConverter implements Converter<JsonNode, Json> {

		private final ObjectMapper objectMapper;

		JsonNodeWritingConverter(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
		}

		@Override
		public Json convert(JsonNode source) {
			try {
				return Json.of(objectMapper.writeValueAsBytes(source));
			} catch (JacksonException e) {
				throw new IllegalArgumentException("Failed to serialize JsonNode to jsonb", e);
			}
		}
	}

	/** {@code jsonb} -&gt; {@link JsonNode} (read). */
	@ReadingConverter
	static final class JsonNodeReadingConverter implements Converter<Json, JsonNode> {

		private final ObjectMapper objectMapper;

		JsonNodeReadingConverter(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
		}

		@Override
		public JsonNode convert(Json source) {
			try {
				return objectMapper.readTree(source.asArray());
			} catch (JacksonException e) {
				throw new IllegalStateException("Failed to parse jsonb into JsonNode", e);
			}
		}
	}
}
