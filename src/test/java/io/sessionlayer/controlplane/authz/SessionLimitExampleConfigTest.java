package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.convert.ApplicationConversionService;

/**
 * S25 Part D — the commented FR-SESS-3 example config must actually parse: the
 * knobs in {@code deploy/session-limits-example.properties} and the
 * application.properties example block are extracted verbatim and bound through
 * the SAME relaxed-binding machinery Boot uses, so a typo'd key or value in an
 * example an operator will uncomment can never rot silently. (The live-boot
 * companion is SessionLimitConfigBindingIT, which boots the app with the three
 * default knobs set and proves the reconcile + enforcement.)
 */
class SessionLimitExampleConfigTest {

	private static final Pattern EXAMPLE_LINE = Pattern
			.compile("^#\\s*(sessionlayer\\.session-limits\\.[A-Za-z0-9.\\-]+)=(\\S+)\\s*$");

	@Test
	void theDeployExampleValuesBindToTheRealProperties() {
		Map<String, String> example = commentedExamples(Path.of("deploy/session-limits-example.properties"));
		assertThat(example).containsOnlyKeys("sessionlayer.session-limits.default-max-concurrent",
				"sessionlayer.session-limits.default-max-session-seconds",
				"sessionlayer.session-limits.default-idle-timeout-seconds");

		SessionLimitProperties bound = bind(example);
		assertThat(bound.getDefaultMaxConcurrent()).isEqualTo(3);
		assertThat(bound.getDefaultMaxSessionSeconds()).isEqualTo(28800);
		assertThat(bound.getDefaultIdleTimeoutSeconds()).isEqualTo(1800);
	}

	@Test
	void theApplicationPropertiesExampleBlockBindsAndParses() {
		Map<String, String> example = commentedExamples(Path.of("src/main/resources/application.properties"));
		assertThat(example).containsKeys("sessionlayer.session-limits.default-max-concurrent",
				"sessionlayer.session-limits.lease-extension", "sessionlayer.session-limits.reaper.interval",
				"sessionlayer.session-limits.reaper.grace");

		// reaper.interval is consumed by @Scheduled placeholder resolution, not the
		// properties class, so the binder ignores it — assert every duration-shaped
		// value is valid ISO-8601 explicitly.
		example.forEach((key, value) -> {
			if (value.startsWith("PT")) {
				assertThat(Duration.parse(value)).isPositive();
			}
		});

		SessionLimitProperties bound = bind(example);
		assertThat(bound.getDefaultMaxConcurrent()).isEqualTo(3);
		assertThat(bound.getDefaultMaxSessionSeconds()).isEqualTo(28800);
		assertThat(bound.getDefaultIdleTimeoutSeconds()).isEqualTo(1800);
		assertThat(bound.getLeaseExtension()).isEqualTo(Duration.ofMinutes(15));
		assertThat(bound.getReaper().getGrace()).isEqualTo(Duration.ofMinutes(5));
	}

	private static SessionLimitProperties bind(Map<String, String> properties) {
		Binder binder = new Binder(List.of(new MapConfigurationPropertySource(properties)), null,
				ApplicationConversionService.getSharedInstance());
		return binder.bind("sessionlayer.session-limits", Bindable.of(SessionLimitProperties.class)).get();
	}

	private static Map<String, String> commentedExamples(Path file) {
		Map<String, String> pairs = new LinkedHashMap<>();
		try {
			for (String line : Files.readAllLines(file)) {
				Matcher matcher = EXAMPLE_LINE.matcher(line);
				if (matcher.matches()) {
					pairs.put(matcher.group(1), matcher.group(2));
				}
			}
		} catch (IOException e) {
			throw new AssertionError("cannot read " + file, e);
		}
		assertThat(pairs).as("commented sessionlayer.session-limits example lines in " + file).isNotEmpty();
		return pairs;
	}
}
