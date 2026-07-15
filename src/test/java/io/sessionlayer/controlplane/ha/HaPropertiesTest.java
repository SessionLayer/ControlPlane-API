package io.sessionlayer.controlplane.ha;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.mock.env.MockEnvironment;

/**
 * {@link HaProperties} binding. The default staleness is the load-bearing value
 * (both the Presence claim/standby decision and the Authorize routing gate key
 * off it), and the relaxed-binding path
 * {@code sessionlayer.ha.presence-staleness} must resolve — a wrong prefix/name
 * would silently fall back to the default.
 */
class HaPropertiesTest {

	@Test
	void defaultsToThirtySeconds() {
		assertThat(new HaProperties().getPresenceStaleness()).isEqualTo(Duration.ofSeconds(30));
	}

	@Test
	void bindsPresenceStalenessFromKebabProperty() {
		HaProperties bound = bind(Map.of("sessionlayer.ha.presence-staleness", "PT12S"));
		assertThat(bound.getPresenceStaleness()).isEqualTo(Duration.ofSeconds(12));
	}

	private static HaProperties bind(Map<String, Object> properties) {
		MockEnvironment environment = new MockEnvironment();
		properties.forEach(environment::setProperty);
		return new Binder(ConfigurationPropertySources.get(environment)).bindOrCreate("sessionlayer.ha",
				HaProperties.class);
	}
}
