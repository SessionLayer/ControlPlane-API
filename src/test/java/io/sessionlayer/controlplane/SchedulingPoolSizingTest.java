package io.sessionlayer.controlplane;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;

/**
 * S25 F2 — every {@code @Scheduled} job shares ONE scheduling pool, and audit
 * partitioning on that pool is authz-availability-critical (a missed partition
 * fails audit inserts, which rolls back allow txs — a fail-closed outage). This
 * guard keeps the pool sized to the real job census so a future job can't
 * silently re-introduce starvation: it scans the codebase for scheduled methods
 * and asserts the configured pool covers them with headroom.
 */
class SchedulingPoolSizingTest {

	@Test
	void theSchedulingPoolCoversEveryScheduledJobWithHeadroom() throws IOException {
		long jobs = scheduledJobCount();
		int poolSize = configuredPoolSize();

		// The floor the F2 review set, and 2x headroom over wedged jobs: even with
		// half the jobs stuck at their 30s block bound, the rest still run.
		assertThat(poolSize).isGreaterThanOrEqualTo(4);
		assertThat(poolSize * 2).as("adding a @Scheduled job? bump spring.task.scheduling.pool.size and its "
				+ "comment in application.properties (found %d jobs)", jobs).isGreaterThanOrEqualTo((int) jobs);
	}

	private static long scheduledJobCount() {
		ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);
		provider.addIncludeFilter(new AnnotationTypeFilter(Component.class));
		return provider.findCandidateComponents("io.sessionlayer.controlplane").stream()
				.map(bd -> ClassUtils.resolveClassName(bd.getBeanClassName(), null))
				.flatMap(type -> Arrays.stream(type.getDeclaredMethods()))
				.filter(method -> method.isAnnotationPresent(Scheduled.class)).count();
	}

	private static int configuredPoolSize() throws IOException {
		Properties properties = new Properties();
		properties.load(new StringReader(Files.readString(Path.of("src/main/resources/application.properties"))));
		String poolSize = properties.getProperty("spring.task.scheduling.pool.size");
		assertThat(poolSize).as("spring.task.scheduling.pool.size must be set explicitly").isNotBlank();
		return Integer.parseInt(poolSize.trim());
	}
}
