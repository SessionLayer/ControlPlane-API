package io.sessionlayer.controlplane.jit;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Drives {@link JitLifecycleService#expireOverdue()} on a periodic schedule so
 * an unapproved request past its approval window, or a granted request past its
 * grant clock, transitions to EXPIRED with an audit even if it is never read
 * again (FR-ACC-2). The evaluator also expires lazily on read (never serves an
 * overdue grant), so the safety property does not depend on this loop; this
 * just keeps the durable state and audit trail current.
 *
 * <p>
 * Gated by {@code sessionlayer.jit.expiry.enabled} (default on). The default
 * delay is long enough not to fire during a short test (which drive expiry
 * explicitly). The block is bounded (S25 F2): the scheduling pool is shared by
 * all six periodic jobs, so a wedged DB connection must time out rather than
 * pin a pool thread indefinitely — an aborted oversized sweep simply resumes
 * next cycle, and lazy read-time expiry protects the grant path regardless;
 * failures are logged and are not fatal.
 */
@Component
@ConditionalOnProperty(value = "sessionlayer.jit.expiry.enabled", havingValue = "true", matchIfMissing = true)
public class JitExpiryScheduler {

	private static final Logger LOG = LoggerFactory.getLogger(JitExpiryScheduler.class);

	private final JitLifecycleService lifecycle;

	public JitExpiryScheduler(JitLifecycleService lifecycle) {
		this.lifecycle = lifecycle;
	}

	@Scheduled(fixedDelayString = "${sessionlayer.jit.expiry.interval:PT5M}", initialDelayString = "${sessionlayer.jit.expiry.interval:PT5M}")
	public void sweep() {
		try {
			lifecycle.expireOverdue().doOnNext(expired -> {
				if (expired > 0) {
					LOG.info("jit expiry sweep transitioned {} overdue request(s) to EXPIRED", expired);
				}
			}).onErrorResume(error -> {
				LOG.warn("jit expiry sweep failed (lazy read-time expiry still protects the grant path): {}",
						error.toString());
				return Mono.empty();
			}).block(Duration.ofSeconds(30));
		} catch (RuntimeException blockTimeout) {
			LOG.warn("jit expiry sweep timed out (lazy read-time expiry still protects the grant path): {}",
					blockTimeout.toString());
		}
	}
}
