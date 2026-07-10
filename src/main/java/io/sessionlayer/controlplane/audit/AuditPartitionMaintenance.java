package io.sessionlayer.controlplane.audit;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Create-ahead maintenance for the {@code audit_event} range partitions
 * (FR-AUD-6, closes R-AUD-1). Without this, the one-time migration seed
 * silently runs out ~13 months after deploy and new audit rows fall into the
 * DEFAULT partition (which retention never reclaims). This ensures a rolling
 * window of future monthly partitions exists — on startup and monthly — so the
 * DEFAULT stays empty and prunable ranges land in dated partitions. It calls
 * the bounded, capped {@code audit_ensure_partitions} (create-only; never
 * drops), which the restricted runtime role is allowed to execute; it is
 * <b>not</b> allowed to prune.
 *
 * <p>
 * Gated by {@code sessionlayer.audit.partition-maintenance.enabled} (default
 * on). Failures are logged, not fatal — the DEFAULT partition guarantees
 * inserts never fail meanwhile.
 */
@Component
@ConditionalOnProperty(value = "sessionlayer.audit.partition-maintenance.enabled", havingValue = "true", matchIfMissing = true)
public class AuditPartitionMaintenance {

	private static final Logger LOG = LoggerFactory.getLogger(AuditPartitionMaintenance.class);

	/** How many months ahead to keep provisioned. */
	private static final int MONTHS_AHEAD = 6;

	private final DatabaseClient db;

	public AuditPartitionMaintenance(DatabaseClient db) {
		this.db = db;
	}

	@EventListener(ApplicationReadyEvent.class)
	public void ensureOnStartup() {
		ensureAhead("startup").block(Duration.ofSeconds(30));
	}

	/**
	 * Monthly (03:00 on the 1st by default); the cron never fires during a short
	 * test.
	 */
	@Scheduled(cron = "${sessionlayer.audit.partition-maintenance.cron:0 0 3 1 * *}")
	public void ensureMonthly() {
		ensureAhead("scheduled").block(Duration.ofSeconds(30));
	}

	private Mono<Void> ensureAhead(String trigger) {
		return db.sql("SELECT runtime.audit_ensure_partitions(date_trunc('month', now())::date, :n)")
				.bind("n", MONTHS_AHEAD).fetch().one()
				.doOnSuccess(
						r -> LOG.info("audit partition create-ahead ({}) ensured {} months", trigger, MONTHS_AHEAD))
				.onErrorResume(e -> {
					LOG.warn("audit partition create-ahead ({}) failed; the DEFAULT partition still accepts inserts",
							trigger, e);
					return Mono.empty();
				}).then();
	}
}
