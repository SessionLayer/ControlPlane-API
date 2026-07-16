package io.sessionlayer.controlplane.recording;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Drives the automated recording-retention prune on startup + a cron cadence
 * (default hourly, FR-AUD-6). Gated by
 * {@code sessionlayer.recording.retention.enabled} (default on) so an operator
 * can disable the <b>automated</b> lifecycle without losing the manual,
 * privileged governance-delete/legal-hold surface (which stays on
 * {@link RecordingRetentionService}).
 */
@Component
@ConditionalOnProperty(value = "sessionlayer.recording.retention.enabled", havingValue = "true", matchIfMissing = true)
public class RecordingRetentionJob {

	private static final Logger LOG = LoggerFactory.getLogger(RecordingRetentionJob.class);

	private final RecordingRetentionService retention;

	public RecordingRetentionJob(RecordingRetentionService retention) {
		this.retention = retention;
	}

	// Fire-and-forget: NEVER block or throw out of the ready event — a retention
	// hiccup must not abort application startup (that would crash-loop the CP and
	// take auth/CA/RBAC down for a recording problem). prune() already swallows its
	// own errors; this is the belt-and-suspenders subscribe (mirrors
	// WormObjectStore).
	@EventListener(ApplicationReadyEvent.class)
	public void pruneOnStartup() {
		retention.prune("startup").subscribe(done -> {
		}, error -> LOG.warn("startup recording retention prune failed (will retry on the schedule)", error));
	}

	// Runs on a dedicated scheduler thread; prune() never signals a fatal error.
	@Scheduled(cron = "${sessionlayer.recording.retention.cron:0 0 * * * *}")
	public void pruneScheduled() {
		retention.prune("scheduled").subscribe(done -> {
		}, error -> LOG.warn("scheduled recording retention prune failed (will retry next cycle)", error));
	}
}
