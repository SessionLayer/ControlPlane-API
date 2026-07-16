package io.sessionlayer.controlplane.recording;

import java.time.Duration;
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

	private final RecordingRetentionService retention;

	public RecordingRetentionJob(RecordingRetentionService retention) {
		this.retention = retention;
	}

	@EventListener(ApplicationReadyEvent.class)
	public void pruneOnStartup() {
		retention.prune("startup").block(Duration.ofSeconds(60));
	}

	@Scheduled(cron = "${sessionlayer.recording.retention.cron:0 0 * * * *}")
	public void pruneScheduled() {
		retention.prune("scheduled").block(Duration.ofSeconds(60));
	}
}
