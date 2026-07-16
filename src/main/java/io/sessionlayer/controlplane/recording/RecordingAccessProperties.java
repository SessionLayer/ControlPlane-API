package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Admin replay/export configuration ({@code sessionlayer.recording.*}, Design
 * §12.2). {@code signedUrlTtl} bounds the single-object presigned GET the CP
 * hands an admin for replay/export — short-lived on purpose (bytes never proxy
 * through the CP; the object stays customer-key encrypted). The WORM store
 * itself is configured separately by {@link WormProperties}
 * ({@code sessionlayer.recording.worm.*}).
 */
@ConfigurationProperties(prefix = "sessionlayer.recording")
public class RecordingAccessProperties {

	private Duration signedUrlTtl = Duration.ofMinutes(5);

	public Duration getSignedUrlTtl() {
		return signedUrlTtl;
	}

	public void setSignedUrlTtl(Duration signedUrlTtl) {
		this.signedUrlTtl = signedUrlTtl;
	}
}
