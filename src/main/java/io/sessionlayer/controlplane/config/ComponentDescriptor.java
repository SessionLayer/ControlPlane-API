package io.sessionlayer.controlplane.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Identity of this Control Plane build: the formal component name (fixed,
 * Design §1) and the SemVer build version.
 *
 * <p>
 * The version is filtered from the Maven project version into
 * {@code application.version} at package time, so it tracks the artifact
 * automatically. Injected by both the gRPC {@code Handshake} service and the
 * REST {@code /v1/version} endpoint so they report one identity.
 */
@Component
public class ComponentDescriptor {

	/** Formal component name (Design §1). */
	public static final String NAME = "SessionLayer Control Plane";

	private final String version;

	public ComponentDescriptor(@Value("${application.version:0.0.0}") String version) {
		this.version = version;
	}

	public String name() {
		return NAME;
	}

	public String version() {
		return version;
	}
}
