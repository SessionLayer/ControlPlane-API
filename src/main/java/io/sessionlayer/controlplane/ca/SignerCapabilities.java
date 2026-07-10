package io.sessionlayer.controlplane.ca;

import java.util.Set;

/**
 * What a signer backend can produce (FR-CA-4 capability check). A
 * {@code ca_config} requesting an algorithm the backend cannot produce is
 * rejected at validation time, not at signing time.
 *
 * @param algorithms
 *            the {@code ca_config.algorithm} ids this backend can sign (e.g.
 *            {@code ecdsa-p256})
 */
public record SignerCapabilities(Set<String> algorithms) {

	public SignerCapabilities {
		algorithms = Set.copyOf(algorithms);
	}

	public boolean supports(String algorithmId) {
		return algorithms.contains(algorithmId);
	}

	public static SignerCapabilities of(CaKeyType... types) {
		return new SignerCapabilities(java.util.Arrays.stream(types).map(CaKeyType::algorithmId)
				.collect(java.util.stream.Collectors.toUnmodifiableSet()));
	}
}
