package io.sessionlayer.controlplane.security.mtls;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Extracts the caller identity from a validated REST mTLS client certificate.
 */
final class MtlsIdentities {

	private static final int SAN_URI = 6;

	private MtlsIdentities() {
	}

	/**
	 * Resolve an identity from a client leaf: a URI SAN if present (the internal-CA
	 * convention, e.g. {@code sessionlayer://gateway/<id>}), else the subject
	 * common name. Returns {@code null} if neither yields a usable value.
	 */
	static String identityOf(X509Certificate leaf) {
		String uri = firstUriSan(leaf);
		if (uri != null) {
			return uri;
		}
		return commonName(leaf.getSubjectX500Principal().getName());
	}

	private static String firstUriSan(X509Certificate leaf) {
		try {
			var sans = leaf.getSubjectAlternativeNames();
			if (sans == null) {
				return null;
			}
			for (List<?> san : sans) {
				if (san.size() >= 2 && san.get(0) instanceof Integer type && type == SAN_URI
						&& san.get(1) instanceof String uri && !uri.isBlank()) {
					return uri;
				}
			}
		} catch (Exception ignored) {
			return null;
		}
		return null;
	}

	private static String commonName(String dn) {
		for (String rdn : dn.split(",")) {
			String t = rdn.trim();
			if (t.regionMatches(true, 0, "CN=", 0, 3)) {
				String cn = t.substring(3).trim();
				return cn.isBlank() ? null : cn;
			}
		}
		return null;
	}
}
