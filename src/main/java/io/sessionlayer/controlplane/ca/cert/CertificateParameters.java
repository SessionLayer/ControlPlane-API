package io.sessionlayer.controlplane.ca.cert;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The variable fields of an OpenSSH certificate (everything except the
 * certified public key and the CA signature). Critical options carry values
 * (encoded with the double length prefix); extensions are flags (empty data).
 * Both are held in byte-lexically sorted collections so the assembler emits
 * them in the required order without duplicates.
 *
 * @param serial
 *            monotonically-assignable serial (uint64)
 * @param type
 *            user or host cert
 * @param keyId
 *            the {@code key id} string ({@code session_id+identity} for the
 *            inner leg, FR-CA-5)
 * @param principals
 *            valid principals (Linux logins for a user cert; hostnames for a
 *            host cert)
 * @param validAfter
 *            not-valid-before (backdated 1–5 min for skew, FR-CA-5/BOOT-4)
 * @param validBefore
 *            not-valid-after (≈ +5 min for the inner leg)
 * @param criticalOptions
 *            value-carrying options (e.g. {@code source-address},
 *            {@code force-command})
 * @param extensions
 *            flag extensions (e.g. {@code permit-pty},
 *            {@code permit-port-forwarding})
 */
public record CertificateParameters(long serial, CertType type, String keyId, List<String> principals,
		Instant validAfter, Instant validBefore, SortedMap<String, String> criticalOptions,
		SortedSet<String> extensions) {

	/**
	 * Byte-lexicographic (unsigned) ordering of names — the OpenSSH ordering rule.
	 */
	public static final java.util.Comparator<String> BYTE_ORDER = (a, b) -> {
		byte[] x = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] y = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		int n = Math.min(x.length, y.length);
		for (int i = 0; i < n; i++) {
			int c = (x[i] & 0xFF) - (y[i] & 0xFF);
			if (c != 0) {
				return c;
			}
		}
		return x.length - y.length;
	};

	public CertificateParameters {
		if (validBefore.isBefore(validAfter)) {
			throw new IllegalArgumentException("validBefore must not precede validAfter");
		}
		criticalOptions = sortedMap(criticalOptions);
		extensions = sortedSet(extensions);
	}

	private static SortedMap<String, String> sortedMap(Map<String, String> in) {
		SortedMap<String, String> m = new TreeMap<>(BYTE_ORDER);
		if (in != null) {
			m.putAll(in);
		}
		return m;
	}

	private static SortedSet<String> sortedSet(java.util.Collection<String> in) {
		SortedSet<String> s = new TreeSet<>(BYTE_ORDER);
		if (in != null) {
			s.addAll(in);
		}
		return s;
	}
}
