package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.TreeMap;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/**
 * The {@code audit_event} tamper-evidence hash chain (Design §12.2 baseline,
 * FR-AUD-3). Each row's {@code record_hash} commits to the previous row's
 * {@code record_hash} and to this row's content:
 *
 * <pre>
 * record_hash = SHA-256( prev_hash ‖ canonical(event) )
 * </pre>
 *
 * where {@code prev_hash} is the predecessor row's {@code record_hash} in
 * {@code seq} order (the {@link #GENESIS} constant for the first chained row),
 * and {@code canonical(event)} is a deterministic, length-framed encoding of
 * the semantic fields.
 *
 * <p>
 * <b>Canonical encoding.</b> Fields are hashed in a fixed order with
 * unambiguous length framing (no delimiter can ever collide with content): a
 * 1-byte present/absent tag, then for present values a 4-byte big-endian length
 * and the UTF-8 bytes. Structured fields ({@code detail}, {@code node_labels})
 * are folded in with object keys sorted so the encoding is invariant to
 * Postgres {@code jsonb} key reordering on read-back. {@code occurred_at} is
 * truncated to microseconds at write time (matching {@code timestamptz}
 * resolution) so the value hashed equals the value that round-trips from the
 * DB. The DB-assigned {@code seq}, {@code prev_hash}, {@code record_hash},
 * {@code version} and {@code created_at} are deliberately excluded (position is
 * enforced by the chain links, not by a self-referential field). Fields, in
 * order: id, occurred_at, actor, subject, action, outcome, correlation_id,
 * session_id, node_id, node_labels, source_ip, access_model, capabilities,
 * detail.
 */
public final class AuditRecordHash {

	/** The chain anchor: {@code prev_hash} of the first chained row (64 hex 0s). */
	public static final String GENESIS = "0".repeat(64);

	private AuditRecordHash() {
	}

	/** Compute this row's {@code record_hash} given its predecessor's. */
	public static String recordHash(String prevHash, AuditEvent event) {
		MessageDigest md = sha256();
		updateString(md, prevHash);
		updateString(md, uuid(event.id()));
		updateString(md, event.occurredAt() == null ? null : event.occurredAt().toString());
		updateString(md, event.actor());
		updateString(md, event.subject());
		updateString(md, event.action());
		updateString(md, event.outcome());
		updateString(md, uuid(event.correlationId()));
		updateString(md, uuid(event.sessionId()));
		updateString(md, uuid(event.nodeId()));
		updateJson(md, event.nodeLabels());
		updateString(md, event.sourceIp());
		updateString(md, event.accessModel());
		updateList(md, event.capabilities());
		updateJson(md, event.detail());
		return hex(md.digest());
	}

	private static String uuid(UUID value) {
		return value == null ? null : value.toString();
	}

	private static void updateString(MessageDigest md, String value) {
		if (value == null) {
			md.update((byte) 0);
			return;
		}
		md.update((byte) 1);
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		updateInt(md, bytes.length);
		md.update(bytes);
	}

	private static void updateList(MessageDigest md, List<String> values) {
		if (values == null) {
			md.update((byte) 0);
			return;
		}
		md.update((byte) 1);
		updateInt(md, values.size());
		for (String value : values) {
			updateString(md, value);
		}
	}

	// Sorted-key recursion so the encoding is stable across jsonb round-trips.
	private static void updateJson(MessageDigest md, JsonNode node) {
		if (node == null || node.isNull()) {
			md.update((byte) 0);
			return;
		}
		md.update((byte) 1);
		if (node.isObject()) {
			md.update((byte) 'O');
			TreeMap<String, JsonNode> sorted = new TreeMap<>();
			for (var property : node.properties()) {
				sorted.put(property.getKey(), property.getValue());
			}
			updateInt(md, sorted.size());
			for (var entry : sorted.entrySet()) {
				updateString(md, entry.getKey());
				updateJson(md, entry.getValue());
			}
		} else if (node.isArray()) {
			md.update((byte) 'A');
			updateInt(md, node.size());
			for (JsonNode child : node) {
				updateJson(md, child);
			}
		} else if (node.isBoolean()) {
			md.update((byte) 'B');
			updateString(md, Boolean.toString(node.booleanValue()));
		} else if (node.isNumber()) {
			md.update((byte) 'N');
			updateString(md, node.toString());
		} else {
			md.update((byte) 'S');
			updateString(md, node.asString());
		}
	}

	private static void updateInt(MessageDigest md, int value) {
		md.update(new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value});
	}

	private static MessageDigest sha256() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}

	private static String hex(byte[] digest) {
		StringBuilder out = new StringBuilder(digest.length * 2);
		for (byte b : digest) {
			out.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
		}
		return out.toString();
	}
}
