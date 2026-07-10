package io.sessionlayer.controlplane.data;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Application-side UUID generation. Primary keys are UUIDv7 (RFC 9562) so that
 * a 48-bit Unix-millisecond timestamp prefix gives time-ordered B-tree locality
 * on the high-write tables ({@code audit_event}, {@code ssh_session},
 * {@code presence}, {@code jit_request}) instead of the index fragmentation of
 * random UUIDv4. See {@code docs/DATA-MODEL.md} §2.
 *
 * <p>
 * We generate client-side (not {@code gen_random_uuid()}) so no Postgres
 * extension is required and so the id is known before insert; the R2DBC
 * "is-new" problem that a client-set id would otherwise cause is solved by the
 * {@code @Version} column on every entity.
 */
public final class Uuids {

	private static final SecureRandom RANDOM = new SecureRandom();

	private Uuids() {
	}

	/**
	 * Generate a UUIDv7: 48-bit big-endian Unix-ms timestamp, 4-bit version
	 * {@code 0b0111}, 12 bits random, 2-bit variant {@code 0b10}, 62 bits random.
	 * Monotonic to the millisecond; ties within a millisecond are randomly ordered
	 * (sufficient for index locality — a strict per-ms counter is unnecessary
	 * here).
	 *
	 * @return a fresh time-ordered version-7 UUID
	 */
	public static UUID v7() {
		long unixTsMs = System.currentTimeMillis();
		byte[] rand = new byte[10];
		RANDOM.nextBytes(rand);

		long rand12 = (((long) (rand[0] & 0xFF) << 8) | (rand[1] & 0xFF)) & 0x0FFFL;
		long msb = ((unixTsMs & 0xFFFFFFFFFFFFL) << 16) // 48-bit timestamp in the high bits
				| 0x7000L // version 7 in bits 15..12
				| rand12; // 12 random bits

		long lsb = 0L;
		for (int i = 2; i < 10; i++) {
			lsb = (lsb << 8) | (rand[i] & 0xFFL);
		}
		lsb &= 0x3FFFFFFFFFFFFFFFL; // clear the top two bits
		lsb |= 0x8000000000000000L; // variant 0b10

		return new UUID(msb, lsb);
	}
}
