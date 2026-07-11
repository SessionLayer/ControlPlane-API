package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link Pin} ({@code runtime.pin}). */
public interface PinRepository extends ReactiveCrudRepository<Pin, UUID> {

	Mono<Pin> findByFingerprintAndIdentity(String fingerprint, String identity);

	Flux<Pin> findByIdentity(String identity);

	/**
	 * Active (unrevoked, unexpired) pins for a fingerprint whose source binding
	 * admits {@code sourceIp} — source-CIDR is a deny-only reducer (FR-AUTH-15),
	 * with the same {@code ::inet}/{@code <<=} predicate as {@code OtpService}
	 * (lenient {@code ::inet} so an operator host-bits CIDR does not throw; a blank
	 * {@code sourceIp} matches only unbound pins). More than one row is ambiguous
	 * and the caller resolves nothing.
	 */
	@Query("""
			SELECT * FROM runtime.pin
			WHERE fingerprint = :fingerprint AND revoked_at IS NULL AND expires_at > now()
			  AND (source_cidr IS NULL OR (:sourceIp <> '' AND :sourceIp::inet <<= source_cidr::inet))""")
	Flux<Pin> findActiveByFingerprintForSource(String fingerprint, String sourceIp);
}
