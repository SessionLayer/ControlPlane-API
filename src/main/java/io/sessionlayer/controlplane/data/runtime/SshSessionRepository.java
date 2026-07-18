package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/** Reactive repository for {@link SshSession} ({@code runtime.ssh_session}). */
public interface SshSessionRepository extends ReactiveCrudRepository<SshSession, UUID> {

	Flux<SshSession> findByIdentity(String identity);

	Flux<SshSession> findByNodeId(UUID nodeId);

	Flux<SshSession> findByAccessModel(String accessModel);
}
