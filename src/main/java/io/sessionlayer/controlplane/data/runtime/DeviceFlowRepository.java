package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link DeviceFlow}. */
public interface DeviceFlowRepository extends ReactiveCrudRepository<DeviceFlow, UUID> {

	Mono<DeviceFlow> findByDeviceCodeHash(String deviceCodeHash);
}
