package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.PolicyEpochRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.SessionSigningTokenService;
import io.sessionlayer.controlplane.recording.RecordingTokenService;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * Orchestrates the connect-time decision (Part B, FR-CHAN-1). It resolves the
 * node's labels, evaluates the data-plane RBAC set with the
 * {@link PolicyEngine} (fail-closed, deny-overrides), and on <b>allow</b>:
 * produces a signed decision context, writes the {@code ssh_session} decision
 * snapshot, and mints the single-use {@code session_signing_token} bound to the
 * AUTHENTICATED caller gateway — replacing S4's minimal token path with the
 * real decision. On <b>deny/Lock</b> (and on any datastore/evaluation error) it
 * mints nothing and records the specific reason to the decision log while the
 * caller sees only a generic deny (FR-AUTHZ-5, §8.4).
 */
@Service
public class ConnectAuthorizationService {

	private static final Logger LOG = LoggerFactory.getLogger(ConnectAuthorizationService.class);
	private static final String DECISION_ACTION = "authz.decision";

	private final NodeRepository nodes;
	private final NodeHostKeyRepository hostKeys;
	private final CaRotationService caRotation;
	private final DpRuleRepository dpRules;
	private final AccessLockRepository accessLocks;
	private final PolicyEpochRepository policyEpochs;
	private final GatewayIdentityRepository gatewayIdentities;
	private final SshSessionRepository sshSessions;
	private final PolicyEngine engine;
	private final DecisionContextSigner signer;
	private final SessionSigningTokenService tokens;
	private final RecordingTokenService recordingTokens;
	private final AuditWriter audit;
	private final AuthzProperties properties;
	private final TransactionalOperator tx;

	public ConnectAuthorizationService(NodeRepository nodes, NodeHostKeyRepository hostKeys,
			CaRotationService caRotation, DpRuleRepository dpRules, AccessLockRepository accessLocks,
			PolicyEpochRepository policyEpochs, GatewayIdentityRepository gatewayIdentities,
			SshSessionRepository sshSessions, PolicyEngine engine, DecisionContextSigner signer,
			SessionSigningTokenService tokens, RecordingTokenService recordingTokens, AuditWriter audit,
			AuthzProperties properties, TransactionalOperator tx) {
		this.nodes = nodes;
		this.hostKeys = hostKeys;
		this.caRotation = caRotation;
		this.dpRules = dpRules;
		this.accessLocks = accessLocks;
		this.policyEpochs = policyEpochs;
		this.gatewayIdentities = gatewayIdentities;
		this.sshSessions = sshSessions;
		this.engine = engine;
		this.signer = signer;
		this.tokens = tokens;
		this.recordingTokens = recordingTokens;
		this.audit = audit;
		this.properties = properties;
		this.tx = tx;
	}

	public Mono<ConnectDecision> authorize(UUID callerGatewayId, String identity, List<String> groups, UUID nodeId,
			String requestedPrincipal, String sourceIp, UUID sessionId) {
		// The connect decision requires a concrete authenticated caller, target node,
		// session, resolved identity, and requested login — a blank one of any of these
		// is meaningless and fails closed (never allow/mint on a subject-less probe).
		if (callerGatewayId == null || nodeId == null || sessionId == null || isBlank(identity)
				|| isBlank(requestedPrincipal)) {
			return denyMissingInput(callerGatewayId, identity, nodeId, sourceIp);
		}
		return nodes.findById(nodeId).flatMap(
				node -> decide(callerGatewayId, identity, groups, node, requestedPrincipal, sourceIp, sessionId))
				.switchIfEmpty(auditDeny(callerGatewayId, identity, nodeId, sourceIp,
						DataPlaneDecision.deny(DataPlaneDecision.Reason.NO_MATCHING_ALLOW, null, null), "node_unknown")
						.thenReturn(ConnectDecision.denied()))
				// Any datastore/unexpected failure denies (fail closed, §8.4) — never leaks.
				.onErrorResume(failure -> {
					LOG.warn("connect authorization failed closed: {}", failure.toString());
					return auditError(callerGatewayId, identity, nodeId, sourceIp).thenReturn(ConnectDecision.denied());
				});
	}

	private Mono<ConnectDecision> decide(UUID callerGatewayId, String identity, List<String> groups, Node node,
			String requestedPrincipal, String sourceIp, UUID sessionId) {
		Mono<Long> epochMono = policyEpochs.findSingleton().map(e -> e.epoch()).defaultIfEmpty(0L);
		Mono<String> gwNameMono = gatewayIdentities.findById(callerGatewayId).map(g -> g.name())
				.defaultIfEmpty("unknown");

		// Read grants first, THEN locks, so the lock set is observed at a snapshot no
		// earlier than the grant set (§8.4: a concurrently-added deny/lock is never
		// missed while an allow from the same edit is honored — deny stays dominant).
		return dpRules.findAll().collectList().flatMap(grants -> accessLocks.findAll().collectList()
				.flatMap(locks -> Mono.zip(epochMono, gwNameMono).flatMap(meta -> {
					long epoch = meta.getT1();
					String gatewayName = meta.getT2();
					Instant now = Instant.now();
					AuthorizationRequest request = new AuthorizationRequest(identity, groups, node.id(),
							labelsOf(node.resolvedLabels()), sourceIp, requestedPrincipal);
					DataPlaneDecision decision = engine.evaluate(request, grants, locks, now);
					if (!decision.allowed()) {
						return auditDeny(callerGatewayId, identity, node.id(), sourceIp, decision, null)
								.thenReturn(ConnectDecision.denied());
					}
					return allow(callerGatewayId, identity, node, gatewayName, requestedPrincipal, sourceIp, sessionId,
							decision, epoch, now);
				})));
	}

	private Mono<ConnectDecision> allow(UUID callerGatewayId, String identity, Node node, String gatewayName,
			String requestedPrincipal, String sourceIp, UUID sessionId, DataPlaneDecision decision, long epoch,
			Instant now) {
		int ttlSeconds = effectiveGrantTtl(decision.grantTtlSeconds());
		Instant grantExpiry = now.plusSeconds(ttlSeconds);
		List<String> logins = decision.sortedLogins();
		List<String> capabilities = decision.sortedCapabilities();
		DecisionContext context = new DecisionContext(node.id(), node.name(), logins, capabilities, requestedPrincipal,
				grantExpiry, epoch, properties.getDecisionTtl(), callerGatewayId, sessionId, sourceIp, now);

		return Mono.zip(signer.sign(context), resolveNodeConnection(node)).flatMap(signedAndConn -> {
			SignedDecisionContext signed = signedAndConn.getT1();
			NodeConnectionInfo nodeConnection = signedAndConn.getT2();
			SshSession session = new SshSession(sessionId, identity, node.id(), node.name(), requestedPrincipal,
					callerGatewayId, gatewayName, "standing", capabilities, decision.matchedRuleId(),
					decision.matchedRuleName(), null, null, epoch, grantExpiry, now, null, null, null, null, null);
			Map<String, String> detail = new HashMap<>();
			detail.put("matched_rule", nullSafe(decision.matchedRuleName()));
			detail.put("principal", requestedPrincipal);
			detail.put("policy_epoch", Long.toString(epoch));
			// ssh_session snapshot + the two single-use tokens + the allow audit are one
			// transaction: a failure rolls all back, so a token is never minted without its
			// session row. The recording token is bound to the SAME {gateway, session,
			// node,
			// principal} as the signing token (Design §12/§15). The tokens/session are
			// saved
			// on the single tx connection sequentially; the audit write (which serializes
			// on
			// the chain advisory lock) is last so that lock is held only until commit.
			Mono<ConnectDecision> allowed = sshSessions.save(session)
					.then(tokens.mint(callerGatewayId, sessionId, node.id(), requestedPrincipal, capabilities,
							sourceIp))
					.flatMap(sessionToken -> recordingTokens
							.mint(callerGatewayId, sessionId, node.id(), requestedPrincipal, sourceIp)
							.flatMap(recordingToken -> audit
									.record(callerGatewayId.toString(), identity, DECISION_ACTION, "success", sessionId,
											node.id(), detail)
									.thenReturn(ConnectDecision.allow(signed, sessionToken, recordingToken,
											nodeConnection))));
			return tx.transactional(allowed);
		});
	}

	// The node's connectivity + host-identity answer from inventory (Design §9;
	// FR-CONN-1/2/5). Reuses the already-loaded node and adds only the
	// node_host_key read (plus the trusted host-CA set when a row anchors to it) —
	// public material only, never a private key (§9.3).
	private Mono<NodeConnectionInfo> resolveNodeConnection(Node node) {
		NodeConnectionInfo.ConnectorModel model = NodeConnectionInfo.ConnectorModel.fromInventory(node.connectorKind());
		String dial = dialAddress(node);
		return hostKeys.findByNodeId(node.id()).collectList().flatMap(rows -> {
			List<byte[]> pinned = rows.stream().filter(row -> "pinned_key".equals(row.source()))
					.map(row -> wireBlob(row.publicKey())).filter(Objects::nonNull).toList();
			// The node's enrollment host cert(s): russh negotiates only the plain host key
			// at KEX (never the live cert), so the CP hands over the stored cert to verify.
			List<byte[]> hostCerts = rows.stream().filter(row -> "host_ca".equals(row.source()))
					.map(row -> wireBlob(row.hostCertRef())).filter(Objects::nonNull).toList();
			if (hostCerts.isEmpty()) {
				return Mono.just(nodeConnection(node, model, dial, List.of(), List.of(), pinned, List.of()));
			}
			return caRotation.trustedCaKeys("host").map(caLines -> {
				List<byte[]> caKeys = caLines.stream().map(ConnectAuthorizationService::wireBlob)
						.filter(Objects::nonNull).toList();
				// Advertise the host-CA path only as a complete triple — trusted CA key(s) to
				// check the signature, the cert, and the expected principal. Missing any leg
				// the Gateway can't verify (no TOFU), so emit none and let pinned / the
				// empty-warn handle it (upholds the proto invariant: host_certificates
				// non-empty whenever host_ca_keys is set).
				if (caKeys.isEmpty()) {
					return nodeConnection(node, model, dial, List.of(), List.of(), pinned, List.of());
				}
				return nodeConnection(node, model, dial, caKeys, List.of(node.name()), pinned, hostCerts);
			});
		});
	}

	private NodeConnectionInfo nodeConnection(Node node, NodeConnectionInfo.ConnectorModel model, String dial,
			List<byte[]> caKeys, List<String> principals, List<byte[]> pinned, List<byte[]> hostCerts) {
		NodeConnectionInfo info = new NodeConnectionInfo(model, dial, caKeys, principals, pinned, hostCerts);
		// FR-CONN-5/7 (§9.3): an agentless node with no host-CA anchor and no pinned
		// key has no enrollment-anchored trust — the Gateway aborts (no TOFU). The
		// decision still ALLOWs; warn so the operator repairs the enrollment.
		if (model == NodeConnectionInfo.ConnectorModel.AGENTLESS && !info.hasHostVerification()) {
			LOG.warn("agentless node {} ({}) has no host-verification material (no host_ca keys, no pinned host "
					+ "keys); the Gateway will abort the session (no TOFU) — enroll a host cert or pin a host key",
					node.id(), node.name());
		}
		return info;
	}

	// §9.2: the agentless dial address is "host:port". Inventory stores a reachable
	// address; if it carries no explicit port, default to SSH 22 (a bare IPv6
	// literal is bracketed first so the result is a valid host:port).
	private static String dialAddress(Node node) {
		String address = node.address();
		if (address == null || address.isBlank()) {
			return ""; // an agent node dials out and needs none (empty per the wire contract)
		}
		String trimmed = address.trim();
		if (hasExplicitPort(trimmed)) {
			return trimmed;
		}
		boolean bareIpv6 = !trimmed.startsWith("[") && trimmed.indexOf(':') != trimmed.lastIndexOf(':');
		return (bareIpv6 ? "[" + trimmed + "]" : trimmed) + ":22";
	}

	private static boolean hasExplicitPort(String address) {
		if (address.startsWith("[")) {
			return address.indexOf("]:") >= 0; // bracketed IPv6 with an explicit :port
		}
		int firstColon = address.indexOf(':');
		if (firstColon < 0 || firstColon != address.lastIndexOf(':')) {
			return false; // no colon (host/IPv4) or many colons (unbracketed IPv6) → no port
		}
		String port = address.substring(firstColon + 1);
		return !port.isEmpty() && port.chars().allMatch(Character::isDigit);
	}

	// An OpenSSH host public-key / TrustedUserCAKeys line is `<type> <base64>
	// [comment]`;
	// the base64 middle token IS the SSH wire encoding. A malformed line returns
	// null
	// and is dropped — fail-closed (dropped trust → the Gateway aborts, never
	// TOFU).
	private static byte[] wireBlob(String openSshLine) {
		if (openSshLine == null) {
			return null;
		}
		String[] fields = openSshLine.trim().split("\\s+");
		if (fields.length < 2) {
			return null;
		}
		try {
			return Base64.getDecoder().decode(fields[1]);
		} catch (IllegalArgumentException notBase64) {
			return null;
		}
	}

	private int effectiveGrantTtl(int grantTtlSeconds) {
		long ceiling = properties.getMaxGrantTtl().toSeconds();
		long chosen = grantTtlSeconds > 0 ? Math.min(grantTtlSeconds, ceiling) : ceiling;
		return (int) Math.min(chosen, Integer.MAX_VALUE);
	}

	private Mono<ConnectDecision> denyMissingInput(UUID callerGatewayId, String identity, UUID nodeId,
			String sourceIp) {
		return auditDeny(callerGatewayId, identity, nodeId, sourceIp,
				DataPlaneDecision.deny(DataPlaneDecision.Reason.EVALUATION_ERROR, null, null), "missing_input")
				.thenReturn(ConnectDecision.denied());
	}

	private Mono<Void> auditDeny(UUID callerGatewayId, String identity, UUID nodeId, String sourceIp,
			DataPlaneDecision decision, String note) {
		Map<String, String> detail = new HashMap<>();
		detail.put("reason", decision.reason().name());
		if (sourceIp != null) {
			detail.put("source_ip", sourceIp); // forensics: which source was denied
		}
		if (decision.matchedRuleName() != null) {
			detail.put("matched_rule", decision.matchedRuleName());
		}
		if (note != null) {
			detail.put("note", note);
		}
		return bestEffortAudit(callerGatewayId, identity, nodeId, "denied", detail);
	}

	private Mono<Void> auditError(UUID callerGatewayId, String identity, UUID nodeId, String sourceIp) {
		Map<String, String> detail = new HashMap<>();
		detail.put("reason", DataPlaneDecision.Reason.EVALUATION_ERROR.name());
		if (sourceIp != null) {
			detail.put("source_ip", sourceIp);
		}
		return bestEffortAudit(callerGatewayId, identity, nodeId, "error", detail);
	}

	// A lost decision-log write must not fail the (already fail-closed) deny, but
	// it
	// MUST be observable — a silent audit gap on the deny path defeats FR-AUD-7.
	private Mono<Void> bestEffortAudit(UUID callerGatewayId, String identity, UUID nodeId, String outcome,
			Map<String, String> detail) {
		return audit.record(actor(callerGatewayId), identity, DECISION_ACTION, outcome, null, nodeId, detail)
				.onErrorResume(auditFailure -> {
					LOG.error("authz decision-log write failed (decision still denied): {}", auditFailure.toString());
					return Mono.empty();
				});
	}

	private static String actor(UUID callerGatewayId) {
		return callerGatewayId == null ? "unknown" : callerGatewayId.toString();
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private static String nullSafe(String value) {
		return value == null ? "" : value;
	}

	// A node's resolved labels are a jsonb object of string->string; coerce values
	// to text (a non-string label value simply stringifies).
	private static Map<String, String> labelsOf(JsonNode resolvedLabels) {
		Map<String, String> labels = new HashMap<>();
		if (resolvedLabels != null && resolvedLabels.isObject()) {
			for (var entry : resolvedLabels.properties()) {
				labels.put(entry.getKey(), entry.getValue().asString());
			}
		}
		return labels;
	}
}
