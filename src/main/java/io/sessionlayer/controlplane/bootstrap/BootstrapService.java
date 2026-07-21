package io.sessionlayer.controlplane.bootstrap;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.authz.SessionLimitProperties;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * First-admin bootstrap (Design §2A, FR-BOOT-2). On an unconfigured system it
 * provisions the initial platform admin — a config-named OIDC subject, or a
 * printed-once credential surrendered via {@code POST /v1/bootstrap/claim} —
 * seeding a {@code platform-admin} role + a {@code role_binding}. It
 * <b>self-disables</b> once a platform admin with {@code user:manage} +
 * {@code rbac:write} exists (a race-safe conditional flip of
 * {@code operator_settings.bootstrap_completed}), and every use is audited.
 */
@Service
public class BootstrapService {

	private static final Logger LOG = LoggerFactory.getLogger(BootstrapService.class);
	private static final String ADMIN_ROLE = "platform-admin";

	// Race-safe self-disable: only the caller that flips completed=false→true wins
	// and provisions; concurrent HA callers observe zero rows and stand down.
	private static final String CLAIM_COMPLETION = """
			UPDATE config.operator_settings
			SET bootstrap_completed = true, bootstrap_completed_at = now(), version = version + 1
			WHERE singleton = true AND bootstrap_completed = false
			RETURNING id""";

	private final OperatorSettingsRepository settings;
	private final PlatformRoleRepository roles;
	private final RoleBindingRepository bindings;
	private final BootstrapProperties properties;
	private final SessionLimitProperties sessionLimits;
	private final AuditEventStore audit;
	private final DatabaseClient db;

	public BootstrapService(OperatorSettingsRepository settings, PlatformRoleRepository roles,
			RoleBindingRepository bindings, BootstrapProperties properties, SessionLimitProperties sessionLimits,
			AuditEventStore audit, DatabaseClient db) {
		this.settings = settings;
		this.roles = roles;
		this.bindings = bindings;
		this.properties = properties;
		this.sessionLimits = sessionLimits;
		this.audit = audit;
		this.db = db;
	}

	public enum ClaimOutcome {
		PROVISIONED, ALREADY_COMPLETED, INVALID_CREDENTIAL, NOT_CREDENTIAL_MODE
	}

	/**
	 * Run at startup: self-disable if an admin exists, else provision or arm a
	 * credential.
	 */
	public Mono<Void> runAtStartup() {
		return ensureSettings().flatMap(current -> hasPlatformAdmin().flatMap(adminExists -> {
			if (current.bootstrapCompleted()) {
				return Mono.empty();
			}
			if (adminExists) {
				LOG.info("first-admin bootstrap: a platform admin already exists — self-disabling");
				return completeBootstrap().then();
			}
			if (properties.getAdminSubject() != null && !properties.getAdminSubject().isBlank()) {
				return provisionAndComplete(properties.getAdminSubject(), properties.getAdminSubjectKind(),
						"config_named_subject").then();
			}
			return armPrintedCredential(current).then();
		}));
	}

	/** Claim the printed-once credential to become the first admin (FR-BOOT-2). */
	public Mono<ClaimOutcome> claim(String credential, String subject) {
		if (subject == null || subject.isBlank() || credential == null || credential.isBlank()) {
			return Mono.just(ClaimOutcome.INVALID_CREDENTIAL);
		}
		return settings.findSingleton().flatMap(current -> {
			if (current.bootstrapCompleted()) {
				return Mono.just(ClaimOutcome.ALREADY_COMPLETED);
			}
			if (current.bootstrapCredentialHash() == null) {
				return Mono.just(ClaimOutcome.NOT_CREDENTIAL_MODE);
			}
			if (!Secrets.constantTimeEquals(Secrets.sha256Hex(credential), current.bootstrapCredentialHash())) {
				return audit.record(subject, subject, "bootstrap.claim", "denied", null, null,
						Map.of("reason", "invalid_credential")).thenReturn(ClaimOutcome.INVALID_CREDENTIAL);
			}
			// Flip first (single winner), then provision — a lost race never
			// double-provisions.
			return db.sql(CLAIM_COMPLETION).map(row -> row.get("id")).one()
					.flatMap(won -> provisionAdminRole(subject, "user", "printed_credential")
							.thenReturn(ClaimOutcome.PROVISIONED))
					.switchIfEmpty(Mono.just(ClaimOutcome.ALREADY_COMPLETED));
		}).defaultIfEmpty(ClaimOutcome.NOT_CREDENTIAL_MODE);
	}

	private Mono<Void> provisionAndComplete(String subject, String subjectKind, String via) {
		return db.sql(CLAIM_COMPLETION).map(row -> row.get("id")).one()
				.flatMap(won -> provisionAdminRole(subject, subjectKind, via)).then();
	}

	private Mono<Void> provisionAdminRole(String subject, String subjectKind, String via) {
		return ensureAdminRole().flatMap(role -> ensureBinding(role, subject, subjectKind))
				.flatMap(binding -> audit.record(subject, subject, "bootstrap.provision", "success", null, null,
						Map.of("via", via, "role", ADMIN_ROLE, "subject_kind", subjectKind)))
				.doOnSuccess(
						v -> LOG.info("first-admin bootstrap: provisioned platform admin {} (via {})", subject, via))
				.then();
	}

	private Mono<PlatformRole> ensureAdminRole() {
		return roles.findByName(ADMIN_ROLE).switchIfEmpty(
				Mono.defer(() -> roles.save(PlatformRole.create(ADMIN_ROLE, List.copyOf(PlatformPermissions.ALL),
						"First-admin bootstrap role" + " (all platform permissions).", "default"))));
	}

	private Mono<RoleBinding> ensureBinding(PlatformRole role, String subject, String subjectKind) {
		return bindings.findByRoleId(role.id())
				.filter(b -> subjectKind.equals(b.subjectKind()) && subject.equals(b.subject())).next()
				.switchIfEmpty(Mono.defer(
						() -> bindings.save(RoleBinding.create(role.id(), subjectKind, subject, null, "default"))));
	}

	private Mono<Void> armPrintedCredential(OperatorSettings current) {
		if (current.bootstrapCredentialHash() != null) {
			LOG.info("first-admin bootstrap: a printed credential is already armed; awaiting claim");
			return Mono.empty();
		}
		String credential = Secrets.randomToken(24);
		OperatorSettings armed = withCredentialHash(current, Secrets.sha256Hex(credential));
		return settings.save(armed).doOnSuccess(s -> LOG.warn(
				"FIRST-ADMIN BOOTSTRAP CREDENTIAL (shown once): {}  — claim it via POST /v1/bootstrap/claim "
						+ "{{\"credential\":\"...\",\"subject\":\"<your-oidc-subject>\"}}; it self-disables after use.",
				credential)).then();
	}

	Mono<Boolean> hasPlatformAdmin() {
		return roles.findAll().collectMap(PlatformRole::id).flatMap(roleById -> bindings.findAll().any(binding -> {
			PlatformRole role = roleById.get(binding.roleId());
			return role != null && role.permissions() != null
					&& role.permissions().contains(PlatformPermissions.USER_MANAGE)
					&& role.permissions().contains(PlatformPermissions.RBAC_WRITE);
		}));
	}

	private Mono<Long> completeBootstrap() {
		return db.sql(CLAIM_COMPLETION).fetch().rowsUpdated();
	}

	private Mono<OperatorSettings> ensureSettings() {
		return settings.findSingleton()
				.switchIfEmpty(Mono.defer(() -> settings.save(seededDefaults()))
						.onErrorResume(conflict -> settings.findSingleton()))
				.flatMap(this::reconcileSessionLimitDefaults).doOnNext(BootstrapService::warnWhenCapUnlimited);
	}

	// FR-SESS-3: the cluster-default session-limit knobs (concurrent cap, max
	// duration, idle timeout) are OPT-IN deployment-config values
	// (sessionlayer.session-limits.default-*). Seed them into a freshly-created
	// singleton, and — since the singleton may already have been created null at
	// cold start — reconcile each on every boot when its property is set
	// (deployment config is authoritative for the cluster default); when unset,
	// leave the stored value untouched (default null ⇒ unlimited/none), so
	// existing deployments are unaffected.
	private OperatorSettings seededDefaults() {
		return applyConfigured(OperatorSettings.defaults());
	}

	private Mono<OperatorSettings> reconcileSessionLimitDefaults(OperatorSettings current) {
		OperatorSettings reconciled = applyConfigured(current);
		return reconciled == current ? Mono.just(current) : settings.save(reconciled);
	}

	private OperatorSettings applyConfigured(OperatorSettings base) {
		OperatorSettings result = base;
		Integer concurrent = sessionLimits.getDefaultMaxConcurrent();
		if (concurrent != null && !concurrent.equals(result.defaultMaxConcurrentSessions())) {
			result = result.withDefaultMaxConcurrentSessions(concurrent);
		}
		Integer maxSeconds = sessionLimits.getDefaultMaxSessionSeconds();
		if (maxSeconds != null && !maxSeconds.equals(result.defaultMaxSessionSeconds())) {
			result = result.withDefaultMaxSessionSeconds(maxSeconds);
		}
		Integer idleSeconds = sessionLimits.getDefaultIdleTimeoutSeconds();
		if (idleSeconds != null && !idleSeconds.equals(result.defaultIdleTimeoutSeconds())) {
			result = result.withDefaultIdleTimeoutSeconds(idleSeconds);
		}
		return result;
	}

	// S25 Part D: an unlimited cluster-default concurrent cap is a legitimate but
	// easily-unintended posture — say so once, loudly, at boot.
	private static void warnWhenCapUnlimited(OperatorSettings current) {
		if (current.defaultMaxConcurrentSessions() == null) {
			LOG.warn("the cluster-default concurrent-session cap is UNLIMITED: identities without a matching "
					+ "session_limit_policy have no concurrent-session bound. Set "
					+ "sessionlayer.session-limits.default-max-concurrent (or "
					+ "operator_settings.default_max_concurrent_sessions) to cap them.");
		}
	}

	private static OperatorSettings withCredentialHash(OperatorSettings s, String hash) {
		return new OperatorSettings(s.id(), s.singleton(), s.kekReference(), s.defaultCaBackend(),
				s.auditRetentionDays(), s.defaultWormMode(), s.otpTtlSeconds(), s.defaultMaxSessionSeconds(),
				s.defaultIdleTimeoutSeconds(), s.defaultMaxConcurrentSessions(), s.bootstrapAdminSubject(), hash,
				s.bootstrapCompleted(), s.bootstrapCompletedAt(), s.recordingCustomerPublicKey(),
				s.recordingKeySealAlgorithm(), s.recordingKeyRef(), s.recordingRetentionDays(),
				s.recordingStrictDefault(), s.origin(), s.version(), s.createdAt(), s.updatedAt());
	}
}
