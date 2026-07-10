package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.sessionlayer.controlplane.ca.backend.local.Kek;
import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import io.sessionlayer.controlplane.ca.backend.local.LocalCaBackend;
import io.sessionlayer.controlplane.ca.backend.local.LocalCaKeyStore;
import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.cert.OpenSshCertificateAssembler;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.ca.wire.SshReader;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The mandatory OpenSSH certificate-assembler validation gate (FR-CA-6, §5.2).
 * Proves the assembler against <b>real OpenSSH tooling</b>:
 * {@code ssh-keygen -L} parses and displays the fields; the critical-options
 * and extensions bytes are byte-identical to what {@code ssh-keygen -s}
 * produces (the double-length-prefix cross-check); the CA signature verifies
 * cryptographically; and a throwaway {@code sshd} trusting the CA via
 * {@code TrustedUserCAKeys} accepts the cert. External-tool tests skip
 * gracefully where the tool is unavailable.
 */
class OpenSshCertSignerValidationTest {

	private final OpenSshCertificateAssembler assembler = new OpenSshCertificateAssembler();

	// ---- signer + CA -------------------------------------------------------

	private record Signer(SshCertSigner signer, LocalCaBackend backend) {
	}

	private Signer newLocalSigner() {
		KekProvider kekProvider = new KekProvider(KekProvider.DEV_DEFAULT_KEK_BASE64, "test");
		Kek kek = kekProvider.newKek();
		try {
			LocalCaKeyStore store = new LocalCaKeyStore();
			var generated = store.generate(CaKeyType.ECDSA_NISTP256, kek);
			LocalCaBackend backend = store.load(CaKeyType.ECDSA_NISTP256, kek, generated.wrapped(),
					generated.publicKeyX509());
			return new Signer(new RawSignerCertSigner(backend, assembler), backend);
		} finally {
			kek.destroy();
		}
	}

	private static ECPublicKey generateSubjectKey() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair kp = g.generateKeyPair();
		return (ECPublicKey) kp.getPublic();
	}

	// ---- tests -------------------------------------------------------------

	@Test
	void innerLegCertVerifiesCryptographicallyAndParsesWithSshKeygen(@TempDir Path dir) throws Exception {
		Signer s = newLocalSigner();
		ECPublicKey subject = generateSubjectKey();
		CertificateParameters params = CertificateProfiles.innerLegSessionCert("sess-abc123", "alice@corp", "deploy",
				"10.0.0.0/8", Set.of("shell", "exec"), 42L, Instant.now());
		OpenSshCertificate cert = s.signer().signCertificate(new CertificateRequest(subject, params));

		// (1) Cryptographic verification: the CA signature must verify over the TBS.
		ParsedCert parsed = parse(cert.blob());
		assertThat(verifySignature(parsed, s.backend().publicKey())).isTrue();

		// (2) ssh-keygen -L structural validation (FR-CA-5 fields).
		assumeTrue(commandAvailable("ssh-keygen"), "ssh-keygen not available");
		Path certFile = dir.resolve("inner-cert.pub");
		Files.writeString(certFile, cert.certificateLine() + "\n");
		String out = exec(dir, "ssh-keygen", "-L", "-f", certFile.toString()).stdout();
		assertThat(out).contains("user certificate");
		assertThat(out).contains("Key ID: \"sess-abc123+alice@corp\"");
		assertThat(out).contains("Serial: 42");
		assertThat(out).contains("deploy"); // principal
		assertThat(out).contains("source-address 10.0.0.0/8"); // value-carrying critical option
		assertThat(out).contains("permit-pty"); // granted flag extension
		assertThat(out).doesNotContain("permit-X11-forwarding"); // default-deny (not granted)
		assertThat(out).doesNotContain("permit-agent-forwarding");
	}

	@Test
	void doubleLengthPrefixGoldenBytes() throws Exception {
		Signer s = newLocalSigner();
		ECPublicKey subject = generateSubjectKey();
		// source-address = value option (double prefix); permit-pty = flag (empty
		// data).
		CertificateParameters params = CertificateProfiles.innerLegSessionCert("sess-1", "u", "deploy", "10.0.0.0/8",
				Set.of("shell"), 1L, Instant.now());
		OpenSshCertificate cert = s.signer().signCertificate(new CertificateRequest(subject, params));
		ParsedCert parsed = parse(cert.blob());

		// Critical options content = string("source-address") || string(
		// string("10.0.0.0/8") ).
		byte[] expectedCritical = new SshWriter().writeString("source-address")
				.writeString(new SshWriter().writeString("10.0.0.0/8").toByteArray()).toByteArray();
		assertThat(parsed.criticalOptions()).isEqualTo(expectedCritical);

		// Extensions content = string("permit-pty") || string("") (empty data, still a
		// 4-byte length prefix).
		byte[] expectedExtensions = new SshWriter().writeString("permit-pty").writeString(new byte[0]).toByteArray();
		assertThat(parsed.extensions()).isEqualTo(expectedExtensions);
	}

	@Test
	void criticalOptionsAndExtensionsMatchSshKeygen(@TempDir Path dir) throws Exception {
		assumeTrue(commandAvailable("ssh-keygen"), "ssh-keygen not available");
		// ssh-keygen generates a CA + a subject key and signs a reference cert with the
		// same options; the options/extensions bytes are CA-independent, so ours must
		// be
		// byte-identical.
		exec(dir, "ssh-keygen", "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f", dir.resolve("ca").toString());
		exec(dir, "ssh-keygen", "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f", dir.resolve("subj").toString());
		exec(dir, "ssh-keygen", "-s", dir.resolve("ca").toString(), "-I", "sess-1+alice", "-n", "deploy", "-O", "clear",
				"-O", "permit-pty", "-O", "source-address=10.0.0.0/8", "-z", "7", "-V", "-5m:+5m",
				dir.resolve("subj.pub").toString());
		byte[] refBlob = readCertBlob(dir.resolve("subj-cert.pub"));
		ParsedCert ref = parse(refBlob);

		// Sign OUR cert for the very same subject key with the same options.
		ECPublicKey subject = SshEcdsaPublicKeys.parseAuthorizedKey(Files.readString(dir.resolve("subj.pub")));
		CertificateParameters params = CertificateProfiles.innerLegSessionCert("sess-1", "alice", "deploy",
				"10.0.0.0/8", Set.of("shell"), 7L, Instant.now());
		OpenSshCertificate mine = newLocalSigner().signer().signCertificate(new CertificateRequest(subject, params));
		ParsedCert ours = parse(mine.blob());

		assertThat(ours.criticalOptions()).isEqualTo(ref.criticalOptions());
		assertThat(ours.extensions()).isEqualTo(ref.extensions());
	}

	@Test
	void throwawaySshdAcceptsTheCert(@TempDir Path dir) throws Exception {
		assumeTrue(commandAvailable("ssh-keygen") && commandAvailable("ssh"), "openssh client not available");
		Path sshdPath = findSshd();
		assumeTrue(sshdPath != null, "sshd not available");

		Signer s = newLocalSigner();
		// A real subject keypair (OpenSSH format) so `ssh -i` can use it; we certify
		// its
		// public key with OUR session CA. The cert principal is the current OS user so
		// a
		// non-root throwaway sshd can actually authenticate it (a full handshake).
		String osUser = System.getProperty("user.name");
		exec(dir, "ssh-keygen", "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f", dir.resolve("subj").toString());
		exec(dir, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", dir.resolve("hostkey").toString());
		ECPublicKey subject = SshEcdsaPublicKeys.parseAuthorizedKey(Files.readString(dir.resolve("subj.pub")));
		CertificateParameters params = CertificateProfiles.innerLegSessionCert("sess-sshd", "alice", osUser,
				"127.0.0.1", Set.of("shell"), 99L, Instant.now());
		OpenSshCertificate cert = s.signer().signCertificate(new CertificateRequest(subject, params));
		Files.writeString(dir.resolve("subj-cert.pub"), cert.certificateLine() + "\n");

		// Trust our session CA via TrustedUserCAKeys.
		Path caFile = dir.resolve("session-ca.pub");
		Files.writeString(caFile, s.signer().caAuthorizedKey("session-ca") + "\n");

		int port = freePort();
		Path config = dir.resolve("sshd_config");
		Files.writeString(config,
				String.join("\n", "Port " + port, "ListenAddress 127.0.0.1", "HostKey " + dir.resolve("hostkey"),
						"TrustedUserCAKeys " + caFile, "PubkeyAuthentication yes", "AuthenticationMethods publickey",
						"UsePAM no", "KbdInteractiveAuthentication no", "StrictModes no",
						"PidFile " + dir.resolve("sshd.pid"), "LogLevel VERBOSE", "") + "\n");

		Path sshdLog = dir.resolve("sshd.log");
		Process sshd = new ProcessBuilder(sshdPath.toString(), "-D", "-e", "-f", config.toString())
				.redirectErrorStream(true).redirectOutput(sshdLog.toFile()).start();
		try {
			// Wait for sshd to come up (or bail out to a skip if it cannot run here).
			boolean up = waitForListening(port, sshdLog);
			assumeTrue(up && sshd.isAlive(), "throwaway sshd did not start in this environment");

			// A real end-to-end handshake: sshd validates the CERTIFICATE (CA trust via
			// TrustedUserCAKeys, signature, validity, principal) and completes the login.
			Exec ssh = exec(dir, 15, "ssh", "-F", "/dev/null", "-i", dir.resolve("subj").toString(), "-o",
					"CertificateFile=" + dir.resolve("subj-cert.pub"), "-o", "UserKnownHostsFile=/dev/null", "-o",
					"StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o",
					"ConnectTimeout=5", "-p", Integer.toString(port), osUser + "@127.0.0.1", "echo HANDSHAKE_OK");
			// Full success (the CA-signed cert authenticated + the session ran the
			// command).
			assertThat(ssh.stdout()).contains("HANDSHAKE_OK");
		} finally {
			sshd.destroyForcibly();
			sshd.waitFor(5, TimeUnit.SECONDS);
		}

		String log = Files.readString(sshdLog);
		// sshd's own record that our Java-assembled cert passed CA/signature/validity/
		// principal validation, and never a validation failure.
		assertThat(log).contains("Accepted certificate ID \"sess-sshd+alice\"");
		assertThat(log).contains("signed by ECDSA CA");
		assertThat(log).doesNotContain("Certificate invalid");
		assertThat(log).doesNotContain("incorrect signature");
	}

	private static int freePort() throws IOException {
		try (var socket = new java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
			return socket.getLocalPort();
		}
	}

	// ---- certificate parsing + verification --------------------------------

	private record ParsedCert(byte[] toBeSigned, byte[] criticalOptions, byte[] extensions, byte[] signatureField) {
	}

	private static ParsedCert parse(byte[] blob) {
		SshReader r = new SshReader(blob);
		r.readString(); // cert-type name
		r.readString(); // nonce
		r.readString(); // curve
		r.readString(); // Q
		r.readUint64(); // serial
		r.readUint32(); // type
		r.readString(); // key id
		r.readString(); // principals
		r.readUint64(); // valid after
		r.readUint64(); // valid before
		byte[] critical = r.readString();
		byte[] extensions = r.readString();
		r.readString(); // reserved
		r.readString(); // signature key
		int tbsLen = r.position();
		byte[] signatureField = r.readString();
		return new ParsedCert(Arrays.copyOfRange(blob, 0, tbsLen), critical, extensions, signatureField);
	}

	private static boolean verifySignature(ParsedCert cert, ECPublicKey caPublicKey) throws Exception {
		SshReader sig = new SshReader(cert.signatureField());
		sig.readStringUtf8(); // "ecdsa-sha2-nistp256"
		SshReader inner = new SshReader(sig.readString());
		BigInteger rr = inner.readMpint();
		BigInteger ss = inner.readMpint();
		Signature verifier = Signature.getInstance("SHA256withECDSA");
		verifier.initVerify(caPublicKey);
		verifier.update(cert.toBeSigned());
		return verifier.verify(rsToDer(rr, ss));
	}

	private static byte[] rsToDer(BigInteger r, BigInteger s) {
		byte[] rb = r.toByteArray();
		byte[] sb = s.toByteArray();
		byte[] rInt = derInteger(rb);
		byte[] sInt = derInteger(sb);
		int len = rInt.length + sInt.length;
		SshWriter w = new SshWriter().writeByte(0x30);
		writeDerLen(w, len);
		return w.writeBytes(rInt).writeBytes(sInt).toByteArray();
	}

	private static byte[] derInteger(byte[] magnitude) {
		SshWriter w = new SshWriter().writeByte(0x02);
		writeDerLen(w, magnitude.length);
		return w.writeBytes(magnitude).toByteArray();
	}

	private static void writeDerLen(SshWriter w, int len) {
		if (len < 0x80) {
			w.writeByte(len);
		} else {
			w.writeByte(0x81).writeByte(len);
		}
	}

	private static byte[] readCertBlob(Path certPub) throws IOException {
		String[] parts = Files.readString(certPub).trim().split("\\s+");
		return java.util.Base64.getDecoder().decode(parts[1]);
	}

	// ---- process helpers ---------------------------------------------------

	private record Exec(int exit, String stdout) {
	}

	private Exec exec(Path dir, String... command) throws Exception {
		return exec(dir, 30, command);
	}

	private Exec exec(Path dir, int timeoutSeconds, String... command) throws Exception {
		Process p = new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true).start();
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
		return new Exec(p.exitValue(), out);
	}

	private static boolean commandAvailable(String name) {
		for (String dir : List.of("/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin")) {
			if (Files.isExecutable(Path.of(dir, name))) {
				return true;
			}
		}
		return false;
	}

	private static Path findSshd() {
		for (String candidate : List.of("/usr/sbin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd")) {
			if (Files.isExecutable(Path.of(candidate))) {
				return Path.of(candidate);
			}
		}
		return null;
	}

	private static boolean waitForListening(int port, Path sshdLog) throws Exception {
		for (int i = 0; i < 50; i++) {
			try (var socket = new java.net.Socket()) {
				socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 200);
				return true;
			} catch (IOException ignored) {
				if (Files.exists(sshdLog) && Files.readString(sshdLog).contains("fatal:")) {
					return false;
				}
				Thread.sleep(100);
			}
		}
		return false;
	}
}
