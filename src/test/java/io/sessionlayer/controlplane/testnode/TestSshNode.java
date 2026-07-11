package io.sessionlayer.controlplane.testnode;

import java.nio.file.Path;
import java.util.Base64;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.Transferable;

/**
 * The vendored Debian 13 OpenSSH node
 * ({@code src/test/resources/testnode/sshd}) as a Testcontainers harness (Part
 * D). The node trusts <b>only</b> the injected session CA via
 * {@code TrustedUserCAKeys}; everything — key generation, cert install, and the
 * SSH handshake — runs <b>inside</b> the container, so no host {@code ssh} is
 * ever used (the user directive). The node has both {@code openssh-server} and
 * {@code openssh-client}, so it can ssh to its own {@code sshd} to complete a
 * real certificate handshake.
 */
public final class TestSshNode {

	/** Cached image name so repeated ITs reuse one build. */
	private static final String IMAGE_NAME = "sessionlayer-testnode:it";
	private static final Path CONTEXT = Path.of("src/test/resources/testnode/sshd");

	private TestSshNode() {
	}

	/**
	 * Start the node trusting {@code trustedUserCaAuthorizedKey} (an OpenSSH
	 * {@code TrustedUserCAKeys} line). Optionally installs a host certificate.
	 */
	@SuppressWarnings("resource")
	public static GenericContainer<?> start(String trustedUserCaAuthorizedKey) {
		GenericContainer<?> node = new GenericContainer<>(
				new ImageFromDockerfile(IMAGE_NAME, false).withFileFromPath(".", CONTEXT))
				.withEnv("TRUSTED_USER_CA", trustedUserCaAuthorizedKey).withExposedPorts(22)
				.waitingFor(Wait.forListeningPort());
		node.start();
		return node;
	}

	/**
	 * Generate an ECDSA P-256 inner keypair <b>inside</b> the node with
	 * {@code ssh-keygen} and return its OpenSSH wire public-key blob (the RPC's
	 * {@code subject_public_key}). The private key stays in the container at
	 * {@code path}.
	 */
	public static byte[] generateInnerKey(GenericContainer<?> node, String path) throws Exception {
		exec(node, "ssh-keygen", "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f", path);
		Container.ExecResult pub = node.execInContainer("cat", path + ".pub");
		String[] parts = pub.getStdout().trim().split("\\s+");
		return Base64.getDecoder().decode(parts[1]);
	}

	/** Install a signed certificate line into the node at {@code path}. */
	public static void installCertificate(GenericContainer<?> node, String path, String certificateLine)
			throws Exception {
		node.copyFileToContainer(Transferable.of(certificateLine + "\n"), path);
	}

	/**
	 * Complete a real SSH handshake inside the node: {@code ssh -i key -o
	 * CertificateFile=cert user@localhost echo HANDSHAKE_OK}. Returns combined
	 * stdout+stderr.
	 */
	public static String handshake(GenericContainer<?> node, String keyPath, String certPath, String user)
			throws Exception {
		Container.ExecResult result = node.execInContainer("ssh", "-i", keyPath, "-o", "CertificateFile=" + certPath,
				"-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes",
				"-o", "BatchMode=yes", "-o", "ConnectTimeout=5", user + "@localhost", "echo HANDSHAKE_OK");
		return result.getStdout() + result.getStderr();
	}

	/**
	 * Run {@code ssh-keygen -L} inside the node to structurally validate a cert.
	 */
	public static String inspectCertificate(GenericContainer<?> node, String certPath) throws Exception {
		return node.execInContainer("ssh-keygen", "-L", "-f", certPath).getStdout();
	}

	private static void exec(GenericContainer<?> node, String... command) throws Exception {
		Container.ExecResult result = node.execInContainer(command);
		if (result.getExitCode() != 0) {
			throw new IllegalStateException("command failed (" + result.getExitCode() + "): "
					+ String.join(" ", command) + "\n" + result.getStdout() + result.getStderr());
		}
	}
}
