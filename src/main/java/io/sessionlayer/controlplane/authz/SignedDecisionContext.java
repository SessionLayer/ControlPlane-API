package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import java.util.List;

/**
 * A produced, signed decision context ready for the wire: the proto message,
 * the exact canonical bytes that were signed, the signature, and the signer's
 * leaf + CA chain (DER) so the Gateway can verify without new trust
 * distribution.
 */
public record SignedDecisionContext(DecisionContext context, byte[] signedContext, byte[] signature,
		byte[] signerCertificateDer, List<byte[]> caChainDer) {
}
