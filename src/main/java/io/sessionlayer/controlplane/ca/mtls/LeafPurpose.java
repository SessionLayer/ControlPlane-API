package io.sessionlayer.controlplane.ca.mtls;

/**
 * The role of an issued X.509 leaf certificate on the internal mTLS plane,
 * which fixes its Extended Key Usage: the CP's own gRPC server certificate
 * ({@code serverAuth}) or a Gateway's client identity certificate
 * ({@code clientAuth}). Default-deny: exactly one EKU is stamped per leaf.
 */
public enum LeafPurpose {

	/** The CP gRPC server certificate (EKU serverAuth). */
	SERVER,

	/** A Gateway's mTLS client identity certificate (EKU clientAuth). */
	CLIENT
}
