package io.sessionlayer.controlplane.ca.cert;

/**
 * OpenSSH certificate type (the {@code uint32 type} field): {@code 1 = user},
 * {@code 2 = host}. The inner-leg session cert is a <b>user</b> cert (FR-CA-5);
 * the host CA issues <b>host</b> certs (Design §9.3).
 */
public enum CertType {

	USER(1), HOST(2);

	private final int value;

	CertType(int value) {
		this.value = value;
	}

	public int value() {
		return value;
	}
}
