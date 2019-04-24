package de.rub.nds.sshattacker.constants;

/**
 * These values are also used for
 * PubkeyAcceptedKeyTypes
 * HostbasedAcceptedKeyTypes
 * HostKeyAlgorithms
*/
public enum PublicKeyAuthenticationAlgorithm {
    ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
    ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM("ecdsa-sha2-nistp384-cert-v01@openssh.com"),
    ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM("ecdsa-sha2-nistp521-cert-v01@openssh.com"),
    SSH_ED25519_CERT_V01_OPENSSH_COM("ssh-ed25519-cert-v01@openssh.com"),
    RSA_SHA2_512_CERT_V01_OPENSSH_COM("rsa-sha2-512-cert-v01@openssh.com"),
    RSA_SHA2_256_CERT_V01_OPENSSH_COM("rsa-sha2-256-cert-v01@openssh.com"),
    SSH_RSA_CERT_V01_OPENSSH_COM("ssh-rsa-cert-v01@openssh.com"),
    ECDSA_SHA2_NISTP256("ecdsa-sha2-nistp256"),
    ECDSA_SHA2_NISTP384("ecdsa-sha2-nistp384"),
    ECDSA_SHA2_NISTP521("ecdsa-sha2-nistp521"),
    SSH_ED25519("ssh-ed25519"),
    RSA_SHA2_512("rsa-sha2-512"),
    RSA_SHA2_256("rsa-sha2-256"),
    SSH_RSA("ssh-rsa"),
    SSH_DSS("ssh-dss"),
    SSH_DSS_CERT_V01_OPENSSH_COM("ssh-dss-cert-v01@openssh.com");

    private final String name;

    private PublicKeyAuthenticationAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
