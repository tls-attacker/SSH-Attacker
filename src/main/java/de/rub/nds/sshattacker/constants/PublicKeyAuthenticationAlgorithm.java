package de.rub.nds.sshattacker.constants;

// same values for
// PubkeyAcceptedKeyTypes
// HostbasedAcceptedKeyTypes
// HostKeyAlgorithms
public enum PublicKeyAuthenticationAlgorithm {
    ecdsa_sha2_nistp256_cert_v01_openssh_com("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
    ecdsa_sha2_nistp384_cert_v01_openssh_com("ecdsa-sha2-nistp384-cert-v01@openssh.com"),
    ecdsa_sha2_nistp521_cert_v01_openssh_com("ecdsa-sha2-nistp521-cert-v01@openssh.com"),
    ssh_ed25519_cert_v01_openssh_com("ssh-ed25519-cert-v01@openssh.com"),
    rsa_sha2_512_cert_v01_openssh_com("rsa-sha2-512-cert-v01@openssh.com"),
    rsa_sha2_256_cert_v01_openssh_com("rsa-sha2-256-cert-v01@openssh.com"),
    ssh_rsa_cert_v01_openssh_com("ssh-rsa-cert-v01@openssh.com"),
    ecdsa_sha2_nistp256("ecdsa-sha2-nistp256"),
    ecdsa_sha2_nistp384("ecdsa-sha2-nistp384"),
    ecdsa_sha2_nistp521("ecdsa-sha2-nistp521"),
    ssh_ed25519("ssh-ed25519"),
    rsa_sha2_512("rsa-sha2-512"),
    rsa_sha2_256("rsa-sha2-256"),
    ssh_rsa("ssh-rsa"),
    ssh_dss("ssh-dss"),
    ssh_dss_cert_v01_openssh_com("ssh-dss-cert-v01@openssh.com");

    private final String name;

    private PublicKeyAuthenticationAlgorithm(String name) {
        this.name = name;
    }
    
    public String getValue(){
        return name;
    }
}
