package de.rub.nds.sshattacker.constants;

public enum MACAlgorithm {
    hmac_md5("hmac-md5"),
    hmac_md5_96("hmac-md5-96"),
    hmac_sha1("hmac-sha1"),
    hmac_sha1_96("hmac-sha1-96"),
    hmac_sha2_256("hmac-sha2-256"),
    hmac_sha2_512("hmac-sha2-512"),
    umac_64_openssh_com("umac-64@openssh.com"),
    umac_128_openssh_com("umac-128@openssh.com"),
    hmac_md5_etm_openssh_com("hmac-md5-etm@openssh.com"),
    hmac_md5_96_etm_openssh_com("hmac-md5-96-etm@openssh.com"),
    hmac_sha1_etm_openssh_com("hmac-sha1-etm@openssh.com"),
    hmac_sha1_96_etm_openssh_com("hmac-sha1-96-etm@openssh.com"),
    hmac_sha2_256_etm_openssh_com("hmac-sha2-256-etm@openssh.com"),
    hmac_sha2_512_etm_openssh_com("hmac-sha2-512-etm@openssh.com"),
    umac_64_etm_openssh_com("umac-64-etm@openssh.com"),
    umac_128_etm_openssh_com("umac-128-etm@openssh.com");

    private String name;

    private MACAlgorithm(String name) {
        this.name = name;
    }

}
