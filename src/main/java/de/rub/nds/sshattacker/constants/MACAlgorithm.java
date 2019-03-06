package de.rub.nds.sshattacker.constants;

public enum MACAlgorithm {
    // TODO are these lengths right?
    hmac_md5("hmac-md5", 16, 16),
    hmac_md5_96("hmac-md5-96", 12, 12),
    hmac_sha1("hmac-sha1", 20, 20),
    hmac_sha1_96("hmac-sha1-96", 12, 12),
    hmac_sha2_256("hmac-sha2-256", 32, 32),
    hmac_sha2_512("hmac-sha2-512", 64, 64),
    umac_64_openssh_com("umac-64@openssh.com", 16, 8),
    umac_128_openssh_com("umac-128@openssh.com", 16, 16),
    hmac_md5_etm_openssh_com("hmac-md5-etm@openssh.com", 16, 16),
    hmac_md5_96_etm_openssh_com("hmac-md5-96-etm@openssh.com", 12, 12),
    hmac_sha1_etm_openssh_com("hmac-sha1-etm@openssh.com", 20, 20),
    hmac_sha1_96_etm_openssh_com("hmac-sha1-96-etm@openssh.com", 12, 12),
    hmac_sha2_256_etm_openssh_com("hmac-sha2-256-etm@openssh.com", 32, 32),
    hmac_sha2_512_etm_openssh_com("hmac-sha2-512-etm@openssh.com", 64, 64),
    umac_64_etm_openssh_com("umac-64-etm@openssh.com", 16, 8),
    umac_128_etm_openssh_com("umac-128-etm@openssh.com", 16, 16);

    private final String name;
    private final int keySize;
    private final int outputSize;

    private MACAlgorithm(String name, int keySize, int outputSize) {
        this.name = name;
        this.keySize = keySize;
        this.outputSize = outputSize;

    }

    @Override
    public String toString() {
        return name;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getOutputSize() {
        return outputSize;
    }

}
