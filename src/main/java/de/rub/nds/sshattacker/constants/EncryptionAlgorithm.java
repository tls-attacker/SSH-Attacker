package de.rub.nds.sshattacker.constants;

public enum EncryptionAlgorithm {
    tdes_cbc("3des-cbc"),
    aes128_cbc("aes128-cbc"),
    aes192_cbc("aes192-cbc"),
    aes256_cbc("aes256-cbc"),
    aes128_ctr("aes128-ctr"),
    aes192_ctr("aes192-ctr"),
    aes256_ctr("aes256-ctr"),
    aes128_gcm_openssh_com("aes128-gcm@openssh.com"),
    aes256_gcm_openssh_com("aes256-gcm@openssh.com"),
    chacha20_poly1305_openssh_com("chacha20-poly1305@openssh.com"),
    rijndael_cbc_lysator_liu_se("rijndael-cbc@lysator.liu.se");

    private String name;

    private EncryptionAlgorithm(String name) {
        this.name = name;
    }
}
