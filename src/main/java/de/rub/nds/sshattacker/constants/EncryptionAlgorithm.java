package de.rub.nds.sshattacker.constants;

public enum EncryptionAlgorithm {
    tdes_cbc("3des-cbc", 8, 8),
    aes128_cbc("aes128-cbc", 16, 16),
    aes192_cbc("aes192-cbc", 24, 16),
    aes256_cbc("aes256-cbc", 32, 16),
    aes128_ctr("aes128-ctr", 16, 16),
    aes192_ctr("aes192-ctr", 24, 16),
    aes256_ctr("aes256-ctr", 32, 16),
    aes128_gcm_openssh_com("aes128-gcm@openssh.com", 16, 16),
    aes256_gcm_openssh_com("aes256-gcm@openssh.com", 32, 16),
    chacha20_poly1305_openssh_com("chacha20-poly1305@openssh.com", 64, 0), // todo find keylength
    rijndael_cbc_lysator_liu_se("rijndael-cbc@lysator.liu.se", 16, 16);

    private final String name;
    private final int keySize;
    private final int blockSize;

    private EncryptionAlgorithm(String name, int keySize, int blockSize) {
        this.name = name;
        this.keySize = keySize;
        this.blockSize = blockSize;
    }

    @Override
    public String toString() {
        return name;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getBlockSize() {
        return blockSize;
    }
}
