package de.rub.nds.sshattacker.constants;

public enum EncryptionAlgorithm {
    TDES_CBC("3des-cbc", 8, 8),
    AES128_CBC("aes128-cbc", 16, 16),
    AES192_CBC("aes192-cbc", 24, 16),
    AES256_CBC("aes256-cbc", 32, 16),
    AES128_CTR("aes128-ctr", 16, 16),
    AES192_CTR("aes192-ctr", 24, 16),
    AES256_CTR("aes256-ctr", 32, 16),
    AES128_GCM_OPENSSH_COM("aes128-gcm@openssh.com", 16, 16),
    AES256_GCM_OPENSSH_COM("aes256-gcm@openssh.com", 32, 16),
    CHACHA20_POLY1305_OPENSSH_COM("chacha20-poly1305@openssh.com", 64, 0), // todo find keylength
    RIJNDAEL_CBC_LYSATOR_LIU_SE("rijndael-cbc@lysator.liu.se", 16, 16);

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
