/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum EncryptionAlgorithm {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#table-ssh-parameters-17
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
     * - https://www.lysator.liu.se/rijndael/
     */
    // [ RFC 4253 ]
    TRIPLE_DES_CBC("3des-cbc", 24, 8),
    BLOWFISH_CBC("blowfish-cbc", 16, 8),
    TWOFISH256_CBC("twofish256-cbc", 32, 16),
    // This is an alias for twofish256-cbc
    TWOFISH_CBC("twofish-cbc", 32, 16),
    TWOFISH192_CBC("twofish192-cbc", 24, 16),
    TWOFISH128_CBC("twofish128-cbc", 16, 16),
    AES256_CBC("aes256-cbc", 32, 16),
    AES192_CBC("aes192-cbc", 24, 16),
    AES128_CBC("aes128-cbc", 16, 16),
    SERPENT256_CBC("serpent256-cbc", 32, 16),
    SERPENT192_CBC("serpent192-cbc", 24, 16),
    SERPENT128_CBC("serpent128-cbc", 16, 16),
    // arcfour was deprecated in [ RFC 8758 ]
    // blockSize = 0 as arcfour is a stream cipher, the output is used as a
    // keystream
    ARCFOUR("arcfour", 16, 0),
    IDEA_CBC("idea-cbc", 16, 8),
    CAST128_CBC("cast128-cbc", 16, 8),
    NONE("none", 0, 0),
    // [ FIPS-46-3 ]
    // des-cbc is deprecated
    DES_CBC("des-cbc", 8, 8),
    // [ RFC 4345 ]
    // arcfour128 and arcfour256 were deprecated in [ RFC 8758 ]
    ARCFOUR128("arcfour128", 16, 0),
    ARCFOUR256("arcfour256", 32, 0),
    // [ RFC 4344 ]
    AES128_CTR("aes128-ctr", 16, 16),
    AES192_CTR("aes192-ctr", 24, 16),
    AES256_CTR("aes256-ctr", 32, 16),
    TRIPLE_DES_CTR("3des-ctr", 24, 8),
    BLOWFISH_CTR("blowfish-ctr", 16, 8),
    TWOFISH128_CTR("twofish128-ctr", 16, 16),
    TWOFISH192_CTR("twofish192-ctr", 24, 16),
    TWOFISH256_CTR("twofish256-ctr", 32, 16),
    SERPENT128_CTR("serpent128-ctr", 16, 16),
    SERPENT192_CTR("serpent192-ctr", 24, 16),
    SERPENT256_CTR("serpent256-ctr", 32, 16),
    IDEA_CTR("idea-ctr", 16, 8),
    CAST128_CTR("cast128-ctr", 16, 8),
    // [ RFC 5647 ]
    AEAD_AES_128_GCM("AEAD_AES_128_GCM", 16, 8),
    AEAD_AES_256_GCM("AEAD_AES_256_GCM", 32, 8),
    // Vendor extensions
    // [ OpenSSH ]
    AES128_GCM_OPENSSH_COM("aes128-gcm@openssh.com", 16, 16),
    AES256_GCM_OPENSSH_COM("aes256-gcm@openssh.com", 32, 16),
    // blockSize = 0 as ChaCha20 is a stream cipher, the output is used as a
    // keystream
    CHACHA20_POLY1305_OPENSSH_COM("chacha20-poly1305@openssh.com", 64, 0),
    // [ Lysator Academic Computer Society ]
    RIJNDAEL_CBC_LYSATOR_LIU_SE("rijndael-cbc@lysator.liu.se", 16, 16);

    private final String name;
    private final int keySize;
    private final int blockSize;

    EncryptionAlgorithm(String name, int keySize, int blockSize) {
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
