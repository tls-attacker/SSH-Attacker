/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum EncryptionAlgorithmFamily {
    NONE(null),
    DES_EDE("DESede"),
    BLOWFISH("Blowfish"),
    TWOFISH("Twofish"),
    AES("AES"),
    SERPENT("Serpent"),
    ARCFOUR("RC4"),
    IDEA("IDEA"),
    CAST128("CAST5"),
    DES("DES"),
    SEED("SEED"),
    CHACHA20_POLY1305("ChaCha20-Poly1305");

    private final String javaName;

    EncryptionAlgorithmFamily(String javaName) {
        this.javaName = javaName;
    }

    public String getJavaName() {
        return javaName;
    }

    public static EncryptionAlgorithmFamily getFamilyForAlgorithm(EncryptionAlgorithm algorithm) {
        switch (algorithm) {
            case NONE:
                return NONE;
            case TRIPLE_DES_CBC:
            case TRIPLE_DES_CTR:
                return DES_EDE;
            case BLOWFISH_CBC:
            case BLOWFISH_CTR:
                return BLOWFISH;
            case TWOFISH_CBC:
            case TWOFISH128_CBC:
            case TWOFISH192_CBC:
            case TWOFISH256_CBC:
            case TWOFISH128_CTR:
            case TWOFISH192_CTR:
            case TWOFISH256_CTR:
                return TWOFISH;
            case AES128_CBC:
            case AES192_CBC:
            case AES256_CBC:
            case AES128_CTR:
            case AES192_CTR:
            case AES256_CTR:
            case AEAD_AES_128_GCM:
            case AEAD_AES_256_GCM:
            case AES128_GCM_OPENSSH_COM:
            case AES256_GCM_OPENSSH_COM:
            case RIJNDAEL_CBC_LYSATOR_LIU_SE:
                return AES;
            case SERPENT128_CBC:
            case SERPENT192_CBC:
            case SERPENT256_CBC:
            case SERPENT128_CTR:
            case SERPENT192_CTR:
            case SERPENT256_CTR:
                return SERPENT;
            case ARCFOUR:
            case ARCFOUR128:
            case ARCFOUR256:
                return ARCFOUR;
            case IDEA_CBC:
            case IDEA_CTR:
                return IDEA;
            case CAST128_CBC:
            case CAST128_CTR:
                return CAST128;
            case DES_CBC:
                return DES;
            case SEED_CBC_SSH_COM:
                return SEED;
            case CHACHA20_POLY1305_OPENSSH_COM:
                return CHACHA20_POLY1305;
            default:
                throw new UnsupportedOperationException(
                        "The encryption algorithm from "
                                + algorithm.name()
                                + " is not supported yet.");
        }
    }
}
