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
        return switch (algorithm) {
            case NONE -> NONE;
            case TRIPLE_DES_CBC, TRIPLE_DES_CTR -> DES_EDE;
            case BLOWFISH_CBC, BLOWFISH_CTR -> BLOWFISH;
            case TWOFISH_CBC,
                    TWOFISH128_CBC,
                    TWOFISH192_CBC,
                    TWOFISH256_CBC,
                    TWOFISH128_CTR,
                    TWOFISH192_CTR,
                    TWOFISH256_CTR ->
                    TWOFISH;
            case AES128_CBC,
                    AES192_CBC,
                    AES256_CBC,
                    AES128_CTR,
                    AES192_CTR,
                    AES256_CTR,
                    AEAD_AES_128_GCM,
                    AEAD_AES_256_GCM,
                    AES128_GCM_OPENSSH_COM,
                    AES256_GCM_OPENSSH_COM,
                    RIJNDAEL_CBC_LYSATOR_LIU_SE ->
                    AES;
            case SERPENT128_CBC,
                    SERPENT192_CBC,
                    SERPENT256_CBC,
                    SERPENT128_CTR,
                    SERPENT192_CTR,
                    SERPENT256_CTR ->
                    SERPENT;
            case ARCFOUR, ARCFOUR128, ARCFOUR256 -> ARCFOUR;
            case IDEA_CBC, IDEA_CTR -> IDEA;
            case CAST128_CBC, CAST128_CTR -> CAST128;
            case DES_CBC -> DES;
            case SEED_CBC_SSH_COM -> SEED;
            case CHACHA20_POLY1305, CHACHA20_POLY1305_OPENSSH_COM -> CHACHA20_POLY1305;
            default ->
                    throw new UnsupportedOperationException(
                            "The encryption algorithm from "
                                    + algorithm.name()
                                    + " is not supported yet.");
        };
    }
}
