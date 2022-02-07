/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum EncryptionAlgorithm {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#table-ssh-parameters-17
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
     * - https://www.lysator.liu.se/rijndael/
     * - https://datatracker.ietf.org/doc/html/draft-kanno-secsh-camellia-02
     */
    // [ RFC 4253 ]
    TRIPLE_DES_CBC(
            "3des-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            24,
            8,
            "DESede/CBC/NoPadding"),
    BLOWFISH_CBC(
            "blowfish-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            8,
            "Blowfish/CBC/NoPadding"),
    TWOFISH256_CBC(
            "twofish256-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            32,
            16,
            "Twofish/CBC/NoPadding"),
    // This is an alias for twofish256-cbc
    TWOFISH_CBC(
            "twofish-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            32,
            16,
            "Twofish/CBC/NoPadding"),
    TWOFISH192_CBC(
            "twofish192-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            24,
            16,
            "Twofish/CBC/NoPadding"),
    TWOFISH128_CBC(
            "twofish128-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            16,
            "Twofish/CBC/NoPadding"),
    AES256_CBC(
            "aes256-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            32,
            16,
            "AES/CBC/NoPadding"),
    AES192_CBC(
            "aes192-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            24,
            16,
            "AES/CBC/NoPadding"),
    AES128_CBC(
            "aes128-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            16,
            "AES/CBC/NoPadding"),
    SERPENT256_CBC(
            "serpent256-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            32,
            16,
            "Serpent/CBC/NoPadding"),
    SERPENT192_CBC(
            "serpent192-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            24,
            16,
            "Serpent/CBC/NoPadding"),
    SERPENT128_CBC(
            "serpent128-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            16,
            "Serpent/CBC/NoPadding"),
    // arcfour was deprecated in [ RFC 8758 ]
    ARCFOUR("arcfour", EncryptionAlgorithmType.STREAM, null, 16, 1, 0, 0, "RC4"),
    IDEA_CBC(
            "idea-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            8,
            "IDEA/CBC/NoPadding"),
    CAST128_CBC(
            "cast128-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            8,
            "CAST5/CBC/NoPadding"),
    NONE("none", EncryptionAlgorithmType.STREAM, null, 0, 1, 0, 0),
    // [ FIPS-46-3 ]
    // des-cbc is deprecated
    DES_CBC(
            "des-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            8,
            8,
            "DES/CBC/NoPadding"),
    // [ RFC 4345 ]
    // arcfour128 and arcfour256 were deprecated in [ RFC 8758 ]
    ARCFOUR128("arcfour128", EncryptionAlgorithmType.STREAM, null, 16, 1, 0, 0, "RC4"),
    ARCFOUR256("arcfour256", EncryptionAlgorithmType.STREAM, null, 32, 1, 0, 0, "RC4"),
    // [ RFC 4344 ]
    AES128_CTR(
            "aes128-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            16,
            "AES/CTR/NoPadding"),
    AES192_CTR(
            "aes192-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            24,
            16,
            "AES/CTR/NoPadding"),
    AES256_CTR(
            "aes256-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            32,
            16,
            "AES/CTR/NoPadding"),
    TRIPLE_DES_CTR(
            "3des-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            24,
            8,
            "DESede/CTR/NoPadding"),
    BLOWFISH_CTR(
            "blowfish-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            8,
            "Blowfish/CTR/NoPadding"),
    TWOFISH128_CTR(
            "twofish128-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            16,
            "Twofish/CTR/NoPadding"),
    TWOFISH192_CTR(
            "twofish192-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            24,
            16,
            "Twofish/CTR/NoPadding"),
    TWOFISH256_CTR(
            "twofish256-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            32,
            16,
            "Twofish/CTR/NoPadding"),
    SERPENT128_CTR(
            "serpent128-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            16,
            "Serpent/CTR/NoPadding"),
    SERPENT192_CTR(
            "serpent192-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            24,
            16,
            "Serpent/CTR/NoPadding"),
    SERPENT256_CTR(
            "serpent256-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            32,
            16,
            "Serpent/CTR/NoPadding"),
    IDEA_CTR(
            "idea-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            8,
            "IDEA/CBC/NoPadding"),
    CAST128_CTR(
            "cast128-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            8,
            "CAST5/CBC/NoPadding"),
    // [ RFC 5647 ]
    AEAD_AES_128_GCM(
            "AEAD_AES_128_GCM",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            16,
            8,
            12,
            16,
            "AES/GCM/NoPadding"),
    AEAD_AES_256_GCM(
            "AEAD_AES_256_GCM",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            32,
            8,
            12,
            16,
            "AES/GCM/NoPadding"),
    // Vendor extensions
    // [ OpenSSH ]
    AES128_GCM_OPENSSH_COM(
            "aes128-gcm@openssh.com",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            16,
            16,
            12,
            16,
            "AES/GCM/NoPadding"),
    AES256_GCM_OPENSSH_COM(
            "aes256-gcm@openssh.com",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            32,
            16,
            12,
            16,
            "AES/GCM/NoPadding"),
    CHACHA20_POLY1305_OPENSSH_COM(
            "chacha20-poly1305@openssh.com",
            EncryptionAlgorithmType.AEAD,
            null,
            64,
            1,
            12,
            16,
            // Note: This is the java name for the packet length cipher
            "ChaCha"),
    // [ OpenSSH Suggestions ]
    CAMELLIA128_CBC_OPENSSH_ORG(
            "camellia128-cbc@openssh.org",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            16,
            "Camellia/CBC/NoPadding"),
    CAMELLIA192_CBC_OPENSSH_ORG(
            "camellia192-cbc@openssh.org",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            24,
            16,
            "Camellia/CBC/NoPadding"),
    CAMELLIA256_CBC_OPENSSH_ORG(
            "camellia256-cbc@openssh.org",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            32,
            16,
            "Camellia/CBC/NoPadding"),
    CAMELLIA128_CTR_OPENSSH_ORG(
            "camellia128-ctr@openssh.org",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            16,
            "Camellia/CTR/NoPadding"),
    CAMELLIA192_CTR_OPENSSH_ORG(
            "camellia192-ctr@openssh.org",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            24,
            16,
            "Camellia/CTR/NoPadding"),
    CAMELLIA256_CTR_OPENSSH_ORG(
            "camellia256-ctr@openssh.org",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            32,
            16,
            "Camellia/CTR/NoPadding"),
    // [ Lysator Academic Computer Society ]
    RIJNDAEL_CBC_LYSATOR_LIU_SE( // a.k.a. aes256-cbc
            "rijndael-cbc@lysator.liu.se",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            32,
            16,
            "AES/CBC/NoPadding"),
    // [ SSH.COM ]
    SEED_CBC_SSH_COM(
            "seed-cbc@ssh.com",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            16,
            "SEED/CBC/NoPadding"),
    // [ libassh ]
    SERPENT128_GCM_LIBASSH_ORG(
            "serpent128-gcm@libassh.org",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            16,
            16,
            12,
            16,
            "Serpent/GCM/NoPadding"),
    SERPENT256_GCM_LIBASSH_ORG(
            "serpent256-gcm@libassh.org",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            32,
            16,
            12,
            16,
            "Serpent/GCM/NoPadding"),
    TWOFISH128_GCM_LIBASSH_ORG(
            "twofish128-gcm@libassh.org",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            16,
            16,
            12,
            16,
            "Twofish/GCM/NoPadding"),
    TWOFISH256_GCM_LIBASSH_ORG(
            "twofish256-gcm@libassh.org",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            32,
            16,
            12,
            16,
            "Twofish/GCM/NoPadding"),
    // Algorithms not registered with the IANA
    CAMELLIA128_CBC(
            "camellia128-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            16,
            16,
            "Camellia/CBC/NoPadding"),
    CAMELLIA192_CBC(
            "camellia192-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            24,
            16,
            "Camellia/CBC/NoPadding"),
    CAMELLIA256_CBC(
            "camellia256-cbc",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CBC,
            32,
            16,
            "Camellia/CBC/NoPadding"),
    CAMELLIA128_CTR(
            "camellia128-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            16,
            16,
            "Camellia/CTR/NoPadding"),
    CAMELLIA192_CTR(
            "camellia192-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            24,
            16,
            "Camellia/CTR/NoPadding"),
    CAMELLIA256_CTR(
            "camellia256-ctr",
            EncryptionAlgorithmType.BLOCK,
            EncryptionMode.CTR,
            32,
            16,
            "Camellia/CTR/NoPadding"),
    AEAD_CAMELLIA_128_GCM(
            "AEAD_CAMELLIA_128_GCM",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            16,
            16,
            12,
            16,
            "Camellia/GCM/NoPadding"),
    AEAD_CAMELLIA_256_GCM(
            "AEAD_CAMELLIA_256_GCM",
            EncryptionAlgorithmType.AEAD,
            EncryptionMode.GCM,
            32,
            16,
            12,
            16,
            "Camellia/GCM/NoPadding");

    private final String name;
    private final EncryptionAlgorithmType type;
    private final EncryptionMode mode;
    private final int keySize;
    private final int blockSize;
    private final int ivSize;
    private final int authTagSize;
    private final String javaName;

    EncryptionAlgorithm(
            String name,
            EncryptionAlgorithmType type,
            EncryptionMode mode,
            int keySize,
            int blockSize,
            String javaName) {
        this(name, type, mode, keySize, blockSize, blockSize, 0, javaName);
    }

    EncryptionAlgorithm(
            String name,
            EncryptionAlgorithmType type,
            EncryptionMode mode,
            int keySize,
            int blockSize,
            int ivSize,
            int authTagSize) {
        this(name, type, mode, keySize, blockSize, ivSize, authTagSize, null);
    }

    EncryptionAlgorithm(
            String name,
            EncryptionAlgorithmType type,
            EncryptionMode mode,
            int keySize,
            int blockSize,
            int ivSize,
            int authTagSize,
            String javaName) {
        this.name = name;
        this.type = type;
        this.mode = mode;
        this.keySize = keySize;
        this.blockSize = blockSize;
        this.ivSize = ivSize;
        this.authTagSize = authTagSize;
        this.javaName = javaName;
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

    public int getIVSize() {
        return ivSize;
    }

    public int getAuthTagSize() {
        return authTagSize;
    }

    public EncryptionAlgorithmType getType() {
        return type;
    }

    public EncryptionMode getMode() {
        return mode;
    }

    public String getJavaName() {
        return javaName;
    }

    public int getKeystreamInitialDiscardLength() {
        if (this == EncryptionAlgorithm.ARCFOUR128 || this == EncryptionAlgorithm.ARCFOUR256) {
            // ARCFOUR128 and ARCFOUR256 skip the first 1536 bytes of the RC4 keystream before
            // starting encryption / decryption
            // ref. RFC 4345 Section 4
            return 1536;
        }
        return 0;
    }
}
