/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum MacAlgorithm {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-18
     *  - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     */
    // [ RFC 4253 ]
    HMAC_SHA1("hmac-sha1", 20, 20),
    HMAC_SHA1_96("hmac-sha1-96", 20, 12),
    HMAC_MD5("hmac-md5", 16, 16),
    HMAC_MD5_96("hmac-md5-96", 16, 12),
    NONE("none", 0, 0),
    // [ RFC 5647 ]
    AEAD_AES128_GCM("AEAD_AES_128_GCM", 16, 16),
    AEAD_AES256_GCM("AEAD_AES_256_GCM", 32, 16),
    // [ RFC 6668 ]
    HMAC_SHA2_256("hmac-sha2-256", 32, 32),
    HMAC_SHA2_512("hmac-sha2-512", 64, 64),
    // Vendor extensions
    // [ OpenSSH ]
    UMAC_32_OPENSSH_COM("umac-32@openssh.com", 16, 4),
    UMAC_64_OPENSSH_COM("umac-64@openssh.com", 16, 8),
    UMAC_96_OPENSSH_COM("umac-96@openssh.com", 16, 12),
    UMAC_128_OPENSSH_COM("umac-128@openssh.com", 16, 16),
    HMAC_SHA1_ETM_OPENSSH_COM("hmac-sha1-etm@openssh.com", 20, 20, true),
    HMAC_SHA1_96_ETM_OPENSSH_COM("hmac-sha1-96-etm@openssh.com", 20, 12, true),
    HMAC_MD5_ETM_OPENSSH_COM("hmac-md5-etm@openssh.com", 16, 16, true),
    HMAC_MD5_96_ETM_OPENSSH_COM("hmac-md5-96-etm@openssh.com", 16, 12, true),
    HMAC_SHA2_256_ETM_OPENSSH_COM("hmac-sha2-256-etm@openssh.com", 32, 32, true),
    HMAC_SHA2_512_ETM_OPENSSH_COM("hmac-sha2-512-etm@openssh.com", 64, 64, true),
    UMAC_32_ETM_OPENSSH_COM("umac-32-etm@openssh.com", 16, 4, true),
    UMAC_64_ETM_OPENSSH_COM("umac-64-etm@openssh.com", 16, 8, true),
    UMAC_96_ETM_OPENSSH_COM("umac-96-etm@openssh.com", 16, 12, true),
    UMAC_128_ETM_OPENSSH_COM("umac-128-etm@openssh.com", 16, 16, true);

    private final String name;
    private final int keySize;
    private final int outputSize;
    private final boolean isETM;

    MacAlgorithm(String name, int keySize, int outputSize) {
        this(name, keySize, outputSize, false);
    }

    MacAlgorithm(String name, int keySize, int outputSize, boolean isETM) {
        this.name = name;
        this.keySize = keySize;
        this.outputSize = outputSize;
        this.isETM = isETM;
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

    public boolean isEncryptThenMacAlgorithm() {
        return isETM;
    }
}
