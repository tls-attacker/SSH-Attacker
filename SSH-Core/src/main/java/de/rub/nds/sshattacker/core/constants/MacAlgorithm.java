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
    HMAC_MD5("hmac-md5", 16, 16),
    HMAC_MD5_96("hmac-md5-96", 12, 12),
    HMAC_SHA1("hmac-sha1", 20, 20),
    HMAC_SHA1_96("hmac-sha1-96", 12, 12),
    HMAC_SHA2_256("hmac-sha2-256", 32, 32),
    HMAC_SHA2_512("hmac-sha2-512", 64, 64),
    UMAC_64_OPENSSH_COM("umac-64@openssh.com", 16, 8),
    UMAC_128_OPENSSH_COM("umac-128@openssh.com", 16, 16),
    HMAC_MD5_ETM_OPENSSH_COM("hmac-md5-etm@openssh.com", 16, 16),
    HMAC_MD5_96_ETM_OPENSSH_COM("hmac-md5-96-etm@openssh.com", 12, 12),
    HMAC_SHA1_ETM_OPENSSH_COM("hmac-sha1-etm@openssh.com", 20, 20),
    HMAC_SHA1_96_ETM_OPENSSH_COM("hmac-sha1-96-etm@openssh.com", 12, 12),
    HMAC_SHA2_256_ETM_OPENSSH_COM("hmac-sha2-256-etm@openssh.com", 32, 32),
    HMAC_SHA2_512_ETM_OPENSSH_COM("hmac-sha2-512-etm@openssh.com", 64, 64),
    UMAC_64_ETM_OPENSSH_COM("umac-64-etm@openssh.com", 16, 8),
    UMAC_128_ETM_OPENSSH_COM("umac-128-etm@openssh.com", 16, 16);

    private final String name;
    private final int keySize;
    private final int outputSize;

    MacAlgorithm(String name, int keySize, int outputSize) {
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
