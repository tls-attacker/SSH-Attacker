/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum CompressionMethod {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-20
     *  - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     */
    // [ RFC 4253 ]
    NONE("none", CompressionAlgorithm.NONE),
    ZLIB("zlib", CompressionAlgorithm.DEFLATE),
    // Vendor extensions
    // [ OpenSSH ]
    ZLIB_OPENSSH_COM("zlib@openssh.com", CompressionAlgorithm.DEFLATE);

    private final String name;
    private final CompressionAlgorithm algorithm;

    CompressionMethod(String name, CompressionAlgorithm algorithm) {
        this.name = name;
        this.algorithm = algorithm;
    }

    public String getName() {
        return name;
    }

    public CompressionAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public String toString() {
        return name;
    }
}
