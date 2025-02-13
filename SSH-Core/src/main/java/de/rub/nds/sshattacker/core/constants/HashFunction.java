/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum HashFunction {
    SHA1(160, "SHA-1"),
    SHA224(224, "SHA-224"),
    SHA256(256, "SHA-256"),
    SHA384(384, "SHA-384"),
    SHA512(512, "SHA-512");

    private final int outputSize;
    private final String javaName;

    HashFunction(int outputSize, String javaName) {
        this.outputSize = outputSize;
        this.javaName = javaName;
    }

    public int getOutputSize() {
        return outputSize;
    }

    public String getJavaName() {
        return javaName;
    }
}
