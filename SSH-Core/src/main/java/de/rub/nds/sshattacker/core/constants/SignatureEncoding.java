/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SignatureEncoding {
    // [ RFC 4253 ]
    SSH_DSS("ssh-dss"),
    SSH_RSA("ssh-rsa"),
    // [ RFC 8332 ]
    RSA_SHA2_256("rsa-sha2-256"),
    RSA_SHA2_512("rsa-sha2-512");

    private final String name;

    SignatureEncoding(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }
}
