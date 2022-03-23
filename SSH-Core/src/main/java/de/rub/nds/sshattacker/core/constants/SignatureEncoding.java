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
    RSA_SHA2_512("rsa-sha2-512"),
    // [ RFC 5656 ]
    ECDSA_SHA2_SECP160K1("ecdsa-sha2-1.3.132.0.9"),
    ECDSA_SHA2_SECP160R1("ecdsa-sha2-1.3.132.0.8"),
    ECDSA_SHA2_SECP160R2("ecdsa-sha2-1.3.132.0.30"),
    ECDSA_SHA2_SECP192K1("ecdsa-sha2-1.3.132.0.31"),
    ECDSA_SHA2_SECP192R1("ecdsa-sha2-1.2.840.10045.3.1.1"),
    ECDSA_SHA2_SECP224K1("ecdsa-sha2-1.3.132.0.32"),
    ECDSA_SHA2_SECP224R1("ecdsa-sha2-1.3.132.0.33"),
    ECDSA_SHA2_SECP256K1("ecdsa-sha2-1.3.132.0.10"),
    ECDSA_SHA2_NISTP256("ecdsa-sha2-nistp256"),
    ECDSA_SHA2_NISTP384("ecdsa-sha2-nistp384"),
    ECDSA_SHA2_NISTP521("ecdsa-sha2-nistp521"),
    ECDSA_SHA2_SECT163K1("ecdsa-sha2-1.3.132.0.1"),
    ECDSA_SHA2_SECT163R1("ecdsa-sha2-1.3.132.0.2"),
    ECDSA_SHA2_SECT163R2("ecdsa-sha2-1.3.132.0.15"),
    ECDSA_SHA2_SECT193R1("ecdsa-sha2-1.3.132.0.24"),
    ECDSA_SHA2_SECT193R2("ecdsa-sha2-1.3.132.0.25"),
    ECDSA_SHA2_SECT233K1("ecdsa-sha2-1.3.132.0.26"),
    ECDSA_SHA2_SECT233R1("ecdsa-sha2-1.3.132.0.27"),
    ECDSA_SHA2_SECT239K1("ecdsa-sha2-1.3.132.0.3"),
    ECDSA_SHA2_SECT283K1("ecdsa-sha2-1.3.132.0.16"),
    ECDSA_SHA2_SECT283R1("ecdsa-sha2-1.3.132.0.17"),
    ECDSA_SHA2_SECT409K1("ecdsa-sha2-1.3.132.0.36"),
    ECDSA_SHA2_SECT409R1("ecdsa-sha2-1.3.132.0.37"),
    ECDSA_SHA2_SECT571K1("ecdsa-sha2-1.3.132.0.38"),
    ECDSA_SHA2_SECT571R1("ecdsa-sha2-1.3.132.0.39"),
    ECDSA_SHA2_BRAINPOOL_P256R1("ecdsa-sha2-1.3.36.3.3.2.8.1.1.7"),
    ECDSA_SHA2_BRAINPOOL_P384R1("ecdsa-sha2-1.3.36.3.3.2.8.1.1.11"),
    ECDSA_SHA2_BRAINPOOL_P512R1("ecdsa-sha2-1.3.36.3.3.2.8.1.1.13"),
    // [ RFC 8709 ]
    SSH_ED25519("ssh-ed25519"),
    SSH_ED448("ssh-ed448");

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
