/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

public enum SignatureAlgorithm {

    /*
     * Source for Java Signature Algorithms
     * https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html#signature-algorithms
     */
    SSH_RSA("ssh-rsa", "SHA1WithRSA"),
    RSA_SHA2_256("rsa-sha2-256", "SHA256WithRSA"),
    RSA_SHA2_512("rsa-sha2-512", "SHA512WithRSA"),
    UNKNOWN("UNKNOWN", "UNKNOWN");

    private final String name;
    private final String javaName;

    SignatureAlgorithm(String name, String javaName) {
        this.name = name;
        this.javaName = javaName;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public String getJavaName() {
        return javaName;
    }

    /**
     * Tries to convert a String to a SignatureAlgorithm
     *
     * @param name String to be converted to SignatureAlgorithm
     * @return Corresponding SignatureAlgorithm or UNKNOWN if none was found
     */
    public static SignatureAlgorithm getSignatureAlgorithm(String name) {
        for (SignatureAlgorithm signatureAlgorithm : values()) {
            if (signatureAlgorithm.getName().equalsIgnoreCase(name)) {
                return signatureAlgorithm;
            }
        }
        return UNKNOWN;
    }
}
