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

public enum KeyExchangeAlgorithm {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-16
     */
    // [ RFC 4419 ]
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1("diffie-hellman-group-exchange-sha1"),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256("diffie-hellman-group-exchange-sha256"),
    // [ RFC 4253 ]
    DIFFIE_HELLMAN_GROUP1_SHA1("diffie-hellman-group1-sha1"),
    DIFFIE_HELLMAN_GROUP14_SHA1("diffie-hellman-group14-sha1"),
    // [ RFC 8268 ]
    DIFFIE_HELLMAN_GROUP14_SHA256("diffie-hellman-group14-sha256"),
    DIFFIE_HELLMAN_GROUP15_SHA512("diffie-hellman-group15-sha512"),
    DIFFIE_HELLMAN_GROUP16_SHA512("diffie-hellman-group16-sha512"),
    DIFFIE_HELLMAN_GROUP17_SHA512("diffie-hellman-group17-sha512"),
    DIFFIE_HELLMAN_GROUP18_SHA512("diffie-hellman-group18-sha512"),
    // [ RFC 5656 ]
    // RFC 5656 defines ecdh-sha2-*, where * is the OID of the curve to use
    // (except for nistp256, nistp384, nistp521)
    ECDH_SHA2_SECP160K1("ecdh-sha2-1.3.132.0.9"),
    ECDH_SHA2_SECP160R1("ecdh-sha2-1.3.132.0.8"),
    ECDH_SHA2_SECP160R2("ecdh-sha2-1.3.132.0.30"),
    ECDH_SHA2_SECP192K1("ecdh-sha2-1.3.132.0.31"),
    ECDH_SHA2_SECP192R1("ecdh-sha2-1.2.840.10045.3.1.1"),
    ECDH_SHA2_SECP224K1("ecdh-sha2-1.3.132.0.32"),
    ECDH_SHA2_SECP224R1("ecdh-sha2-1.3.132.0.33"),
    ECDH_SHA2_SECP256K1("ecdh-sha2-1.3.132.0.10"),
    ECDH_SHA2_NISTP256("ecdh-sha2-nistp256"),
    ECDH_SHA2_NISTP384("ecdh-sha2-nistp384"),
    ECDH_SHA2_NISTP521("ecdh-sha2-nistp521"),
    ECDH_SHA2_SECT163K1("ecdh-sha2-1.3.132.0.1"),
    ECDH_SHA2_SECT163R1("ecdh-sha2-1.3.132.0.2"),
    ECDH_SHA2_SECT163R2("ecdh-sha2-1.3.132.0.15"),
    ECDH_SHA2_SECT193R1("ecdh-sha2-1.3.132.0.24"),
    ECDH_SHA2_SECT193R2("ecdh-sha2-1.3.132.0.25"),
    ECDH_SHA2_SECT233K1("ecdh-sha2-1.3.132.0.26"),
    ECDH_SHA2_SECT233R1("ecdh-sha2-1.3.132.0.27"),
    ECDH_SHA2_SECT239K1("ecdh-sha2-1.3.132.0.3"),
    ECDH_SHA2_SECT283K1("ecdh-sha2-1.3.132.0.16"),
    ECDH_SHA2_SECT283R1("ecdh-sha2-1.3.132.0.17"),
    ECDH_SHA2_SECT409K1("ecdh-sha2-1.3.132.0.36"),
    ECDH_SHA2_SECT409R1("ecdh-sha2-1.3.132.0.37"),
    ECDH_SHA2_SECT571K1("ecdh-sha2-1.3.132.0.38"),
    ECDH_SHA2_SECT571R1("ecdh-sha2-1.3.132.0.39"),
    ECDH_SHA2_BRAINPOOL_P256R1("ecdh-sha2-1.3.36.3.3.2.8.1.1.7"),
    ECDH_SHA2_BRAINPOOL_P384R1("ecdh-sha2-1.3.36.3.3.2.8.1.1.11"),
    ECDH_SHA2_BRAINPOOL_P512R1("ecdh-sha2-1.3.36.3.3.2.8.1.1.13"),
    ECMQV_SHA2("ecmqv-sha2"),
    // [ RFC 8732 ]
    // GSS-API key exchange methods would be listed here (gss-*)
    // TODO: Change implementation to support wildcard key exchange method names
    // [ RFC 4432 ]
    RSA1024_SHA1("rsa1024-sha1"),
    RSA2048_SHA256("rsa2048-sha256"),
    // [ RFC 8308 ]
    EXT_INFO_S("ext-info-s"),
    EXT_INFO_C("ext-info-c"),
    // [ RFC 8731 ]
    CURVE25519_SHA256("curve25519-sha256"),
    CURVE448_SHA512("curve448-sha512"),
    // Vendor extensions
    // [ LibSSH ]
    CURVE25519_SHA256_LIBSSH_ORG("curve25519-sha256@libssh.org");

    private final String name;

    KeyExchangeAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

}
