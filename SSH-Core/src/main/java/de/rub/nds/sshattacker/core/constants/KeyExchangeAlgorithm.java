/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum KeyExchangeAlgorithm {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-16
     */
    // [ RFC 4419 ]
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1(
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE,
            "diffie-hellman-group-exchange-sha1",
            "SHA-1"),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256(
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE,
            "diffie-hellman-group-exchange-sha256",
            "SHA-256"),
    // [ RFC 4253 ]
    DIFFIE_HELLMAN_GROUP1_SHA1(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group1-sha1", "SHA-1"),
    DIFFIE_HELLMAN_GROUP14_SHA1(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group14-sha1", "SHA-1"),
    // [ RFC 8268 ]
    DIFFIE_HELLMAN_GROUP14_SHA256(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group14-sha256", "SHA-256"),
    DIFFIE_HELLMAN_GROUP15_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group15-sha512", "SHA-512"),
    DIFFIE_HELLMAN_GROUP16_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group16-sha512", "SHA-512"),
    DIFFIE_HELLMAN_GROUP17_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group17-sha512", "SHA-512"),
    DIFFIE_HELLMAN_GROUP18_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group18-sha512", "SHA-512"),
    // [ RFC 5656 ]
    // RFC 5656 defines ecdh-sha2-*, where * is the OID of the curve to use
    // (except for nistp256, nistp384, nistp521)
    ECDH_SHA2_SECP160K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.9", "SHA-256"),
    ECDH_SHA2_SECP160R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.8", "SHA-256"),
    ECDH_SHA2_SECP160R2(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.30", "SHA-256"),
    ECDH_SHA2_SECP192K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.31", "SHA-256"),
    ECDH_SHA2_SECP192R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.2.840.10045.3.1.1", "SHA-256"),
    ECDH_SHA2_SECP224K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.32", "SHA-256"),
    ECDH_SHA2_SECP224R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.33", "SHA-256"),
    ECDH_SHA2_SECP256K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.10", "SHA-256"),
    ECDH_SHA2_NISTP256(KeyExchangeFlowType.ECDH, "ecdh-sha2-nistp256", "SHA-256"),
    ECDH_SHA2_NISTP384(KeyExchangeFlowType.ECDH, "ecdh-sha2-nistp384", "SHA-384"),
    ECDH_SHA2_NISTP521(KeyExchangeFlowType.ECDH, "ecdh-sha2-nistp521", "SHA-512"),
    ECDH_SHA2_SECT163K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.1", "SHA-256"),
    ECDH_SHA2_SECT163R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.2", "SHA-256"),
    ECDH_SHA2_SECT163R2(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.15", "SHA-256"),
    ECDH_SHA2_SECT193R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.24", "SHA-256"),
    ECDH_SHA2_SECT193R2(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.25", "SHA-256"),
    ECDH_SHA2_SECT233K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.26", "SHA-256"),
    ECDH_SHA2_SECT233R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.27", "SHA-256"),
    ECDH_SHA2_SECT239K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.3", "SHA-256"),
    ECDH_SHA2_SECT283K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.16", "SHA-384"),
    ECDH_SHA2_SECT283R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.17", "SHA-384"),
    ECDH_SHA2_SECT409K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.36", "SHA-512"),
    ECDH_SHA2_SECT409R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.37", "SHA-512"),
    ECDH_SHA2_SECT571K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.38", "SHA-512"),
    ECDH_SHA2_SECT571R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.39", "SHA-512"),
    ECDH_SHA2_BRAINPOOLP256R1(
            KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.36.3.3.2.8.1.1.7", "SHA-256"),
    ECDH_SHA2_BRAINPOOLP384R1(
            KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.36.3.3.2.8.1.1.11", "SHA-384"),
    ECDH_SHA2_BRAINPOOLP512R1(
            KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.36.3.3.2.8.1.1.13", "SHA-512"),
    ECMQV_SHA2(KeyExchangeFlowType.ECMQV, "ecmqv-sha2", null),
    // [ RFC 8732 ]
    // GSS-API key exchange methods would be listed here (gss-*)
    // TODO: Change implementation to support wildcard key exchange method names
    // [ RFC 4432 ]
    RSA1024_SHA1(KeyExchangeFlowType.RSA, "rsa1024-sha1", "SHA-1"),
    RSA2048_SHA256(KeyExchangeFlowType.RSA, "rsa2048-sha256", "SHA-256"),
    // [ RFC 8308 ]
    EXT_INFO_S(null, "ext-info-s", null),
    EXT_INFO_C(null, "ext-info-c", null),
    // [ RFC 8731 ]
    CURVE25519_SHA256(KeyExchangeFlowType.ECDH, "curve25519-sha256", "SHA-256"),
    CURVE448_SHA512(KeyExchangeFlowType.ECDH, "curve448-sha512", "SHA-512"),
    // Vendor extensions
    // [ LibSSH ]
    CURVE25519_SHA256_LIBSSH_ORG(
            KeyExchangeFlowType.ECDH, "curve25519-sha256@libssh.org", "SHA-256");

    private final String name;
    private final String digest;
    private final KeyExchangeFlowType flowType;

    KeyExchangeAlgorithm(KeyExchangeFlowType flowType, String name, String digest) {
        this.name = name;
        this.digest = digest;
        this.flowType = flowType;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getDigest() {
        return digest;
    }

    public KeyExchangeFlowType getFlowType() {
        return flowType;
    }
}
