/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Map;
import java.util.TreeMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum KeyExchangeAlgorithm {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-
     * parameters-16
     */

    // [ RFC 4419 ]
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1(
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE,
            "diffie-hellman-group-exchange-sha1",
            HashFunction.SHA1),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256(
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE,
            "diffie-hellman-group-exchange-sha256",
            HashFunction.SHA256),
    // [ RFC 4253 ]
    DIFFIE_HELLMAN_GROUP1_SHA1(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group1-sha1", HashFunction.SHA1),
    DIFFIE_HELLMAN_GROUP14_SHA1(
            KeyExchangeFlowType.DIFFIE_HELLMAN, "diffie-hellman-group14-sha1", HashFunction.SHA1),
    // [ RFC 8268 ]
    DIFFIE_HELLMAN_GROUP14_SHA256(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group14-sha256",
            HashFunction.SHA256),
    DIFFIE_HELLMAN_GROUP15_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group15-sha512",
            HashFunction.SHA512),
    DIFFIE_HELLMAN_GROUP16_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group16-sha512",
            HashFunction.SHA512),
    DIFFIE_HELLMAN_GROUP17_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group17-sha512",
            HashFunction.SHA512),
    DIFFIE_HELLMAN_GROUP18_SHA512(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group18-sha512",
            HashFunction.SHA512),
    // [ RFC 5656 ]
    // RFC 5656 defines ecdh-sha2-*, where * is the OID of the curve to use
    // (except for nistp256, nistp384, nistp521)
    ECDH_SHA2_SECP160K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.9", HashFunction.SHA256),
    ECDH_SHA2_SECP160R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.8", HashFunction.SHA256),
    ECDH_SHA2_SECP160R2(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.30", HashFunction.SHA256),
    ECDH_SHA2_SECP192K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.31", HashFunction.SHA256),
    ECDH_SHA2_SECP192R1(
            KeyExchangeFlowType.ECDH, "ecdh-sha2-1.2.840.10045.3.1.1", HashFunction.SHA256),
    ECDH_SHA2_SECP224K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.32", HashFunction.SHA256),
    ECDH_SHA2_SECP224R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.33", HashFunction.SHA256),
    ECDH_SHA2_SECP256K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.10", HashFunction.SHA256),
    ECDH_SHA2_NISTP256(KeyExchangeFlowType.ECDH, "ecdh-sha2-nistp256", HashFunction.SHA256),
    ECDH_SHA2_NISTP384(KeyExchangeFlowType.ECDH, "ecdh-sha2-nistp384", HashFunction.SHA384),
    ECDH_SHA2_NISTP521(KeyExchangeFlowType.ECDH, "ecdh-sha2-nistp521", HashFunction.SHA512),
    ECDH_SHA2_SECT163K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.1", HashFunction.SHA256),
    ECDH_SHA2_SECT163R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.2", HashFunction.SHA256),
    ECDH_SHA2_SECT163R2(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.15", HashFunction.SHA256),
    ECDH_SHA2_SECT193R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.24", HashFunction.SHA256),
    ECDH_SHA2_SECT193R2(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.25", HashFunction.SHA256),
    ECDH_SHA2_SECT233K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.26", HashFunction.SHA256),
    ECDH_SHA2_SECT233R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.27", HashFunction.SHA256),
    ECDH_SHA2_SECT239K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.3", HashFunction.SHA256),
    ECDH_SHA2_SECT283K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.16", HashFunction.SHA384),
    ECDH_SHA2_SECT283R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.17", HashFunction.SHA384),
    ECDH_SHA2_SECT409K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.36", HashFunction.SHA512),
    ECDH_SHA2_SECT409R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.37", HashFunction.SHA512),
    ECDH_SHA2_SECT571K1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.38", HashFunction.SHA512),
    ECDH_SHA2_SECT571R1(KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.132.0.39", HashFunction.SHA512),
    ECDH_SHA2_BRAINPOOLP256R1(
            KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.36.3.3.2.8.1.1.7", HashFunction.SHA256),
    ECDH_SHA2_BRAINPOOLP384R1(
            KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.36.3.3.2.8.1.1.11", HashFunction.SHA384),
    ECDH_SHA2_BRAINPOOLP512R1(
            KeyExchangeFlowType.ECDH, "ecdh-sha2-1.3.36.3.3.2.8.1.1.13", HashFunction.SHA512),
    ECMQV_SHA2(KeyExchangeFlowType.ECMQV, "ecmqv-sha2", null),
    // [ RFC 8732 ]
    // GSS-API key exchange methods would be listed here (gss-*)
    // TODO: Change implementation to support wildcard key exchange method names
    // [ RFC 4432 ]
    RSA1024_SHA1(KeyExchangeFlowType.RSA, "rsa1024-sha1", HashFunction.SHA1),
    RSA2048_SHA256(KeyExchangeFlowType.RSA, "rsa2048-sha256", HashFunction.SHA256),
    // [ RFC 8308 ]
    EXT_INFO_S(null, "ext-info-s", null),
    EXT_INFO_C(null, "ext-info-c", null),
    // [ RFC 8731 ]
    CURVE25519_SHA256(KeyExchangeFlowType.ECDH, "curve25519-sha256", HashFunction.SHA256),
    CURVE448_SHA512(KeyExchangeFlowType.ECDH, "curve448-sha512", HashFunction.SHA512),
    // [ draft-josefsson-ntruprime-ssh-02 ]
    SNTRUP761X25519_SHA512(
            KeyExchangeFlowType.HYBRID, "sntrup761x25519-sha512", HashFunction.SHA512),
    // [ draft-kampanakis-curdle-ssh-pq-ke-04 ]
    MLKEM768NISTP256_SHA256(
            KeyExchangeFlowType.HYBRID, "mlkem768nistp256-sha256", HashFunction.SHA256),
    MLKEM1024NISTP384_SHA384(
            KeyExchangeFlowType.HYBRID, "mlkem1024nistp384-sha384", HashFunction.SHA384),
    MLKEM768X25519_SHA256(KeyExchangeFlowType.HYBRID, "mlkem768x25519-sha256", HashFunction.SHA256),
    // Vendor extensions
    // [ LibSSH ]
    CURVE25519_SHA256_LIBSSH_ORG(
            KeyExchangeFlowType.ECDH, "curve25519-sha256@libssh.org", HashFunction.SHA256),
    // [ OpenSSH ]
    SNTRUP761X25519_SHA512_OPENSSH_COM(
            KeyExchangeFlowType.HYBRID, "sntrup761x25519-sha512@openssh.com", HashFunction.SHA512),
    KEX_STRICT_S_V00_OPENSSH_COM(null, "kex-strict-s-v00@openssh.com", null),
    KEX_STRICT_C_V00_OPENSSH_COM(null, "kex-strict-c-v00@openssh.com", null),
    // [ TinySSH ]
    SNTRUP4591761X25519_SHA512_TINYSSH_ORG(
            KeyExchangeFlowType.HYBRID,
            "sntrup4591761x25519-sha512@tinyssh.org",
            HashFunction.SHA512),
    // [ SSH.COM ]
    CURVE25519_FRODOKEM1344_SHA512_SSH_COM(
            KeyExchangeFlowType.HYBRID,
            "curve25519-frodokem1344-sha512@ssh.com",
            HashFunction.SHA512),
    ECDH_NISTP521_KYBER1024_SHA512_SSH_COM(
            KeyExchangeFlowType.HYBRID,
            "ecdh-nistp521-kyber1024-sha512@ssh.com",
            HashFunction.SHA512),
    ECDH_NISTP521_FIRESABER_SHA512_SSH_COM(
            KeyExchangeFlowType.HYBRID,
            "ecdh-nistp521-firesaber-sha512@ssh.com",
            HashFunction.SHA512),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA224_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE,
            "diffie-hellman-group-exchange-sha224@ssh.com",
            HashFunction.SHA224),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA384_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE,
            "diffie-hellman-group-exchange-sha384@ssh.com",
            HashFunction.SHA384),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA512_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE,
            "diffie-hellman-group-exchange-sha512@ssh.com",
            HashFunction.SHA512),
    DIFFIE_HELLMAN_GROUP14_SHA224_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group14-sha224@ssh.com",
            HashFunction.SHA224),
    DIFFIE_HELLMAN_GROUP14_SHA256_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group14-sha256@ssh.com",
            HashFunction.SHA256),
    DIFFIE_HELLMAN_GROUP15_SHA256_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group15-sha256@ssh.com",
            HashFunction.SHA256),
    DIFFIE_HELLMAN_GROUP15_SHA384_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group15-sha384@ssh.com",
            HashFunction.SHA384),
    DIFFIE_HELLMAN_GROUP16_SHA384_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group16-sha384@ssh.com",
            HashFunction.SHA384),
    DIFFIE_HELLMAN_GROUP16_SHA512_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group16-sha512@ssh.com",
            HashFunction.SHA512),
    DIFFIE_HELLMAN_GROUP18_SHA512_SSH_COM(
            KeyExchangeFlowType.DIFFIE_HELLMAN,
            "diffie-hellman-group18-sha512@ssh.com",
            HashFunction.SHA512),
    UNKNOWN(null, null, null);

    private static final Logger LOGGER = LogManager.getLogger();

    private final String name;
    private final HashFunction hashFunction;
    private final KeyExchangeFlowType flowType;

    private static final Map<String, KeyExchangeAlgorithm> map;

    static {
        map = new TreeMap<>();
        for (KeyExchangeAlgorithm algorithm : values()) {
            if (algorithm.name != null) {
                map.put(algorithm.name, algorithm);
            }
        }
    }

    KeyExchangeAlgorithm(KeyExchangeFlowType flowType, String name, HashFunction hashFunction) {
        this.flowType = flowType;
        this.name = name;
        this.hashFunction = hashFunction;
    }

    @Override
    public String toString() {
        return name;
    }

    public HashFunction getHashFunction() {
        return hashFunction;
    }

    public KeyExchangeFlowType getFlowType() {
        return flowType;
    }

    public static KeyExchangeAlgorithm fromName(String name) {
        KeyExchangeAlgorithm result = map.get(name);
        if (result != null) {
            return result;
        }
        return UNKNOWN;
    }
}
