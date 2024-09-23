/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * These values are also used for PubkeyAcceptedKeyTypes HostbasedAcceptedKeyTypes HostKeyAlgorithms
 */
public enum PublicKeyAlgorithm {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
     */
    // [ RFC 4253 ]
    SSH_DSS("ssh-dss", PublicKeyFormat.SSH_DSS, SignatureEncoding.SSH_DSS, "SHA1WithDSA"),
    SSH_RSA("ssh-rsa", PublicKeyFormat.SSH_RSA, SignatureEncoding.SSH_RSA, "SHA1WithRSA"),
    SPKI_SIGN_RSA("spki-sign-rsa", PublicKeyFormat.SPKI_SIGN_RSA, SignatureEncoding.SSH_RSA),
    SPKI_SIGN_DSS("spki-sign-dss", PublicKeyFormat.SPKI_SIGN_DSS, SignatureEncoding.SSH_DSS),
    PGP_SIGN_RSA("pgp-sign-rsa", PublicKeyFormat.PGP_SIGN_RSA, SignatureEncoding.SSH_RSA),
    PGP_SIGN_DSS("pgp-sign-dss", PublicKeyFormat.PGP_SIGN_DSS, SignatureEncoding.SSH_DSS),
    // [ RFC 8332 ]
    RSA_SHA2_256(
            "rsa-sha2-256",
            PublicKeyFormat.SSH_RSA,
            SignatureEncoding.RSA_SHA2_256,
            "SHA256WithRSA"),
    RSA_SHA2_512(
            "rsa-sha2-512",
            PublicKeyFormat.SSH_RSA,
            SignatureEncoding.RSA_SHA2_512,
            "SHA512WithRSA"),
    // [ RFC 4462 ]
    NULL("null", PublicKeyFormat.NULL),
    // [ RFC 5656 ]
    ECDSA_SHA2_SECP160K1(
            "ecdsa-sha2-1.3.132.0.9",
            PublicKeyFormat.ECDSA_SHA2_SECP160K1,
            SignatureEncoding.ECDSA_SHA2_SECP160K1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECP160R1(
            "ecdsa-sha2-1.3.132.0.8",
            PublicKeyFormat.ECDSA_SHA2_SECP160R1,
            SignatureEncoding.ECDSA_SHA2_SECP160R1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECP160R2(
            "ecdsa-sha2-1.3.132.0.30",
            PublicKeyFormat.ECDSA_SHA2_SECP160R2,
            SignatureEncoding.ECDSA_SHA2_SECP160R2,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECP192K1(
            "ecdsa-sha2-1.3.132.0.31",
            PublicKeyFormat.ECDSA_SHA2_SECP192K1,
            SignatureEncoding.ECDSA_SHA2_SECP192K1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECP192R1(
            "ecdsa-sha2-1.2.840.10045.3.1.1",
            PublicKeyFormat.ECDSA_SHA2_SECP192R1,
            SignatureEncoding.ECDSA_SHA2_SECP192R1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECP224K1(
            "ecdsa-sha2-1.3.132.0.32",
            PublicKeyFormat.ECDSA_SHA2_SECP224K1,
            SignatureEncoding.ECDSA_SHA2_SECP224K1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECP224R1(
            "ecdsa-sha2-1.3.132.0.33",
            PublicKeyFormat.ECDSA_SHA2_SECP224R1,
            SignatureEncoding.ECDSA_SHA2_SECP224R1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECP256K1(
            "ecdsa-sha2-1.3.132.0.10",
            PublicKeyFormat.ECDSA_SHA2_SECP256K1,
            SignatureEncoding.ECDSA_SHA2_SECP256K1,
            "SHA256withECDSA"),
    ECDSA_SHA2_NISTP256(
            "ecdsa-sha2-nistp256",
            PublicKeyFormat.ECDSA_SHA2_NISTP256,
            SignatureEncoding.ECDSA_SHA2_NISTP256,
            "SHA256withECDSA"),
    ECDSA_SHA2_NISTP384(
            "ecdsa-sha2-nistp384",
            PublicKeyFormat.ECDSA_SHA2_NISTP384,
            SignatureEncoding.ECDSA_SHA2_NISTP384,
            "SHA384withECDSA"),
    ECDSA_SHA2_NISTP521(
            "ecdsa-sha2-nistp521",
            PublicKeyFormat.ECDSA_SHA2_NISTP521,
            SignatureEncoding.ECDSA_SHA2_NISTP521,
            "SHA512withECDSA"),
    ECDSA_SHA2_SECT163K1(
            "ecdsa-sha2-1.3.132.0.1",
            PublicKeyFormat.ECDSA_SHA2_SECT163K1,
            SignatureEncoding.ECDSA_SHA2_SECT163K1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT163R1(
            "ecdsa-sha2-1.3.132.0.2",
            PublicKeyFormat.ECDSA_SHA2_SECT163R1,
            SignatureEncoding.ECDSA_SHA2_SECT163R1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT163R2(
            "ecdsa-sha2-1.3.132.0.15",
            PublicKeyFormat.ECDSA_SHA2_SECT163R2,
            SignatureEncoding.ECDSA_SHA2_SECT163R2,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT193R1(
            "ecdsa-sha2-1.3.132.0.24",
            PublicKeyFormat.ECDSA_SHA2_SECT193R1,
            SignatureEncoding.ECDSA_SHA2_SECT193R1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT193R2(
            "ecdsa-sha2-1.3.132.0.25",
            PublicKeyFormat.ECDSA_SHA2_SECT193R2,
            SignatureEncoding.ECDSA_SHA2_SECT193R2,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT233K1(
            "ecdsa-sha2-1.3.132.0.26",
            PublicKeyFormat.ECDSA_SHA2_SECT233K1,
            SignatureEncoding.ECDSA_SHA2_SECT233K1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT233R1(
            "ecdsa-sha2-1.3.132.0.27",
            PublicKeyFormat.ECDSA_SHA2_SECT233R1,
            SignatureEncoding.ECDSA_SHA2_SECT233R1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT239K1(
            "ecdsa-sha2-1.3.132.0.3",
            PublicKeyFormat.ECDSA_SHA2_SECT239K1,
            SignatureEncoding.ECDSA_SHA2_SECT239K1,
            "SHA256withECDSA"),
    ECDSA_SHA2_SECT283K1(
            "ecdsa-sha2-1.3.132.0.16",
            PublicKeyFormat.ECDSA_SHA2_SECT283K1,
            SignatureEncoding.ECDSA_SHA2_SECT283K1,
            "SHA384withECDSA"),
    ECDSA_SHA2_SECT283R1(
            "ecdsa-sha2-1.3.132.0.17",
            PublicKeyFormat.ECDSA_SHA2_SECT283R1,
            SignatureEncoding.ECDSA_SHA2_SECT283R1,
            "SHA384withECDSA"),
    ECDSA_SHA2_SECT409K1(
            "ecdsa-sha2-1.3.132.0.36",
            PublicKeyFormat.ECDSA_SHA2_SECT409K1,
            SignatureEncoding.ECDSA_SHA2_SECT409K1,
            "SHA512withECDSA"),
    ECDSA_SHA2_SECT409R1(
            "ecdsa-sha2-1.3.132.0.37",
            PublicKeyFormat.ECDSA_SHA2_SECT409R1,
            SignatureEncoding.ECDSA_SHA2_SECT409R1,
            "SHA512withECDSA"),
    ECDSA_SHA2_SECT571K1(
            "ecdsa-sha2-1.3.132.0.38",
            PublicKeyFormat.ECDSA_SHA2_SECT571K1,
            SignatureEncoding.ECDSA_SHA2_SECT571K1,
            "SHA512withECDSA"),
    ECDSA_SHA2_SECT571R1(
            "ecdsa-sha2-1.3.132.0.39",
            PublicKeyFormat.ECDSA_SHA2_SECT571R1,
            SignatureEncoding.ECDSA_SHA2_SECT571R1,
            "SHA512withECDSA"),
    ECDSA_SHA2_BRAINPOOL_P256R1(
            "ecdsa-sha2-1.3.36.3.3.2.8.1.1.7",
            PublicKeyFormat.ECDSA_SHA2_BRAINPOOL_P256R1,
            SignatureEncoding.ECDSA_SHA2_BRAINPOOL_P256R1,
            "SHA256withECDSA"),
    ECDSA_SHA2_BRAINPOOL_P384R1(
            "ecdsa-sha2-1.3.36.3.3.2.8.1.1.11",
            PublicKeyFormat.ECDSA_SHA2_BRAINPOOL_P384R1,
            SignatureEncoding.ECDSA_SHA2_BRAINPOOL_P384R1,
            "SHA384withECDSA"),
    ECDSA_SHA2_BRAINPOOL_P512R1(
            "ecdsa-sha2-1.3.36.3.3.2.8.1.1.13",
            PublicKeyFormat.ECDSA_SHA2_BRAINPOOL_P512R1,
            SignatureEncoding.ECDSA_SHA2_BRAINPOOL_P512R1,
            "SHA512withECDSA"),
    // [ RFC 6187 ]
    X509V3_SSH_DSS("x509v3-ssh-dss", PublicKeyFormat.X509V3_SSH_DSS),
    X509V3_SSH_RSA("x509v3-ssh-rsa", PublicKeyFormat.X509V3_SSH_RSA),
    X509V3_RSA2048_SHA256("x509v3-rsa2048-sha256", PublicKeyFormat.X509V3_RSA2048_SHA256),
    X509V3_ECDSA_SHA2_SECP160K1(
            "x509v3-ecdsa-sha2-1.3.132.0.9", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP160K1),
    X509V3_ECDSA_SHA2_SECP160R1(
            "x509v3-ecdsa-sha2-1.3.132.0.8", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP160R1),
    X509V3_ECDSA_SHA2_SECP160R2(
            "x509v3-ecdsa-sha2-1.3.132.0.30", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP160R2),
    X509V3_ECDSA_SHA2_SECP192K1(
            "x509v3-ecdsa-sha2-1.3.132.0.31", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP192K1),
    X509V3_ECDSA_SHA2_SECP192R1(
            "x509v3-ecdsa-sha2-1.2.840.10045.3.1.1", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP192R1),
    X509V3_ECDSA_SHA2_SECP224K1(
            "x509v3-ecdsa-sha2-1.3.132.0.32", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP224K1),
    X509V3_ECDSA_SHA2_SECP224R1(
            "x509v3-ecdsa-sha2-1.3.132.0.33", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP224R1),
    X509V3_ECDSA_SHA2_SECP256K1(
            "x509v3-ecdsa-sha2-1.3.132.0.10", PublicKeyFormat.X509V3_ECDSA_SHA2_SECP256K1),
    X509V3_ECDSA_SHA2_NISTP256(
            "x509v3-ecdsa-sha2-nistp256", PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP256),
    X509V3_ECDSA_SHA2_NISTP384(
            "x509v3-ecdsa-sha2-nistp384", PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP384),
    X509V3_ECDSA_SHA2_NISTP521(
            "x509v3-ecdsa-sha2-nistp521", PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP521),
    X509V3_ECDSA_SHA2_SECT163K1(
            "x509v3-ecdsa-sha2-1.3.132.0.1", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT163K1),
    X509V3_ECDSA_SHA2_SECT163R1(
            "x509v3-ecdsa-sha2-1.3.132.0.2", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT163R1),
    X509V3_ECDSA_SHA2_SECT163R2(
            "x509v3-ecdsa-sha2-1.3.132.0.15", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT163R2),
    X509V3_ECDSA_SHA2_SECT193R1(
            "x509v3-ecdsa-sha2-1.3.132.0.24", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT193R1),
    X509V3_ECDSA_SHA2_SECT193R2(
            "x509v3-ecdsa-sha2-1.3.132.0.25", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT193R2),
    X509V3_ECDSA_SHA2_SECT233K1(
            "x509v3-ecdsa-sha2-1.3.132.0.26", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT233K1),
    X509V3_ECDSA_SHA2_SECT233R1(
            "x509v3-ecdsa-sha2-1.3.132.0.27", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT233R1),
    X509V3_ECDSA_SHA2_SECT239K1(
            "x509v3-ecdsa-sha2-1.3.132.0.3", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT239K1),
    X509V3_ECDSA_SHA2_SECT283K1(
            "x509v3-ecdsa-sha2-1.3.132.0.16", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT283K1),
    X509V3_ECDSA_SHA2_SECT283R1(
            "x509v3-ecdsa-sha2-1.3.132.0.17", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT283R1),
    X509V3_ECDSA_SHA2_SECT409K1(
            "x509v3-ecdsa-sha2-1.3.132.0.36", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT409K1),
    X509V3_ECDSA_SHA2_SECT409R1(
            "x509v3-ecdsa-sha2-1.3.132.0.37", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT409R1),
    X509V3_ECDSA_SHA2_SECT571K1(
            "x509v3-ecdsa-sha2-1.3.132.0.38", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT571K1),
    X509V3_ECDSA_SHA2_SECT571R1(
            "x509v3-ecdsa-sha2-1.3.132.0.39", PublicKeyFormat.X509V3_ECDSA_SHA2_SECT571R1),
    X509V3_ECDSA_SHA2_BRAINPOOL_P256R1(
            "x509v3-ecdsa-sha2-1.3.36.3.3.2.8.1.1.7",
            PublicKeyFormat.X509V3_ECDSA_SHA2_BRAINPOOL_P256R1),
    X509V3_ECDSA_SHA2_BRAINPOOL_P384R1(
            "x509v3-ecdsa-sha2-1.3.36.3.3.2.8.1.1.11",
            PublicKeyFormat.X509V3_ECDSA_SHA2_BRAINPOOL_P384R1),
    X509V3_ECDSA_SHA2_BRAINPOOL_P512R1(
            "x509v3-ecdsa-sha2-1.3.36.3.3.2.8.1.1.13",
            PublicKeyFormat.X509V3_ECDSA_SHA2_BRAINPOOL_P512R1),
    // [ RFC 8709 ]
    SSH_ED25519(
            "ssh-ed25519", PublicKeyFormat.SSH_ED25519, SignatureEncoding.SSH_ED25519, "Ed25519"),
    SSH_ED448("ssh-ed448", PublicKeyFormat.SSH_ED448, SignatureEncoding.SSH_ED448, "Ed448"),
    // Vendor extensions
    // [ OpenSSH ]
    SSH_RSA_CERT_V01_OPENSSH_COM(
            "ssh-rsa-cert-v01@openssh.com", PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM, SignatureEncoding.SSH_RSA, "SHA1WithRSA"),
    RSA_SHA2_256_CERT_V01_OPENSSH_COM(
            "rsa-sha2-256-cert-v01@openssh.com", PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM, SignatureEncoding.RSA_SHA2_256, "SHA256WithRSA"),
    RSA_SHA2_512_CERT_V01_OPENSSH_COM(
            "rsa-sha2-512-cert-v01@openssh.com", PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM, SignatureEncoding.RSA_SHA2_512, "SHA512WithRSA"),
    SSH_DSS_CERT_V01_OPENSSH_COM(
            "ssh-dss-cert-v01@openssh.com", PublicKeyFormat.SSH_DSS_CERT_V01_OPENSSH_COM, SignatureEncoding.SSH_DSS, "SHA1WithDSA"),
    ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM(
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            PublicKeyFormat.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM, SignatureEncoding.ECDSA_SHA2_NISTP256, "SHA256withECDSA"),
    ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM(
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            PublicKeyFormat.ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM, SignatureEncoding.ECDSA_SHA2_NISTP384, "SHA384withECDSA"),
    ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM(
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            PublicKeyFormat.ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM, SignatureEncoding.ECDSA_SHA2_NISTP521, "SHA512withECDSA"),
    SSH_ED25519_CERT_V01_OPENSSH_COM(
            "ssh-ed25519-cert-v01@openssh.com", PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM, SignatureEncoding.SSH_ED25519, "Ed25519"),
    SK_ECDSA_SHA2_NISTP256_OPENSSH_COM(
            "sk-ecdsa-sha2-nistp256@openssh.com",
            PublicKeyFormat.SK_ECDSA_SHA2_NISTP256_OPENSSH_COM),
    SK_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM(
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            PublicKeyFormat.SK_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM),
    SK_SSH_ED25519_OPENSSH_COM(
            "sk-ssh-ed25519@openssh.com", PublicKeyFormat.SK_SSH_ED25519_OPENSSH_COM),
    SK_SSH_ED25519_CERT_V01_OPENSSH_COM(
            "sk-ssh-ed25519-cert-v01@openssh.com",
            PublicKeyFormat.SK_SSH_ED25519_CERT_V01_OPENSSH_COM),
    // [ SSH.COM ]
    SSH_RSA_SHA224_SSH_COM(
            "ssh-rsa-sha224@ssh.com",
            PublicKeyFormat.SSH_RSA,
            SignatureEncoding.SSH_RSA,
            "SHA224withRSA"),
    SSH_RSA_SHA256_SSH_COM(
            "ssh-rsa-sha256@ssh.com",
            PublicKeyFormat.SSH_RSA,
            SignatureEncoding.SSH_RSA,
            "SHA256withRSA"),
    SSH_RSA_SHA384_SSH_COM(
            "ssh-rsa-sha384@ssh.com",
            PublicKeyFormat.SSH_RSA,
            SignatureEncoding.SSH_RSA,
            "SHA384withRSA"),
    SSH_RSA_SHA512_SSH_COM(
            "ssh-rsa-sha512@ssh.com",
            PublicKeyFormat.SSH_RSA,
            SignatureEncoding.SSH_RSA,
            "SHA512withRSA");

    private final String name;
    private final PublicKeyFormat keyFormat;
    private final SignatureEncoding signatureEncoding;
    private final String javaName;

    public static final Map<String, PublicKeyAlgorithm> map;

    static {
        Map<String, PublicKeyAlgorithm> mutableMap = new TreeMap<>();
        for (PublicKeyAlgorithm algorithm : values()) {
            mutableMap.put(algorithm.name, algorithm);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    PublicKeyAlgorithm(String name, PublicKeyFormat keyFormat) {
        this(name, keyFormat, null, null);
    }

    PublicKeyAlgorithm(
            String name, PublicKeyFormat keyFormat, SignatureEncoding signatureEncoding) {
        this(name, keyFormat, signatureEncoding, null);
    }

    PublicKeyAlgorithm(
            String name,
            PublicKeyFormat keyFormat,
            SignatureEncoding signatureEncoding,
            String javaName) {
        this.name = name;
        this.signatureEncoding = signatureEncoding;
        this.keyFormat = keyFormat;
        this.javaName = javaName;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public PublicKeyFormat getKeyFormat() {
        return keyFormat;
    }

    public SignatureEncoding getSignatureEncoding() {
        return signatureEncoding;
    }

    public String getJavaName() {
        return javaName;
    }

    public static PublicKeyAlgorithm fromName(String name) {
        return map.get(name);
    }
}
