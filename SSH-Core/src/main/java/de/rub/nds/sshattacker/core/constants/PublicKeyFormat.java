/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

public enum PublicKeyFormat {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
     */
    // [ RFC 4253 ]
    SSH_DSS("ssh-dss"),
    SSH_RSA("ssh-rsa"),
    SPKI_SIGN_RSA("spki-sign-rsa"),
    SPKI_SIGN_DSS("spki-sign-dss"),
    PGP_SIGN_RSA("pgp-sign-rsa"),
    PGP_SIGN_DSS("pgp-sign-dss"),
    // [ RFC 4462 ]
    NULL("null"),
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
    // [ RFC 6187 ]
    X509V3_SSH_DSS("x509v3-ssh-dss"),
    X509V3_SSH_RSA("x509v3-ssh-rsa"),
    X509V3_RSA2048_SHA256("x509v3-rsa2048-sha256"),
    X509V3_ECDSA_SHA2_SECP160K1("x509v3-ecdsa-sha2-1.3.132.0.9"),
    X509V3_ECDSA_SHA2_SECP160R1("x509v3-ecdsa-sha2-1.3.132.0.8"),
    X509V3_ECDSA_SHA2_SECP160R2("x509v3-ecdsa-sha2-1.3.132.0.30"),
    X509V3_ECDSA_SHA2_SECP192K1("x509v3-ecdsa-sha2-1.3.132.0.31"),
    X509V3_ECDSA_SHA2_SECP192R1("x509v3-ecdsa-sha2-1.2.840.10045.3.1.1"),
    X509V3_ECDSA_SHA2_SECP224K1("x509v3-ecdsa-sha2-1.3.132.0.32"),
    X509V3_ECDSA_SHA2_SECP224R1("x509v3-ecdsa-sha2-1.3.132.0.33"),
    X509V3_ECDSA_SHA2_SECP256K1("x509v3-ecdsa-sha2-1.3.132.0.10"),
    X509V3_ECDSA_SHA2_NISTP256("x509v3-ecdsa-sha2-nistp256"),
    X509V3_ECDSA_SHA2_NISTP384("x509v3-ecdsa-sha2-nistp384"),
    X509V3_ECDSA_SHA2_NISTP521("x509v3-ecdsa-sha2-nistp521"),
    X509V3_ECDSA_SHA2_SECT163K1("x509v3-ecdsa-sha2-1.3.132.0.1"),
    X509V3_ECDSA_SHA2_SECT163R1("x509v3-ecdsa-sha2-1.3.132.0.2"),
    X509V3_ECDSA_SHA2_SECT163R2("x509v3-ecdsa-sha2-1.3.132.0.15"),
    X509V3_ECDSA_SHA2_SECT193R1("x509v3-ecdsa-sha2-1.3.132.0.24"),
    X509V3_ECDSA_SHA2_SECT193R2("x509v3-ecdsa-sha2-1.3.132.0.25"),
    X509V3_ECDSA_SHA2_SECT233K1("x509v3-ecdsa-sha2-1.3.132.0.26"),
    X509V3_ECDSA_SHA2_SECT233R1("x509v3-ecdsa-sha2-1.3.132.0.27"),
    X509V3_ECDSA_SHA2_SECT239K1("x509v3-ecdsa-sha2-1.3.132.0.3"),
    X509V3_ECDSA_SHA2_SECT283K1("x509v3-ecdsa-sha2-1.3.132.0.16"),
    X509V3_ECDSA_SHA2_SECT283R1("x509v3-ecdsa-sha2-1.3.132.0.17"),
    X509V3_ECDSA_SHA2_SECT409K1("x509v3-ecdsa-sha2-1.3.132.0.36"),
    X509V3_ECDSA_SHA2_SECT409R1("x509v3-ecdsa-sha2-1.3.132.0.37"),
    X509V3_ECDSA_SHA2_SECT571K1("x509v3-ecdsa-sha2-1.3.132.0.38"),
    X509V3_ECDSA_SHA2_SECT571R1("x509v3-ecdsa-sha2-1.3.132.0.39"),
    X509V3_ECDSA_SHA2_BRAINPOOL_P256R1("x509v3-ecdsa-sha2-1.3.36.3.3.2.8.1.1.7"),
    X509V3_ECDSA_SHA2_BRAINPOOL_P384R1("x509v3-ecdsa-sha2-1.3.36.3.3.2.8.1.1.11"),
    X509V3_ECDSA_SHA2_BRAINPOOL_P512R1("x509v3-ecdsa-sha2-1.3.36.3.3.2.8.1.1.13"),
    // Without RFC
    X509V3_SSH_ED25519("x509v3-ssh-ed25519"),
    // [ RFC 8709 ]
    SSH_ED25519("ssh-ed25519"),
    SSH_ED448("ssh-ed448"),
    // Vendor extensions
    // [ OpenSSH ]
    SSH_RSA_CERT_V01_OPENSSH_COM("ssh-rsa-cert-v01@openssh.com"),
    RSA_SHA2_256_CERT_V01_OPENSSH_COM("rsa-sha2-256-cert-v01@openssh.com"),
    RSA_SHA2_512_CERT_V01_OPENSSH_COM("rsa-sha2-512-cert-v01@openssh.com"),
    SSH_DSS_CERT_V01_OPENSSH_COM("ssh-dss-cert-v01@openssh.com"),
    ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
    ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM("ecdsa-sha2-nistp384-cert-v01@openssh.com"),
    ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM("ecdsa-sha2-nistp521-cert-v01@openssh.com"),
    SSH_ED25519_CERT_V01_OPENSSH_COM("ssh-ed25519-cert-v01@openssh.com"),
    SK_ECDSA_SHA2_NISTP256_OPENSSH_COM("sk-ecdsa-sha2-nistp256@openssh.com"),
    SK_SSH_ED25519_OPENSSH_COM("sk-ssh-ed25519@openssh.com"),
    SK_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"),
    SK_SSH_ED25519_CERT_V01_OPENSSH_COM("sk-ssh-ed25519-cert-v01@openssh.com");

    private final String name;

    public static final Map<String, PublicKeyFormat> map;

    static {
        Map<String, PublicKeyFormat> mutableMap = new TreeMap<>();
        for (PublicKeyFormat format : values()) {
            mutableMap.put(format.name, format);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    PublicKeyFormat(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public static PublicKeyFormat fromName(String name) {
        return map.get(name);
    }

    public static PublicKeyFormat fromNamedEcGroup(NamedEcGroup group, boolean x509Variant) {
        return switch (group) {
            case SECP160K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECP160K1 : ECDSA_SHA2_SECP160K1;
            case SECP160R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECP160R1 : ECDSA_SHA2_SECP160R1;
            case SECP160R2 -> x509Variant ? X509V3_ECDSA_SHA2_SECP160R2 : ECDSA_SHA2_SECP160R2;
            case SECP192K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECP192K1 : ECDSA_SHA2_SECP192K1;
            case SECP192R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECP192R1 : ECDSA_SHA2_SECP192R1;
            case SECP224K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECP224K1 : ECDSA_SHA2_SECP224K1;
            case SECP224R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECP224R1 : ECDSA_SHA2_SECP224R1;
            case SECP256K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECP256K1 : ECDSA_SHA2_SECP256K1;
            case SECP256R1 -> x509Variant ? X509V3_ECDSA_SHA2_NISTP256 : ECDSA_SHA2_NISTP256;
            case SECP384R1 -> x509Variant ? X509V3_ECDSA_SHA2_NISTP384 : ECDSA_SHA2_NISTP384;
            case SECP521R1 -> x509Variant ? X509V3_ECDSA_SHA2_NISTP521 : ECDSA_SHA2_NISTP521;
            case SECT163K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT163K1 : ECDSA_SHA2_SECT163K1;
            case SECT163R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT163R1 : ECDSA_SHA2_SECT163R1;
            case SECT163R2 -> x509Variant ? X509V3_ECDSA_SHA2_SECT163R2 : ECDSA_SHA2_SECT163R2;
            case SECT193R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT193R1 : ECDSA_SHA2_SECT193R1;
            case SECT193R2 -> x509Variant ? X509V3_ECDSA_SHA2_SECT193R2 : ECDSA_SHA2_SECT193R2;
            case SECT233K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT233K1 : ECDSA_SHA2_SECT233K1;
            case SECT233R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT233R1 : ECDSA_SHA2_SECT233R1;
            case SECT239K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT239K1 : ECDSA_SHA2_SECT239K1;
            case SECT283K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT283K1 : ECDSA_SHA2_SECT283K1;
            case SECT283R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT283R1 : ECDSA_SHA2_SECT283R1;
            case SECT409K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT409K1 : ECDSA_SHA2_SECT409K1;
            case SECT409R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT409R1 : ECDSA_SHA2_SECT409R1;
            case SECT571K1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT571K1 : ECDSA_SHA2_SECT571K1;
            case SECT571R1 -> x509Variant ? X509V3_ECDSA_SHA2_SECT571R1 : ECDSA_SHA2_SECT571R1;
            case BRAINPOOLP256R1 ->
                    x509Variant ? X509V3_ECDSA_SHA2_BRAINPOOL_P256R1 : ECDSA_SHA2_BRAINPOOL_P256R1;
            case BRAINPOOLP384R1 ->
                    x509Variant ? X509V3_ECDSA_SHA2_BRAINPOOL_P384R1 : ECDSA_SHA2_BRAINPOOL_P384R1;
            case BRAINPOOLP512R1 ->
                    x509Variant ? X509V3_ECDSA_SHA2_BRAINPOOL_P512R1 : ECDSA_SHA2_BRAINPOOL_P512R1;
            case CURVE25519 -> x509Variant ? X509V3_SSH_ED25519 : SSH_ED25519;
            case CURVE448 -> {
                if (x509Variant) {
                    throw new NotImplementedException(
                            "X509 variant of CURVE448 is not implemented");
                }
                yield SSH_ED448;
            }
        };
    }
}
