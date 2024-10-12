/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.crypto.keys.parser.*;
import de.rub.nds.sshattacker.core.crypto.keys.serializer.*;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Utility class for public key parsing and serializing */
public final class PublicKeyHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private PublicKeyHelper() {
        super();
    }

    /**
     * Parses the given encoded public key bytes. Instead of an explicit key format, the key format
     * will be directly extracted from the public key bytes. Note that this behavior may lead to
     * unexpected errors and does not conform with RFC 4253.
     *
     * @param encodedPublicKeyBytes Encoded public key in some SSH public key format
     * @return The parsed public key
     * @throws NotImplementedException Thrown whenever support for the extracted key format has not
     *     yet been implemented.
     */
    public static SshPublicKey<?, ?> parse(byte[] encodedPublicKeyBytes) {
        if (isX509Format(encodedPublicKeyBytes)) {
            PublicKeyFormat keyFormat = parseX509(encodedPublicKeyBytes);

            switch (keyFormat) {
                case X509V3_SSH_RSA:
                case X509V3_RSA2048_SHA256:
                    return new X509RsaPublicKeyParser(
                                    encodedPublicKeyBytes,
                                    findX509StartIndex(encodedPublicKeyBytes))
                            .parse();
                case X509V3_ECDSA_SHA2_SECP160K1:
                case X509V3_ECDSA_SHA2_SECP160R1:
                case X509V3_ECDSA_SHA2_SECP160R2:
                case X509V3_ECDSA_SHA2_SECP192K1:
                case X509V3_ECDSA_SHA2_SECP192R1:
                case X509V3_ECDSA_SHA2_SECP224K1:
                case X509V3_ECDSA_SHA2_SECP224R1:
                case X509V3_ECDSA_SHA2_SECP256K1:
                case X509V3_ECDSA_SHA2_NISTP256:
                case X509V3_ECDSA_SHA2_NISTP384:
                case X509V3_ECDSA_SHA2_NISTP521:
                case X509V3_ECDSA_SHA2_SECT163K1:
                case X509V3_ECDSA_SHA2_SECT163R1:
                case X509V3_ECDSA_SHA2_SECT163R2:
                case X509V3_ECDSA_SHA2_SECT193R1:
                case X509V3_ECDSA_SHA2_SECT193R2:
                case X509V3_ECDSA_SHA2_SECT233K1:
                case X509V3_ECDSA_SHA2_SECT233R1:
                case X509V3_ECDSA_SHA2_SECT239K1:
                case X509V3_ECDSA_SHA2_SECT283K1:
                case X509V3_ECDSA_SHA2_SECT283R1:
                case X509V3_ECDSA_SHA2_SECT409K1:
                case X509V3_ECDSA_SHA2_SECT409R1:
                case X509V3_ECDSA_SHA2_SECT571K1:
                case X509V3_ECDSA_SHA2_SECT571R1:
                    return new X509EcdsaPublicKeyParser(
                                    encodedPublicKeyBytes,
                                    findX509StartIndex(encodedPublicKeyBytes))
                            .parse();
                case X509V3_SSH_DSS:
                    return new X509DsaPublicKeyParser(
                                    encodedPublicKeyBytes,
                                    findX509StartIndex(encodedPublicKeyBytes))
                            .parse();
                case X509V3_SSH_ED25519:
                    return new X509XCurvePublicKeyParser(
                                    encodedPublicKeyBytes,
                                    findX509StartIndex(encodedPublicKeyBytes))
                            .parse();
                default:
                    throw new NotImplementedException(
                            "Parser for Public Key Format " + keyFormat + " not implemented.");
            }
        } else {
            // Normal SSH Public Key Parsing
            int keyFormatLength =
                    ArrayConverter.bytesToInt(
                            Arrays.copyOfRange(
                                    encodedPublicKeyBytes,
                                    0,
                                    DataFormatConstants.STRING_SIZE_LENGTH));
            String keyFormatName =
                    new String(
                            Arrays.copyOfRange(
                                    encodedPublicKeyBytes,
                                    DataFormatConstants.STRING_SIZE_LENGTH,
                                    DataFormatConstants.STRING_SIZE_LENGTH + keyFormatLength),
                            StandardCharsets.US_ASCII);

            PublicKeyFormat keyFormat = PublicKeyFormat.fromName(keyFormatName);
            switch (keyFormat) {
                case SSH_RSA:
                    return new RsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
                case SSH_DSS:
                    return new DsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
                case ECDSA_SHA2_SECP160K1:
                case ECDSA_SHA2_SECP160R1:
                case ECDSA_SHA2_SECP160R2:
                case ECDSA_SHA2_SECP192K1:
                case ECDSA_SHA2_NISTP256:
                case ECDSA_SHA2_NISTP384:
                case ECDSA_SHA2_NISTP521:
                case ECDSA_SHA2_SECT163K1:
                case ECDSA_SHA2_SECT163R1:
                case ECDSA_SHA2_SECT163R2:
                case ECDSA_SHA2_SECT193R1:
                case ECDSA_SHA2_SECT193R2:
                case ECDSA_SHA2_SECT233K1:
                case ECDSA_SHA2_SECT233R1:
                case ECDSA_SHA2_SECT239K1:
                case ECDSA_SHA2_SECT283K1:
                case ECDSA_SHA2_SECT283R1:
                case ECDSA_SHA2_SECT409K1:
                case ECDSA_SHA2_SECT409R1:
                case ECDSA_SHA2_SECT571K1:
                case ECDSA_SHA2_SECT571R1:
                case ECDSA_SHA2_BRAINPOOL_P256R1:
                case ECDSA_SHA2_BRAINPOOL_P384R1:
                case ECDSA_SHA2_BRAINPOOL_P512R1:
                    return new EcdsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
                case SSH_RSA_CERT_V01_OPENSSH_COM:
                case RSA_SHA2_512_CERT_V01_OPENSSH_COM:
                case RSA_SHA2_256_CERT_V01_OPENSSH_COM:
                    return new CertRsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
                case SSH_DSS_CERT_V01_OPENSSH_COM:
                    return new CertDsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
                case ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM:
                case ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM:
                case ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM:
                    return new CertEcdsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
                case SSH_ED25519_CERT_V01_OPENSSH_COM:
                    return new CertXCurvePublicKeyParser(encodedPublicKeyBytes, 0).parse();
                case X509V3_SSH_RSA:
                    return new X509RsaPublicKeyParser(encodedPublicKeyBytes, 12).parse();
                case SSH_ED25519:
                case SSH_ED448:
                    return new XCurvePublicKeyParser(encodedPublicKeyBytes, 0).parse();
                default:
                    throw new NotImplementedException(
                            "Parser for Public Key Format " + keyFormat + " not implemented.");
            }
        }
    }

    /**
     * Parses the given encoded public key bytes if it is in X.509 format.
     *
     * @param encodedPublicKeyBytes Encoded public key in X.509 format
     * @return The parsed public key
     */
    private static PublicKeyFormat parseX509(byte[] encodedPublicKeyBytes) {
        try {
            // Determine the starting point of the ASN.1 block dynamically
            int startIndex = findX509StartIndex(encodedPublicKeyBytes);
            return extractKeyFormatFromX509(encodedPublicKeyBytes, startIndex);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid X.509 Certificate!", e);
        }
    }

    /**
     * Determines the correct starting index for parsing an X.509 certificate.
     *
     * @param encodedPublicKeyBytes Encoded public key in X.509 format
     * @return The starting index for parsing the X.509 certificate
     */
    private static int findX509StartIndex(byte[] encodedPublicKeyBytes) {
        // Search for SEQUENCE (0x30 82 oder 0x30 81)
        for (int i = 0; i < encodedPublicKeyBytes.length - 1; i++) {
            if (encodedPublicKeyBytes[i] == 0x30
                    && (encodedPublicKeyBytes[i + 1] == (byte) 0x82
                            || encodedPublicKeyBytes[i + 1] == (byte) 0x81)) {
                return i; // Der Startpunkt des X.509-Zertifikats wurde gefunden
            }
        }

        throw new IllegalArgumentException("Konnte Start des X.509-Zertifikats nicht finden.");
    }

    private static boolean isX509Format(byte[] encodedPublicKeyBytes) {
        try {
            int startIndex = findX509StartIndex(encodedPublicKeyBytes);
            return (startIndex >= 0);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static PublicKeyFormat extractKeyFormatFromX509(
            byte[] encodedCertificateBytes, int startIndex) throws Exception {
        // Start parsing the certificate from the specified start index onwards
        ByteArrayInputStream certInputStream =
                new ByteArrayInputStream(
                        encodedCertificateBytes,
                        startIndex,
                        encodedCertificateBytes.length - startIndex);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certInputStream);
        PublicKey publicKey = cert.getPublicKey();

        // Recognize RSA keys
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            String signatureAlgorithm = cert.getSigAlgName();
            int keyLength = rsaPublicKey.getModulus().bitLength();

            if (keyLength == 2048 && "SHA256withRSA".equalsIgnoreCase(signatureAlgorithm)) {
                return PublicKeyFormat.X509V3_RSA2048_SHA256;
            } else {
                return PublicKeyFormat.X509V3_SSH_RSA; // Default fallback for other RSA types
            }
        }
        // Recognize elliptic curve keys and determine the exact curve
        else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ECParameterSpec params = ecPublicKey.getParams();

            // Distinguish different curves based on their parameters (OID or curve name)
            String curveName = params.toString();

            // Required curves
            if (curveName.contains("secp256r1")) { // NIST P-256
                return PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP256;
            } else if (curveName.contains("secp384r1")) { // NIST P-384
                return PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP384;
            } else if (curveName.contains("secp521r1")) { // NIST P-521
                return PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP521;
            }
            // Recommended curves
            else if (curveName.contains("sect163k1")) { // NIST K-163
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT163K1;
            } else if (curveName.contains("secp192r1")) { // NIST P-192
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECP192R1;
            } else if (curveName.contains("secp224r1")) { // NIST P-224
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECP224R1;
            } else if (curveName.contains("sect233k1")) { // NIST K-233
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT233K1;
            } else if (curveName.contains("sect233r1")) { // NIST B-233
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT233R1;
            } else if (curveName.contains("sect283k1")) { // NIST K-283
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT283K1;
            } else if (curveName.contains("sect409k1")) { // NIST K-409
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT409K1;
            } else if (curveName.contains("sect409r1")) { // NIST B-409
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT409R1;
            } else if (curveName.contains("sect571k1")) { // NIST K-571
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT571K1;
            } else if (curveName.contains("sect571r1")) { // NIST B-571
                return PublicKeyFormat.X509V3_ECDSA_SHA2_SECT571R1;
            }
            // Unsupported curves
            else {
                throw new NotImplementedException("ECC curve " + curveName + " is not supported.");
            }
        }
        // Recognize DSS (DSA) keys
        else if (publicKey instanceof DSAPublicKey) {
            return PublicKeyFormat.X509V3_SSH_DSS;
        }
        // Recognize ED25519 keys
        else if (publicKey.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            return PublicKeyFormat.X509V3_SSH_ED25519;
        }
        // If the public key type is not supported
        else {
            throw new NotImplementedException(
                    "Public Key Format " + publicKey.getAlgorithm() + " is not supported.");
        }
    }

    /**
     * Parses the given encoded public key bytes using the specified key format.
     *
     * @param expectedKeyFormat The public key format (must be explicitly known as per RFC 4253 Sec.
     *     6.6)
     * @param encodedPublicKeyBytes Encoded public key in the specified format
     * @return The parsed public key
     * @throws NotImplementedException Thrown whenever support for the specified key format has not
     *     yet been implemented.
     */
    public static SshPublicKey<?, ?> parse(
            PublicKeyFormat expectedKeyFormat, byte[] encodedPublicKeyBytes) {
        SshPublicKey<?, ?> publicKey = parse(encodedPublicKeyBytes);
        if (!(publicKey instanceof SshPublicKey)) {
            throw new IllegalArgumentException("Parsed key is not of expected type SshPublicKey.");
        }
        if (publicKey.getPublicKeyFormat() != expectedKeyFormat) {
            LOGGER.warn(
                    "Expected public key of format '{}', but got '{}'. Continuing anyway.",
                    expectedKeyFormat,
                    publicKey.getPublicKeyFormat());
        }
        return publicKey;
    }

    /**
     * Serializes the given host key using its primary key format into a byte array.
     *
     * @param hostKey Host key to serialize
     * @return A serialized representation of the host key its primary key format
     * @throws NotImplementedException Thrown whenever support for the key format has not yet been
     *     implemented.
     */
    public static byte[] encode(SshPublicKey<?, ?> hostKey) {
        return encode(hostKey.getPublicKeyFormat(), hostKey.getPublicKey());
    }

    /**
     * Serializes the given public key using the specified key format into a byte array.
     *
     * @param keyFormat The public key format
     * @param publicKey Public key to serialize
     * @return A serialized representation of the public key in the specified public key format or
     *     null, if key format does not support the given key.
     * @throws NotImplementedException Thrown whenever support for the specified key format has not
     *     yet been implemented.
     */
    public static byte[] encode(PublicKeyFormat keyFormat, PublicKey publicKey) {
        try {
            switch (keyFormat) {
                case SSH_RSA:
                    return new RsaPublicKeySerializer((CustomRsaPublicKey) publicKey).serialize();
                case SSH_DSS:
                    return new DsaPublicKeySerializer((CustomDsaPublicKey) publicKey).serialize();
                case ECDSA_SHA2_SECP160K1:
                case ECDSA_SHA2_SECP160R1:
                case ECDSA_SHA2_SECP160R2:
                case ECDSA_SHA2_SECP192K1:
                case ECDSA_SHA2_NISTP256:
                case ECDSA_SHA2_NISTP384:
                case ECDSA_SHA2_NISTP521:
                    return new EcdsaPublicKeySerializer((CustomEcPublicKey) publicKey).serialize();
                case SSH_RSA_CERT_V01_OPENSSH_COM:
                    return new CertRsaPublicKeySerializer((CustomCertRsaPublicKey) publicKey)
                            .serialize();
                case SSH_DSS_CERT_V01_OPENSSH_COM:
                    return new CertDsaPublicKeySerializer((CustomCertDsaPublicKey) publicKey)
                            .serialize();
                case ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM:
                case ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM:
                case ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM:
                    return new CertEcdsaPublicKeySerializer((CustomCertEcdsaPublicKey) publicKey)
                            .serialize();
                case SSH_ED25519_CERT_V01_OPENSSH_COM:
                    return new CertXCurvePublicKeySerializer((CustomCertXCurvePublicKey) publicKey)
                            .serialize();
                case SSH_ED25519:
                case SSH_ED448:
                    return new XCurvePublicKeySerializer((XCurveEcPublicKey) publicKey).serialize();
                case X509V3_SSH_RSA:
                case X509V3_RSA2048_SHA256:
                    return new X509RsaPublicKeySerializer((CustomX509RsaPublicKey) publicKey)
                            .serialize();
                case X509V3_ECDSA_SHA2_SECP160K1:
                case X509V3_ECDSA_SHA2_SECP160R1:
                case X509V3_ECDSA_SHA2_SECP160R2:
                case X509V3_ECDSA_SHA2_SECP192K1:
                case X509V3_ECDSA_SHA2_SECP192R1:
                case X509V3_ECDSA_SHA2_SECP224K1:
                case X509V3_ECDSA_SHA2_SECP224R1:
                case X509V3_ECDSA_SHA2_SECP256K1:
                case X509V3_ECDSA_SHA2_NISTP256:
                case X509V3_ECDSA_SHA2_NISTP384:
                case X509V3_ECDSA_SHA2_NISTP521:
                case X509V3_ECDSA_SHA2_SECT163K1:
                case X509V3_ECDSA_SHA2_SECT163R1:
                case X509V3_ECDSA_SHA2_SECT163R2:
                case X509V3_ECDSA_SHA2_SECT193R1:
                case X509V3_ECDSA_SHA2_SECT193R2:
                case X509V3_ECDSA_SHA2_SECT233K1:
                case X509V3_ECDSA_SHA2_SECT233R1:
                case X509V3_ECDSA_SHA2_SECT239K1:
                case X509V3_ECDSA_SHA2_SECT283K1:
                case X509V3_ECDSA_SHA2_SECT283R1:
                case X509V3_ECDSA_SHA2_SECT409K1:
                case X509V3_ECDSA_SHA2_SECT409R1:
                case X509V3_ECDSA_SHA2_SECT571K1:
                case X509V3_ECDSA_SHA2_SECT571R1:
                    return new X509EcdsaPublicKeySerializer((CustomX509EcdsaPublicKey) publicKey)
                            .serialize();
                case X509V3_SSH_DSS:
                    return new X509DsaPublicKeySerializer((CustomX509DsaPublicKey) publicKey)
                            .serialize();
                case X509V3_SSH_ED25519:
                    return new X509XCurvePublicKeySerializer((CustomX509XCurvePublicKey) publicKey)
                            .serialize();
                default:
                    throw new NotImplementedException(
                            "Serializer für Public Key Format "
                                    + keyFormat
                                    + " ist noch nicht implementiert.");
            }
        } catch (ClassCastException e) {
            LOGGER.error(
                    "Unable to encode public key with key format '{}' due to mismatching classes, got '{}'",
                    keyFormat,
                    publicKey.getClass().getSimpleName());
            LOGGER.debug(e);
            return null;
        }
    }
}
