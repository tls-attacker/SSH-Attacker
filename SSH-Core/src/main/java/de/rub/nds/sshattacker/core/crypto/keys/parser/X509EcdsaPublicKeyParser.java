/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomX509EcdsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;

public class X509EcdsaPublicKeyParser
        extends Parser<SshPublicKey<CustomX509EcdsaPublicKey, CustomEcPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    // Map to store OID to curve name mapping
    private static final Map<String, String> oidToCurveNameMap = new HashMap<>();

    static {
        // Populate with known OIDs and curve names
        // Required  Curves (RFC 5656, Abschnitt 10.1)
        oidToCurveNameMap.put("1.2.840.10045.3.1.7", "secp256r1");
        oidToCurveNameMap.put("1.3.132.0.34", "secp384r1");
        oidToCurveNameMap.put("1.3.132.0.35", "secp521r1");

        // Recommended Curves (RFC 5656, Abschnitt 10.2)
        oidToCurveNameMap.put("1.3.132.0.1", "sect163k1");
        oidToCurveNameMap.put("1.2.840.10045.3.1.1", "secp192r1");
        oidToCurveNameMap.put("1.3.132.0.33", "secp224r1");
        oidToCurveNameMap.put("1.3.132.0.26", "sect233k1");
        oidToCurveNameMap.put("1.3.132.0.27", "sect233r1");
        oidToCurveNameMap.put("1.3.132.0.16", "sect283k1");
        oidToCurveNameMap.put("1.3.132.0.36", "sect409k1");
        oidToCurveNameMap.put("1.3.132.0.37", "sect409r1");
        oidToCurveNameMap.put("1.3.132.0.38", "sect571k1");
    }

    public X509EcdsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomX509EcdsaPublicKey, CustomEcPrivateKey> parse() {
        try {
            int startIndex = findX509StartIndex(getArray());
            LOGGER.debug("Found X.509 start index at: {}", startIndex);

            // Extract the certificate from the byte array
            X509Certificate cert = extractCertificate(getArray(), startIndex);
            PublicKey publicKey = cert.getPublicKey();

            // If the public key is of type ECPublicKey
            if (publicKey instanceof ECPublicKey ecPublicKey) {
                byte[] signature = cert.getSignature();

                // Retrieve the curve OID
                ECParameterSpec ecParams = ecPublicKey.getParams();
                String curveOid = getCurveOid(ecParams);

                // Lookup the curve name from the OID
                String curveName = oidToCurveNameMap.getOrDefault(curveOid, "Unknown Curve");

                // Map the curve name to the appropriate NamedEcGroup (locally in the parser)
                NamedEcGroup group = mapCurveNameToNamedEcGroup(curveName);

                // Create CustomX509EcdsaPublicKey object
                CustomX509EcdsaPublicKey customX509EcdsaPublicKey =
                        new CustomX509EcdsaPublicKey(
                                ecPublicKey.getW().getAffineX(),
                                ecPublicKey.getW().getAffineY(),
                                group,
                                signature);

                // Set parsed values to the CustomX509EcdsaPublicKey object
                customX509EcdsaPublicKey.setVersion(cert.getVersion());
                customX509EcdsaPublicKey.setIssuer(cert.getIssuerDN().getName());
                customX509EcdsaPublicKey.setSubject(cert.getSubjectDN().getName());
                customX509EcdsaPublicKey.setSignatureAlgorithm(cert.getSigAlgName());
                customX509EcdsaPublicKey.setSerial(cert.getSerialNumber().longValue());
                customX509EcdsaPublicKey.setValidAfter(cert.getNotBefore().getTime());
                customX509EcdsaPublicKey.setValidBefore(cert.getNotAfter().getTime());
                customX509EcdsaPublicKey.setPublicKeyAlgorithm(publicKey.getAlgorithm());

                // Log parsed elements including the curve name
                LOGGER.debug("Parsed Version: V{}", cert.getVersion());
                LOGGER.debug("Parsed Subject: {}", cert.getSubjectDN());
                LOGGER.debug("Parsed Issuer: {}", cert.getIssuerDN());
                LOGGER.debug("Parsed Signature Algorithm: {}", cert.getSigAlgName());
                LOGGER.debug("Parsed Serial Number: {}", cert.getSerialNumber());
                LOGGER.debug(
                        "Parsed Valid From: {}",
                        DATE_FORMATTER.format(cert.getNotBefore().toInstant()));
                LOGGER.debug(
                        "Parsed Valid To: {}",
                        DATE_FORMATTER.format(cert.getNotAfter().toInstant()));
                LOGGER.debug("Parsed Public Key Algorithm: {}", publicKey.getAlgorithm());
                LOGGER.debug(
                        "Parsed ECDSA Public Key Point: x={}, y={}",
                        ecPublicKey.getW().getAffineX(),
                        ecPublicKey.getW().getAffineY());
                LOGGER.debug("Parsed Curve Name: {}", curveName);

                // Set Extensions, if any
                Map<String, String> extensionsMap = parseExtensions(cert);
                customX509EcdsaPublicKey.setExtensions(extensionsMap);
                if (extensionsMap != null && !extensionsMap.isEmpty()) {
                    LOGGER.debug("Parsed Certificate Extensions:");
                    for (Map.Entry<String, String> entry : extensionsMap.entrySet()) {
                        LOGGER.debug(
                                "Extension OID: {}, Value: {}", entry.getKey(), entry.getValue());
                    }
                } else {
                    LOGGER.debug("No extensions found in the certificate.");
                }

                LOGGER.debug("Successfully parsed the X.509 ECDSA Certificate Public Key.");

                // Dynamically determine the PublicKeyFormat based on the curve
                PublicKeyFormat keyFormat =
                        switch (curveName) {
                            // Required Curves (RFC 5656, Section 10.1)
                            case "secp256r1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP256;
                            case "secp384r1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP384;
                            case "secp521r1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP521;

                            // Recommended curves (RFC 5656, Section 10.2)
                            case "sect163k1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECT163K1;
                            case "secp192r1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECP192R1;
                            case "secp224r1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECP224R1;
                            case "sect233k1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECT233K1;
                            case "sect233r1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECT233R1;
                            case "sect283k1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECT283K1;
                            case "sect409k1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECT409K1;
                            case "sect409r1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECT409R1;
                            case "sect571k1" -> PublicKeyFormat.X509V3_ECDSA_SHA2_SECT571K1;

                            // Unknown or not supported curves
                            default ->
                                    throw new IllegalArgumentException(
                                            "Unsupported curve: " + curveName);
                        };

                // Wrap the CustomX509EcdsaPublicKey in an SshPublicKey and return
                return new SshPublicKey<>(keyFormat, customX509EcdsaPublicKey);
            } else {
                throw new IllegalArgumentException(
                        "Invalid X.509 certificate - ECDSA key missing.");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid X.509 certificate!", e);
        }
    }

    // Utility methods for finding the X.509 start index, extracting the certificate, and parsing
    // extensions

    private int findX509StartIndex(byte[] encodedPublicKeyBytes) {
        int startIndex = 8; // Skip SSH header
        while (startIndex < encodedPublicKeyBytes.length) {
            if (encodedPublicKeyBytes[startIndex] == 0x30) { // ASN.1 SEQUENCE Tag
                LOGGER.debug("Found ASN.1 SEQUENCE at index: {}", startIndex);
                return startIndex;
            }
            startIndex++;
        }
        throw new IllegalArgumentException("Could not find start of the X.509 certificate.");
    }

    private X509Certificate extractCertificate(byte[] encodedCertificateBytes, int startIndex)
            throws Exception {
        ByteArrayInputStream certInputStream =
                new ByteArrayInputStream(
                        encodedCertificateBytes,
                        startIndex,
                        encodedCertificateBytes.length - startIndex);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) certFactory.generateCertificate(certInputStream);
    }

    public static String getCurveOid(ECParameterSpec ecParams) {
        // Hole die Bit-Länge der Kurve
        int fieldSize = ecParams.getOrder().bitLength();

        // OID based on bit length
        return switch (fieldSize) {
            case 256 -> "1.2.840.10045.3.1.7"; // secp256r1 (nistp256)
            case 384 -> "1.3.132.0.34"; // secp384r1 (nistp384)
            case 521 -> "1.3.132.0.35"; // secp521r1 (nistp521)
            case 163 -> "1.3.132.0.1"; // sect163k1 (nistk163)
            case 192 -> "1.2.840.10045.3.1.1"; // secp192r1 (nistp192)
            case 224 -> "1.3.132.0.33"; // secp224r1 (nistp224)
            case 283 -> "1.3.132.0.16"; // sect283k1 (nistk283)
            case 571 -> "1.3.132.0.38"; // sect571k1 (nistt571)
            default -> "Unknown OID";
        };
    }

    private Map<String, String> parseExtensions(X509Certificate cert) {
        Map<String, String> extensionsMap = new HashMap<>();

        try {
            byte[] subjectKeyIdentifier =
                    cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            if (subjectKeyIdentifier != null) {
                extensionsMap.put("SubjectKeyIdentifier", bytesToHex(subjectKeyIdentifier));
            }

            byte[] authorityKeyIdentifier =
                    cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            if (authorityKeyIdentifier != null) {
                extensionsMap.put("AuthorityKeyIdentifier", bytesToHex(authorityKeyIdentifier));
            }

        } catch (Exception e) {
            LOGGER.warn("Error parsing extensions: {}", e.getMessage());
        }

        return extensionsMap;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // Map curve name to NamedEcGroup locally without modifying NamedEcGroup
    private NamedEcGroup mapCurveNameToNamedEcGroup(String curveName) {
        return switch (curveName) {
            // Required Curves (RFC 5656, Section 10.1)
            case "secp256r1" -> NamedEcGroup.SECP256R1;
            case "secp384r1" -> NamedEcGroup.SECP384R1;
            case "secp521r1" -> NamedEcGroup.SECP521R1;

            // Recommended Curves (RFC 5656, Section 10.2)
            case "sect163k1" -> NamedEcGroup.SECT163K1;
            case "secp192r1" -> NamedEcGroup.SECP192R1;
            case "secp224r1" -> NamedEcGroup.SECP224R1;
            case "sect233k1" -> NamedEcGroup.SECT233K1;
            case "sect233r1" -> NamedEcGroup.SECT233R1;
            case "sect283k1" -> NamedEcGroup.SECT283K1;
            case "sect409k1" -> NamedEcGroup.SECT409K1;
            case "sect409r1" -> NamedEcGroup.SECT409R1;
            case "sect571k1" -> NamedEcGroup.SECT571K1;
            default -> throw new IllegalArgumentException("Unknown curve name: " + curveName);
        };
    }
}
