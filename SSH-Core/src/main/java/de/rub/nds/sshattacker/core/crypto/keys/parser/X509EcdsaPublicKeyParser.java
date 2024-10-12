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
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;

public class X509EcdsaPublicKeyParser
        extends Parser<SshPublicKey<CustomX509EcdsaPublicKey, CustomEcPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();

    // Map to store OID to curve name mapping
    private static final Map<String, String> oidToCurveNameMap = new HashMap<>();

    static {
        // Populate with known OIDs and curve names
        oidToCurveNameMap.put("1.2.840.10045.3.1.7", "secp256r1");
        oidToCurveNameMap.put("1.3.132.0.34", "secp384r1");
        oidToCurveNameMap.put("1.3.132.0.35", "secp521r1");
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
            if (publicKey instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
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
                                signature,
                                curveName,
                                group);

                // Set parsed values to the CustomX509EcdsaPublicKey object
                customX509EcdsaPublicKey.setVersion(cert.getVersion());
                customX509EcdsaPublicKey.setIssuer(cert.getIssuerDN().getName());
                customX509EcdsaPublicKey.setSubject(cert.getSubjectDN().getName());
                customX509EcdsaPublicKey.setSignatureAlgorithm(cert.getSigAlgName());
                customX509EcdsaPublicKey.setSerial(cert.getSerialNumber().longValue());
                customX509EcdsaPublicKey.setValidAfter(cert.getNotBefore().getTime() / 1000);
                customX509EcdsaPublicKey.setValidBefore(cert.getNotAfter().getTime() / 1000);
                customX509EcdsaPublicKey.setPublicKeyAlgorithm(publicKey.getAlgorithm());
                customX509EcdsaPublicKey.setCurveName(curveName);

                // Log parsed elements
                LOGGER.debug("Parsed Version: V{}", cert.getVersion());
                LOGGER.debug("Parsed Subject: {}", cert.getSubjectDN());
                LOGGER.debug("Parsed Issuer: {}", cert.getIssuerDN());
                LOGGER.debug("Parsed Signature Algorithm: {}", cert.getSigAlgName());
                LOGGER.debug("Parsed Serial Number: {}", cert.getSerialNumber());
                LOGGER.debug("Parsed Valid From: {}", cert.getNotBefore());
                LOGGER.debug("Parsed Valid To: {}", cert.getNotAfter());
                LOGGER.debug("Parsed Public Key Algorithm: {}", publicKey.getAlgorithm());
                LOGGER.debug(
                        "Parsed ECDSA Public Key Point: x={}, y={}",
                        ecPublicKey.getW().getAffineX(),
                        ecPublicKey.getW().getAffineY());

                // Set Extensions, if any
                Map<String, String> extensionsMap = parseExtensions(cert);
                customX509EcdsaPublicKey.setExtensions(extensionsMap);

                LOGGER.debug("Successfully parsed the X.509 ECDSA Certificate Public Key.");

                // Wrap the CustomX509EcdsaPublicKey in an SshPublicKey and return
                return new SshPublicKey<>(
                        PublicKeyFormat.X509V3_ECDSA_SHA2_NISTP256, customX509EcdsaPublicKey);
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
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(certInputStream);
    }

    private String getCurveOid(ECParameterSpec ecParams) {
        // Dynamically map ECParameterSpec to known curve OIDs
        // Placeholder implementation, you could compare parameters to known curves here
        return "1.2.840.10045.3.1.7"; // Default example for secp256r1
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
        switch (curveName) {
            case "secp256r1":
                return NamedEcGroup.SECP256R1;
            case "secp384r1":
                return NamedEcGroup.SECP384R1;
            case "secp521r1":
                return NamedEcGroup.SECP521R1;
            default:
                throw new IllegalArgumentException("Unknown curve name: " + curveName);
        }
    }
}
