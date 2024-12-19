/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomX509DsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import jakarta.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509DsaPublicKeyParser
        extends Parser<SshPublicKey<CustomX509DsaPublicKey, CustomDsaPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    public X509DsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomX509DsaPublicKey, CustomDsaPrivateKey> parse() {
        try {
            // Start parsing the certificate dynamically based on the ASN.1 structure
            int startIndex = findX509StartIndex(getArray());
            LOGGER.debug("Found X.509 start index at: {}", startIndex);

            X509Certificate cert = extractCertificate(getArray(), startIndex);
            PublicKey publicKey = cert.getPublicKey();

            // Falls der Key des Typs DSA ist, dann verwenden wir den CustomX509DsaPublicKey
            if (publicKey instanceof DSAPublicKey) {
                DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
                byte[] signature = cert.getSignature();
                CustomX509DsaPublicKey customX509DsaPublicKey =
                        new CustomX509DsaPublicKey(dsaPublicKey, signature);

                // Setze die geparsten Werte in das CustomX509DsaPublicKey-Objekt
                customX509DsaPublicKey.setVersion(cert.getVersion());
                customX509DsaPublicKey.setIssuer(cert.getIssuerDN().getName());
                customX509DsaPublicKey.setSubject(cert.getSubjectDN().getName());
                customX509DsaPublicKey.setSignatureAlgorithm(cert.getSigAlgName());
                customX509DsaPublicKey.setSerial(cert.getSerialNumber().longValue());
                customX509DsaPublicKey.setValidAfter(cert.getNotBefore().getTime());
                customX509DsaPublicKey.setValidBefore(cert.getNotAfter().getTime());
                customX509DsaPublicKey.setPublicKeyAlgorithm(publicKey.getAlgorithm());

                // DSA-spezifische Parameter setzen
                customX509DsaPublicKey.setY(dsaPublicKey.getY()); // Y-Wert des DSA-Schlüssels

                // Ausgabe der geparsten Elemente ins Log
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
                LOGGER.debug("Parsed DSA Y Value: {}", dsaPublicKey.getY());

                // Ausgabe der X.509-Erweiterungen (Extensions)
                try {
                    List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
                    if (extendedKeyUsage != null) {
                        LOGGER.debug("Parsed Extended Key Usage: {}", extendedKeyUsage);
                    }
                } catch (CertificateParsingException e) {
                    LOGGER.warn("Error parsing Extended Key Usage: {}", e.getMessage());
                }

                byte[] authorityKeyIdentifier = cert.getExtensionValue("2.5.29.35");
                if (authorityKeyIdentifier != null) {
                    String authorityKeyIdentifierHex =
                            DatatypeConverter.printHexBinary(authorityKeyIdentifier);
                    LOGGER.debug("Parsed Authority Key Identifier: {}", authorityKeyIdentifierHex);
                }

                byte[] subjectKeyIdentifier = cert.getExtensionValue("2.5.29.14");
                if (subjectKeyIdentifier != null) {
                    String subjectKeyIdentifierHex =
                            DatatypeConverter.printHexBinary(subjectKeyIdentifier);
                    LOGGER.debug("Parsed Subject Key Identifier: {}", subjectKeyIdentifierHex);
                }

                boolean[] keyUsage = cert.getKeyUsage();
                if (keyUsage != null) {
                    LOGGER.debug("Parsed Key Usage:");
                    for (int i = 0; i < keyUsage.length; i++) {
                        LOGGER.debug("  Key Usage {}: {}", i, keyUsage[i]);
                    }
                }

                // Setze Extensions, falls vorhanden
                HashMap<String, String> extensionsMap = new HashMap<>();
                if (authorityKeyIdentifier != null) {
                    extensionsMap.put(
                            "AuthorityKeyIdentifier", Arrays.toString(authorityKeyIdentifier));
                }
                if (subjectKeyIdentifier != null) {
                    extensionsMap.put(
                            "SubjectKeyIdentifier", Arrays.toString(subjectKeyIdentifier));
                }
                customX509DsaPublicKey.setExtensions(extensionsMap);

                // Ausgabe der CA-Informationen, falls vorhanden
                if (cert.getBasicConstraints() != -1) {
                    LOGGER.debug(
                            "Parsed Certificate is a CA Certificate. Basic Constraints: {}",
                            cert.getBasicConstraints());
                } else {
                    LOGGER.debug("Parsed Certificate is not a CA Certificate.");
                }

                LOGGER.debug("Successfully parsed the X.509 DSA Certificate Public Key.");
                return new SshPublicKey<>(PublicKeyFormat.X509V3_SSH_DSS, customX509DsaPublicKey);
            } else {
                throw new IllegalArgumentException(
                        "Ungültiges X.509 Zertifikat - Unterstützter Schlüsseltyp fehlt.");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Ungültiges X.509 Zertifikat!", e);
        }
    }

    // Funktion zur Bestimmung des Offsets für den Start des ASN.1-Blocks
    private static int findX509StartIndex(byte[] encodedPublicKeyBytes) {
        int startIndex = 8; // SSH-Header überspringen
        while (startIndex < encodedPublicKeyBytes.length) {
            if (encodedPublicKeyBytes[startIndex] == 0x30) { // ASN.1 SEQUENCE Tag
                LOGGER.debug("Found ASN.1 SEQUENCE at index: {}", startIndex);
                return startIndex;
            }
            startIndex++;
        }
        LOGGER.error("Failed to find start of X.509 certificate");
        throw new IllegalArgumentException("Konnte Start des X.509 Zertifikats nicht finden.");
    }

    // Extrahiert das vollständige Zertifikat
    private static X509Certificate extractCertificate(
            byte[] encodedCertificateBytes, int startIndex) throws Exception {
        if (startIndex >= encodedCertificateBytes.length) {
            LOGGER.error("Start index exceeds the length of the byte array");
            throw new IllegalArgumentException("Start index exceeds the length of the byte array");
        }

        LOGGER.debug("Extracting certificate starting at index: {}", startIndex);
        ByteArrayInputStream certInputStream =
                new ByteArrayInputStream(
                        encodedCertificateBytes,
                        startIndex,
                        encodedCertificateBytes.length - startIndex);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        try {
            return (X509Certificate) certFactory.generateCertificate(certInputStream);
        } catch (Exception e) {
            LOGGER.error("Failed to extract certificate", e);
            throw new IllegalArgumentException(
                    "Could not parse X.509 certificate: " + e.getMessage(), e);
        }
    }
}
