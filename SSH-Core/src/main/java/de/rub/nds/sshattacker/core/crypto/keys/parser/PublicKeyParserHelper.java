/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class PublicKeyParserHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private PublicKeyParserHelper() {
        super();
    }

    // Funktion zur Bestimmung des Offsets für den Start des ASN.1-Blocks
    public static int findX509StartIndex(byte[] encodedPublicKeyBytes) {
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

    // Extracts the complete certificate
    public static X509Certificate extractCertificate(
            byte[] encodedCertificateBytes, int startIndex, boolean foreceBounceCastle)
            throws Exception {
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
        CertificateFactory certFactory =
                foreceBounceCastle
                        ? CertificateFactory.getInstance("X.509", "BC")
                        : CertificateFactory.getInstance("X.509");

        try {
            return (X509Certificate) certFactory.generateCertificate(certInputStream);
        } catch (Exception e) {
            LOGGER.error("Failed to extract certificate", e);
            throw new IllegalArgumentException(
                    "Could not parse X.509 certificate: " + e.getMessage(), e);
        }
    }
}
