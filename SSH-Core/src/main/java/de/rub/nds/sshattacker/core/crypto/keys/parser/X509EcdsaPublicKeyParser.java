/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomX509EcdsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
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

    public X509EcdsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomX509EcdsaPublicKey, CustomEcPrivateKey> parse() {
        try {
            int startIndex = PublicKeyParserHelper.findX509StartIndex(getArray());

            // Extract the certificate from the byte array
            X509Certificate cert =
                    PublicKeyParserHelper.extractCertificate(getArray(), startIndex, true);
            PublicKey publicKey = cert.getPublicKey();

            // If the public key is of type ECPublicKey
            if (publicKey instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                byte[] signature = cert.getSignature();

                // Map the curve name to the appropriate NamedEcGroup (locally in the parser)
                NamedEcGroup group = NamedEcGroup.fromEcParameterSpec(ecPublicKey.getParams());

                // Lookup the curve name
                String curveName = group.getJavaName();

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
                HashMap<String, String> extensionsMap = parseExtensions(cert);
                customX509EcdsaPublicKey.setExtensions(extensionsMap);
                if (!extensionsMap.isEmpty()) {
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
                PublicKeyFormat keyFormat = PublicKeyFormat.fromNamedEcGroup(group, true);

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

    private static HashMap<String, String> parseExtensions(X509Certificate cert) {
        HashMap<String, String> extensionsMap = new HashMap<>();

        try {
            byte[] subjectKeyIdentifier =
                    cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            if (subjectKeyIdentifier != null) {
                extensionsMap.put(
                        "SubjectKeyIdentifier",
                        ArrayConverter.bytesToRawHexString(subjectKeyIdentifier));
            }

            byte[] authorityKeyIdentifier =
                    cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            if (authorityKeyIdentifier != null) {
                extensionsMap.put(
                        "AuthorityKeyIdentifier",
                        ArrayConverter.bytesToRawHexString(authorityKeyIdentifier));
            }

        } catch (Exception e) {
            LOGGER.warn("Error parsing extensions: {}", e.getMessage());
        }

        return extensionsMap;
    }
}
