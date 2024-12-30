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
import de.rub.nds.sshattacker.core.crypto.keys.CustomX509XCurvePublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import jakarta.xml.bind.DatatypeConverter;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class X509XCurvePublicKeyParser extends Parser<SshPublicKey<CustomX509XCurvePublicKey, ?>> {

    private static final Logger LOGGER = LogManager.getLogger();

    static {
        // BouncyCastle-Provider added
        Security.addProvider(new BouncyCastleProvider());
    }

    public X509XCurvePublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomX509XCurvePublicKey, ?> parse() {
        try {
            // Start parsing the certificate dynamically based on the ASN.1 structure
            int startIndex = PublicKeyParserHelper.findX509StartIndex(getArray());
            X509Certificate cert =
                    PublicKeyParserHelper.extractCertificate(getArray(), startIndex, true);
            PublicKey publicKey = cert.getPublicKey();

            // Falls der Key Ed25519 oder Ed448 ist
            byte[] encodedPublicKey = publicKey.getEncoded();
            NamedEcGroup group = detectEdCurveGroup(publicKey.getAlgorithm());

            if (group != null) {
                byte[] signature = cert.getSignature();
                CustomX509XCurvePublicKey customX509XCurvePublicKey =
                        new CustomX509XCurvePublicKey(encodedPublicKey, group, signature);

                // Set parsed value in CustomX509XCurvePublicKey object
                customX509XCurvePublicKey.setVersion(cert.getVersion());
                customX509XCurvePublicKey.setIssuer(cert.getIssuerDN().getName());
                customX509XCurvePublicKey.setSubject(cert.getSubjectDN().getName());
                customX509XCurvePublicKey.setSignatureAlgorithm(cert.getSigAlgName());
                customX509XCurvePublicKey.setSerial(cert.getSerialNumber().longValue());
                customX509XCurvePublicKey.setValidAfter(cert.getNotBefore().getTime());
                customX509XCurvePublicKey.setValidBefore(cert.getNotAfter().getTime());
                customX509XCurvePublicKey.setPublicKeyAlgorithm(publicKey.getAlgorithm());

                // Logger
                LOGGER.debug("Parsed Version: V{}", cert.getVersion());
                LOGGER.debug("Parsed Subject: {}", cert.getSubjectDN());
                LOGGER.debug("Parsed Issuer: {}", cert.getIssuerDN());
                LOGGER.debug("Parsed Signature Algorithm: {}", cert.getSigAlgName());
                LOGGER.debug("Parsed Serial Number: {}", cert.getSerialNumber());
                LOGGER.debug("Parsed Valid From: {}", cert.getNotBefore());
                LOGGER.debug("Parsed Valid To: {}", cert.getNotAfter());
                LOGGER.debug("Parsed Public Key Algorithm: {}", publicKey.getAlgorithm());

                // X.509-Extensions
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

                // Set Extensions
                HashMap<String, String> extensionsMap = new HashMap<>();
                if (authorityKeyIdentifier != null) {
                    extensionsMap.put(
                            "AuthorityKeyIdentifier", Arrays.toString(authorityKeyIdentifier));
                }
                if (subjectKeyIdentifier != null) {
                    extensionsMap.put(
                            "SubjectKeyIdentifier", Arrays.toString(subjectKeyIdentifier));
                }
                customX509XCurvePublicKey.setExtensions(extensionsMap);

                // CA-Information
                if (cert.getBasicConstraints() != -1) {
                    LOGGER.debug(
                            "Parsed Certificate is a CA Certificate. Basic Constraints: {}",
                            cert.getBasicConstraints());
                } else {
                    LOGGER.debug("Parsed Certificate is not a CA Certificate.");
                }

                LOGGER.debug("Successfully parsed the X.509 EdDSA Certificate Public Key.");
                return new SshPublicKey<>(
                        PublicKeyFormat.X509V3_SSH_ED25519, customX509XCurvePublicKey);
            } else {
                throw new IllegalArgumentException(
                        "Ungültiges X.509 Zertifikat - Unterstützter Schlüsseltyp fehlt.");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Ungültiges X.509 Zertifikat!", e);
        }
    }

    // Find EdDSA-Curve
    private static NamedEcGroup detectEdCurveGroup(String algorithm) {
        if (algorithm.equalsIgnoreCase("Ed25519")) {
            return NamedEcGroup.CURVE25519;
        } else if (algorithm.equalsIgnoreCase("Ed448")) {
            return NamedEcGroup.CURVE448;
        }
        return null;
    }
}
