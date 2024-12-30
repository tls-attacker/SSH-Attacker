/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomX509RsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import jakarta.xml.bind.DatatypeConverter;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509RsaPublicKeyParser
        extends Parser<SshPublicKey<CustomX509RsaPublicKey, CustomRsaPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    public X509RsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomX509RsaPublicKey, CustomRsaPrivateKey> parse() {
        try {
            // Start parsing the certificate dynamically based on the ASN.1 structure
            int startIndex = PublicKeyParserHelper.findX509StartIndex(getArray());

            X509Certificate cert =
                    PublicKeyParserHelper.extractCertificate(getArray(), startIndex, false);
            PublicKey publicKey = cert.getPublicKey();

            if (publicKey instanceof RSAPublicKey) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                byte[] signature = cert.getSignature();
                CustomX509RsaPublicKey customX509RsaPublicKey =
                        new CustomX509RsaPublicKey(rsaPublicKey, signature);

                // Set the parsed values in the CustomX509RsaPublicKey object
                customX509RsaPublicKey.setVersion(cert.getVersion());
                customX509RsaPublicKey.setIssuer(cert.getIssuerDN().getName());
                customX509RsaPublicKey.setSubject(cert.getSubjectDN().getName());
                customX509RsaPublicKey.setSignatureAlgorithm(cert.getSigAlgName());
                customX509RsaPublicKey.setSerial(cert.getSerialNumber().longValue());
                customX509RsaPublicKey.setValidAfter(cert.getNotBefore().getTime());
                customX509RsaPublicKey.setValidBefore(cert.getNotAfter().getTime());
                customX509RsaPublicKey.setPublicKeyAlgorithm(publicKey.getAlgorithm());
                customX509RsaPublicKey.setModulus(rsaPublicKey.getModulus());
                customX509RsaPublicKey.setPublicExponent(rsaPublicKey.getPublicExponent());

                // Output of the parsed elements to the log
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
                LOGGER.debug("Parsed Modulus: {}", rsaPublicKey.getModulus());
                LOGGER.debug("Parsed Public Exponent: {}", rsaPublicKey.getPublicExponent());

                // Output of the X.509 extensions
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
                customX509RsaPublicKey.setExtensions(extensionsMap);

                // Output of CA information, if available
                if (cert.getBasicConstraints() != -1) {
                    LOGGER.debug(
                            "Parsed Certificate is a CA Certificate. Basic Constraints: {}",
                            cert.getBasicConstraints());
                } else {
                    LOGGER.debug("Parsed Certificate is not a CA Certificate.");
                }

                // **Distinguish the key type based on the signature algorithm and the key length**
                String signatureAlgorithm = cert.getSigAlgName();
                int keyLength = rsaPublicKey.getModulus().bitLength();

                if (keyLength == 2048 && "SHA256withRSA".equalsIgnoreCase(signatureAlgorithm)) {
                    LOGGER.debug("Detected x509v3-rsa2048-sha256 certificate.");
                    return new SshPublicKey<>(
                            PublicKeyFormat.X509V3_RSA2048_SHA256, customX509RsaPublicKey);
                } else {
                    LOGGER.debug("Detected x509v3-ssh-rsa certificate.");
                    return new SshPublicKey<>(
                            PublicKeyFormat.X509V3_SSH_RSA, customX509RsaPublicKey);
                }
            } else {
                throw new IllegalArgumentException(
                        "Ungültiges X.509 Zertifikat - Unterstützter Schlüsseltyp fehlt.");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Ungültiges X.509 Zertifikat!", e);
        }
    }
}
