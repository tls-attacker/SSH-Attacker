/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertDsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertDsaPublicKeyParser
        extends Parser<SshPublicKey<CustomCertDsaPublicKey, CustomDsaPrivateKey>> {

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    private static final Logger LOGGER = LogManager.getLogger();

    public CertDsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomCertDsaPublicKey, CustomDsaPrivateKey> parse() {
        CustomCertDsaPublicKey publicKey = new CustomCertDsaPublicKey();

        // Format (string "ssh-dss-cert-v01@openssh.com")
        int formatLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed formatLength: {}", formatLength);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed format: {}", format);

        if (!format.equals(PublicKeyFormat.SSH_DSS_CERT_V01_OPENSSH_COM.getName())) {
            LOGGER.warn(
                    "Unexpected public key format '{}'. Parsing may not yield expected results.",
                    format);
        }

        // Nonce (string nonce)
        int nonceLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed nonceLength: {}", nonceLength);
        byte[] nonce = parseByteArrayField(nonceLength);
        LOGGER.debug("Parsed nonce: {}", Arrays.toString(nonce));
        publicKey.setNonce(nonce);

        // p (mpint p)
        int pLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed pLength: {}", pLength);
        publicKey.setP(parseBigIntField(pLength));
        LOGGER.debug("Parsed p: {}", publicKey.getP());

        // q (mpint q)
        int qLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed qLength: {}", qLength);
        publicKey.setQ(parseBigIntField(qLength));
        LOGGER.debug("Parsed q: {}", publicKey.getQ());

        // g (mpint g)
        int gLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed gLength: {}", gLength);
        publicKey.setG(parseBigIntField(gLength));
        LOGGER.debug("Parsed g: {}", publicKey.getG());

        // y (mpint y)
        int yLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed yLength: {}", yLength);
        publicKey.setY(parseBigIntField(yLength));
        LOGGER.debug("Parsed y: {}", publicKey.getY());

        // Serial (uint64 serial)
        long serial = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        LOGGER.debug("Parsed serial: {}", serial);
        publicKey.setSerial(serial);

        // Type (uint32 type)
        int certType = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed certType: {}", certType);
        publicKey.setCertType(String.valueOf(certType));

        // Key ID (string key id)
        int keyIdLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed keyIdLength: {}", keyIdLength);
        String keyId = parseByteString(keyIdLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed keyId: {}", keyId);
        publicKey.setKeyId(keyId);

        // Principals (string valid principals)
        int totalPrincipalLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed total principal length: {}", totalPrincipalLength);

        String[] validPrincipals = new String[totalPrincipalLength];
        int bytesProcessed = 0;
        int principalIndex = 0;
        while (bytesProcessed < totalPrincipalLength) {
            int principalLength = parseIntField(DataFormatConstants.UINT32_SIZE);
            if (principalLength > 0) {
                String principal = parseByteString(principalLength, StandardCharsets.US_ASCII);
                validPrincipals[principalIndex++] = principal;
            }
            bytesProcessed += principalLength + DataFormatConstants.UINT32_SIZE;
        }

        // Nur die tatsächlich gesetzten Principals weitergeben
        String[] parsedPrincipals = Arrays.copyOf(validPrincipals, principalIndex);
        LOGGER.debug("Parsed principals: {}", Arrays.toString(parsedPrincipals));
        publicKey.setValidPrincipals(parsedPrincipals);

        // Validity period (uint64 valid after)
        long validFrom = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validFromDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validFrom));
        LOGGER.debug("Parsed validFrom: {} (Date: {})", validFrom, validFromDate);
        publicKey.setValidAfter(validFrom);

        // Validity period (uint64 valid before)
        long validTo = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validToDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validTo));
        LOGGER.debug("Parsed validTo: {} (Date: {})", validTo, validToDate);
        publicKey.setValidBefore(validTo);

        // Critical Options (parsing critical options as a map of key-value pairs)
        int criticalOptionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed criticalOptionsLength: {}", criticalOptionsLength);

        Map<String, String> criticalOptionsMap = new HashMap<>();
        if (criticalOptionsLength > 0) {
            int bytesParsed = 0;
            while (bytesParsed < criticalOptionsLength) {
                int optionNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
                String optionName = parseByteString(optionNameLength, StandardCharsets.US_ASCII);
                int optionValueLength = parseIntField(DataFormatConstants.UINT32_SIZE);
                String optionValue = parseByteString(optionValueLength, StandardCharsets.US_ASCII);
                criticalOptionsMap.put(optionName, optionValue);
                LOGGER.debug("Parsed critical option: {}   {}", optionName, optionValue);
                bytesParsed +=
                        optionNameLength
                                + optionValueLength
                                + (2 * DataFormatConstants.UINT32_SIZE);
            }
        }
        publicKey.setCriticalOptions(criticalOptionsMap); // Setze Critical Options

        // Extensions (parsing extensions as a map of key-value pairs)
        int extensionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed extensionsLength: {}", extensionsLength);

        Map<String, String> extensionsMap = new HashMap<>();
        if (extensionsLength > 0) {
            int bytesParsed = 0;
            while (bytesParsed < extensionsLength) {
                int extensionNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
                String extensionName =
                        parseByteString(extensionNameLength, StandardCharsets.US_ASCII);
                int extensionValueLength = parseIntField(DataFormatConstants.UINT32_SIZE);
                String extensionValue =
                        parseByteString(extensionValueLength, StandardCharsets.US_ASCII);
                extensionsMap.put(extensionName, extensionValue);
                LOGGER.debug("Parsed extension: {}   {}", extensionName, extensionValue);
                bytesParsed +=
                        extensionNameLength
                                + extensionValueLength
                                + (2 * DataFormatConstants.UINT32_SIZE);
            }
        }
        publicKey.setExtensions(extensionsMap); // Setze Extensions

        // Reserved (string reserved)
        int reservedLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] reserved = parseByteArrayField(reservedLength);
        LOGGER.debug("Parsed reserved: {}", reserved);

        // Signature Key (string signature key)
        int signatureKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed signatureKeyLength: {}", signatureKeyLength);
        byte[] signatureKey = parseByteArrayField(signatureKeyLength);
        LOGGER.debug("Parsed signatureKey: {}", Arrays.toString(signatureKey));
        publicKey.setSignatureKey(signatureKey);

        // Signature (string signature)
        int signatureLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed signatureLength: {}", signatureLength);
        byte[] signature = parseByteArrayField(signatureLength);
        LOGGER.debug("Parsed signature: {}", Arrays.toString(signature));
        publicKey.setSignature(signature);

        LOGGER.debug("Successfully parsed the DSA Certificate Public Key.");

        return new SshPublicKey<>(PublicKeyFormat.SSH_DSS_CERT_V01_OPENSSH_COM, publicKey);
    }
}
