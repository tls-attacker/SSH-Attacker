/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertEcdsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertEcdsaPublicKeyParser
        extends Parser<SshPublicKey<CustomCertEcdsaPublicKey, CustomEcPrivateKey>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    public CertEcdsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomCertEcdsaPublicKey, CustomEcPrivateKey> parse() {
        CustomCertEcdsaPublicKey publicKey = new CustomCertEcdsaPublicKey();

        // Format (string "ecdsa-sha2-nistp256-cert-v01@openssh.com", etc.)
        int formatLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed formatLength: {}", formatLength);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed format: {}", format);
        publicKey.setCertFormat(format);

        if (!format.startsWith("ecdsa-sha2-")) {
            LOGGER.warn("Unexpected format '{}', expected ecdsa-sha2-*", format);
        }

        // Nonce
        int nonceLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed nonceLength: {}", nonceLength);
        byte[] nonce = parseByteArrayField(nonceLength);
        LOGGER.debug("Parsed nonce: {}", () -> ArrayConverter.bytesToRawHexString(nonce));
        publicKey.setNonce(nonce);

        // Curve
        int curveIdentifierLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String curveIdentifier = parseByteString(curveIdentifierLength, StandardCharsets.US_ASCII);
        NamedEcGroup group = NamedEcGroup.fromIdentifier(curveIdentifier);
        publicKey.setGroup(group);
        LOGGER.debug("Parsed curve: {}", curveIdentifier);

        // Public Key
        int publicKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        Point publicKeyPoint =
                PointFormatter.formatFromByteArray(group, parseByteArrayField(publicKeyLength));
        publicKey.setW(publicKeyPoint);
        LOGGER.debug("Parsed publicKey: {}", publicKeyPoint);

        // Serial
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

        LinkedList<String> validPrincipals = new LinkedList<>();
        int bytesProcessed = 0;
        while (bytesProcessed < totalPrincipalLength) {
            int principalLength = parseIntField(DataFormatConstants.UINT32_SIZE);
            if (principalLength > 0) {
                String principal = parseByteString(principalLength, StandardCharsets.US_ASCII);
                validPrincipals.add(principal);
            }
            bytesProcessed += principalLength + DataFormatConstants.UINT32_SIZE;
        }

        String[] parsedPrincipals = validPrincipals.toArray(new String[0]);
        LOGGER.debug("Parsed principals: {}", () -> Arrays.toString(parsedPrincipals));
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

        HashMap<String, String> criticalOptionsMap = new HashMap<>();
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
        publicKey.setCriticalOptions(criticalOptionsMap);

        // Extensions (parsing extensions as a map of key-value pairs)
        int extensionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed extensionsLength: {}", extensionsLength);

        HashMap<String, String> extensionsMap = new HashMap<>();
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
        publicKey.setExtensions(extensionsMap);

        // Reserved
        int reservedLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] reservedBytes = parseByteArrayField(reservedLength);
        String reserved = new String(reservedBytes, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed reserved: {}", reserved);
        publicKey.setReserved(reserved);

        // Signature Key
        int signatureKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed signatureKeyLength: {}", signatureKeyLength);
        byte[] signatureKey = parseByteArrayField(signatureKeyLength);
        LOGGER.debug(
                "Parsed signatureKey: {}", () -> ArrayConverter.bytesToRawHexString(signatureKey));
        publicKey.setSignatureKey(signatureKey);

        // Signature
        int signatureLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed signatureLength: {}", signatureLength);
        byte[] signature = parseByteArrayField(signatureLength);
        LOGGER.debug("Parsed signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
        publicKey.setSignature(signature);

        LOGGER.debug("Successfully parsed the ECDSA certificate public key.");

        return new SshPublicKey<>(PublicKeyFormat.fromName(format), publicKey);
    }
}
