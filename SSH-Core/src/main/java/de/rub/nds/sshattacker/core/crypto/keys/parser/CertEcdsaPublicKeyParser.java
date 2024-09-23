/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertEcdsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class CertEcdsaPublicKeyParser extends Parser<SshPublicKey<CustomCertEcdsaPublicKey, CustomEcPrivateKey>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter
            .ofLocalizedDateTime(FormatStyle.MEDIUM)
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
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed format: {}", format);

        if (!format.startsWith("ecdsa-sha2-")) {
            LOGGER.warn("Unexpected format '{}', expected ecdsa-sha2-*", format);
        }

        // Nonce
        int nonceLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] nonce = parseByteArrayField(nonceLength);
        publicKey.setNonce(nonce);
        LOGGER.debug("Parsed nonce: {}", nonce);

        // Curve
        int curveIdentifierLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String curveIdentifier = parseByteString(curveIdentifierLength, StandardCharsets.US_ASCII);
        NamedEcGroup group = NamedEcGroup.fromIdentifier(curveIdentifier);
        publicKey.setGroup(group);
        publicKey.setCurveName(group.getIdentifier());
        LOGGER.debug("Parsed curve: {}", curveIdentifier);

        // Public Key
        int publicKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        Point publicKeyPoint = PointFormatter.formatFromByteArray(group, parseByteArrayField(publicKeyLength));
        publicKey.setPublicKey(publicKeyPoint);
        LOGGER.debug("Parsed publicKey: {}", publicKeyPoint);

        // Serial
        long serial = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        publicKey.setSerial(serial);
        LOGGER.debug("Parsed serial: {}", serial);

        // Certificate Type
        int certType = parseIntField(DataFormatConstants.UINT32_SIZE);
        publicKey.setCertType(String.valueOf(certType));
        LOGGER.debug("Parsed certType: {}", certType);

        // Key ID
        int keyIdLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String keyId = parseByteString(keyIdLength, StandardCharsets.US_ASCII);
        publicKey.setKeyId(keyId);
        LOGGER.debug("Parsed keyId: {}", keyId);

        // Valid Principals
        int totalPrincipalLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed total principal length: {}", totalPrincipalLength);

        String[] validPrincipals = new String[totalPrincipalLength];
        int bytesProcessed = 0;
        int principalIndex = 0;
        while (bytesProcessed < totalPrincipalLength) {
            int principalLength = parseIntField(DataFormatConstants.UINT32_SIZE);
            String principal = parseByteString(principalLength, StandardCharsets.US_ASCII);
            LOGGER.debug("Parsed principal: {}", principal);
            validPrincipals[principalIndex++] = principal;
            bytesProcessed += principalLength + DataFormatConstants.UINT32_SIZE;
        }
        publicKey.setValidPrincipals(validPrincipals);

        // Valid After
        long validAfter = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validAfterDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validAfter));
        publicKey.setValidAfter(validAfter);
        LOGGER.debug("Parsed validAfter: {} (Date: {})", validAfter, validAfterDate);

        // Valid Before
        long validBefore = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validBeforeDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validBefore));
        publicKey.setValidBefore(validBefore);
        LOGGER.debug("Parsed validBefore: {} (Date: {})", validBefore, validBeforeDate);

        // Critical Options
        int criticalOptionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        Map<String, String> criticalOptionsMap = parseOptions(criticalOptionsLength);
        publicKey.setCriticalOptions(criticalOptionsMap);
        LOGGER.debug("Parsed critical options: {}", criticalOptionsMap);

        // Extensions
        int extensionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        Map<String, String> extensionsMap = parseOptions(extensionsLength);
        publicKey.setExtensions(extensionsMap);
        LOGGER.debug("Parsed extensions: {}", extensionsMap);

        // Reserved
        int reservedLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] reserved = parseByteArrayField(reservedLength);
        LOGGER.debug("Parsed reserved: {}", reserved);

        // Signature Key
        int signatureKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] signatureKey = parseByteArrayField(signatureKeyLength);
        publicKey.setSignatureKey(signatureKey);
        LOGGER.debug("Parsed signatureKey: {}", signatureKey);

        // Signature
        int signatureLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] signature = parseByteArrayField(signatureLength);
        publicKey.setSignature(signature);
        LOGGER.debug("Parsed signature: {}", signature);

        LOGGER.debug("Successfully parsed the ECDSA certificate public key.");

        return new SshPublicKey<>(PublicKeyFormat.fromName(format), publicKey);
    }

    private Map<String, String> parseOptions(int length) {
        Map<String, String> options = new HashMap<>();
        if (length > 0) {
            int bytesParsed = 0;
            while (bytesParsed < length) {
                int optionNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
                String optionName = parseByteString(optionNameLength, StandardCharsets.US_ASCII);
                int optionValueLength = parseIntField(DataFormatConstants.UINT32_SIZE);
                String optionValue = parseByteString(optionValueLength, StandardCharsets.US_ASCII);
                options.put(optionName, optionValue);
                bytesParsed += optionNameLength + optionValueLength + (2 * DataFormatConstants.UINT32_SIZE);
            }
        }
        return options;
    }
}
