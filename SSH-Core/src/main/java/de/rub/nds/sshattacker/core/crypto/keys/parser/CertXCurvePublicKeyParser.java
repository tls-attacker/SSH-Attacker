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
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertXCurvePublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class CertXCurvePublicKeyParser extends Parser<SshPublicKey<CustomCertXCurvePublicKey, ?>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    public CertXCurvePublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomCertXCurvePublicKey, ?> parse() {
        CustomCertXCurvePublicKey publicKey = new CustomCertXCurvePublicKey();

        // Format (ssh-ed25519-cert-v01@openssh.com)
        int formatLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed format: {}", format);

        // Check format for Ed25519 certificate
        NamedEcGroup group;
        if (format.equals(PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM.getName())) {
            group = NamedEcGroup.CURVE25519;
        } else {
            throw new IllegalArgumentException("Unsupported key format: " + format);
        }
        publicKey.setGroup(group);

        // Nonce
        int nonceLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] nonce = parseByteArrayField(nonceLength);
        publicKey.setNonce(nonce);
        LOGGER.debug("Parsed nonce: {}", Arrays.toString(nonce));

        // Public Key (pk)
        int publicKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] publicKeyBytes = parseByteArrayField(publicKeyLength);
        publicKey.setPublicKey(publicKeyBytes);
        LOGGER.debug("Parsed publicKey: {}", Arrays.toString(publicKeyBytes));

        // Serial
        long serial = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        publicKey.setSerial(serial);
        LOGGER.debug("Parsed serial: {}", serial);

        // Certificate Type (host or user)
        int certType = parseIntField(DataFormatConstants.UINT32_SIZE);
        publicKey.setCertType(String.valueOf(certType));
        LOGGER.debug("Parsed certType: {}", certType);

        // Key ID
        int keyIdLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String keyId = parseByteString(keyIdLength, StandardCharsets.US_ASCII);
        publicKey.setKeyId(keyId);
        LOGGER.debug("Parsed keyId: {}", keyId);

        // Principals (string valid principals)
        int totalPrincipalLength = parseIntField(DataFormatConstants.UINT32_SIZE);
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

        // Validity period (uint64 valid after)
        long validAfter = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validAfterDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validAfter));
        publicKey.setValidAfter(validAfter);
        LOGGER.debug("Parsed validAfter: {} (Date: {})", validAfter, validAfterDate);

        // Validity period (uint64 valid before)
        long validBefore = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validBeforeDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validBefore));
        publicKey.setValidBefore(validBefore);
        LOGGER.debug("Parsed validBefore: {} (Date: {})", validBefore, validBeforeDate);

        // Critical Options (since none are specified in the certificate, leave empty)
        int criticalOptionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        if (criticalOptionsLength > 0) {
            Map<String, String> criticalOptionsMap = parseOptions(criticalOptionsLength);
            publicKey.setCriticalOptions(criticalOptionsMap);
            LOGGER.debug("Parsed critical options: {}", criticalOptionsMap);
        }

        // Extensions (since none are specified in the certificate, leave empty)
        int extensionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        if (extensionsLength > 0) {
            Map<String, String> extensionsMap = parseOptions(extensionsLength);
            publicKey.setExtensions(extensionsMap);
            LOGGER.debug("Parsed extensions: {}", extensionsMap);
        }

        // Signature Key (could be missing, make sure to check)
        int signatureKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] signatureKey = parseByteArrayField(signatureKeyLength);
        publicKey.setSignatureKey(signatureKey);
        LOGGER.debug("Parsed signatureKey: {}", Arrays.toString(signatureKey));

        // Signature
        int signatureLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] signature = parseByteArrayField(signatureLength);
        publicKey.setSignature(signature);
        LOGGER.debug("Parsed signature: {}", Arrays.toString(signature));

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
