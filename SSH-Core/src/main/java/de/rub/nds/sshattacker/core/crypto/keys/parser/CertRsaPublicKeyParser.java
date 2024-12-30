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
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
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

public class CertRsaPublicKeyParser
        extends Parser<SshPublicKey<CustomCertRsaPublicKey, CustomRsaPrivateKey>> {
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    public CertRsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public SshPublicKey<CustomCertRsaPublicKey, CustomRsaPrivateKey> parse() {
        CustomCertRsaPublicKey publicKey = new CustomCertRsaPublicKey();

        // Format (string "ssh-rsa-cert-v01@openssh.com")
        int formatLength = parseIntField();
        LOGGER.debug("Parsed formatLength: {}", formatLength);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed format: {}", format);
        publicKey.setCertFormat(format);

        if (!format.equals(PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM.getName())) {
            LOGGER.warn(
                    "Unexpected public key format '{}'. Parsing may not yield expected results.",
                    format);
        }

        // Nonce (string nonce)
        int nonceLength = parseIntField();
        LOGGER.debug("Parsed nonceLength: {}", nonceLength);
        byte[] nonce = parseByteArrayField(nonceLength);
        LOGGER.debug("Parsed nonce: {}", () -> ArrayConverter.bytesToRawHexString(nonce));
        publicKey.setNonce(nonce);

        // Public Exponent (mpint e)
        int publicExponentLength = parseIntField();
        LOGGER.debug("Parsed publicExponentLength: {}", publicExponentLength);
        publicKey.setPublicExponent(parseBigIntField(publicExponentLength));
        LOGGER.debug("Parsed publicExponent: {}", publicKey.getPublicExponent());

        // Modulus (mpint n)
        int modulusLength = parseIntField();
        LOGGER.debug("Parsed modulusLength: {}", modulusLength);
        publicKey.setModulus(parseBigIntField(modulusLength));
        LOGGER.debug("Parsed modulus: {}", publicKey.getModulus());

        // Serial (uint64 serial)
        long serial = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        LOGGER.debug("Parsed serial: {}", serial);
        publicKey.setSerial(serial); // Setze Serial

        // Type (uint32 type)
        int certType = parseIntField();
        LOGGER.debug("Parsed certType: {}", certType);
        publicKey.setCertType(String.valueOf(certType));

        // Key ID (string key id)
        int keyIdLength = parseIntField();
        LOGGER.debug("Parsed keyIdLength: {}", keyIdLength);
        String keyId = parseByteString(keyIdLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed keyId: {}", keyId);
        publicKey.setKeyId(keyId); // Setze Key ID

        // Principals (string valid principals)
        int totalPrincipalLength = parseIntField();
        LOGGER.debug("Parsed total principal length: {}", totalPrincipalLength);

        LinkedList<String> validPrincipals = new LinkedList<>();
        int bytesProcessed = 0;
        while (bytesProcessed < totalPrincipalLength) {
            int principalLength = parseIntField();
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
        int criticalOptionsLength = parseIntField();
        LOGGER.debug("Parsed criticalOptionsLength: {}", criticalOptionsLength);

        HashMap<String, String> criticalOptionsMap = new HashMap<>();
        if (criticalOptionsLength > 0) {
            int bytesParsed = 0;
            while (bytesParsed < criticalOptionsLength) {
                int optionNameLength = parseIntField();
                String optionName = parseByteString(optionNameLength, StandardCharsets.US_ASCII);
                int optionValueLength = parseIntField();
                String optionValue = parseByteString(optionValueLength, StandardCharsets.US_ASCII);
                criticalOptionsMap.put(optionName, optionValue);
                LOGGER.debug("Parsed critical option: {}   {}", optionName, optionValue);
                bytesParsed +=
                        optionNameLength + optionValueLength + 2 * DataFormatConstants.UINT32_SIZE;
            }
        }
        publicKey.setCriticalOptions(criticalOptionsMap); // Setze Critical Options

        // Extensions (parsing extensions as a map of key-value pairs)
        int extensionsLength = parseIntField();
        LOGGER.debug("Parsed extensionsLength: {}", extensionsLength);

        HashMap<String, String> extensionsMap = new HashMap<>();
        if (extensionsLength > 0) {
            int bytesParsed = 0;
            while (bytesParsed < extensionsLength) {
                int extensionNameLength = parseIntField();
                String extensionName =
                        parseByteString(extensionNameLength, StandardCharsets.US_ASCII);
                int extensionValueLength = parseIntField();
                String extensionValue =
                        parseByteString(extensionValueLength, StandardCharsets.US_ASCII);
                extensionsMap.put(extensionName, extensionValue);
                LOGGER.debug("Parsed extension: {}   {}", extensionName, extensionValue);
                bytesParsed +=
                        extensionNameLength
                                + extensionValueLength
                                + 2 * DataFormatConstants.UINT32_SIZE;
            }
        }
        publicKey.setExtensions(extensionsMap); // Setze Extensions

        // Reserved (string reserved)
        int reservedLength = parseIntField();
        byte[] reservedBytes = parseByteArrayField(reservedLength);
        String reserved = new String(reservedBytes, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed reserved: {}", reserved);
        publicKey.setReserved(reserved);

        // Signature Key (string signature key)
        int signatureKeyLength = parseIntField();
        LOGGER.debug("Parsed signatureKeyLength: {}", signatureKeyLength);
        byte[] signatureKey = parseByteArrayField(signatureKeyLength);
        LOGGER.debug(
                "Parsed signatureKey: {}", () -> ArrayConverter.bytesToRawHexString(signatureKey));
        publicKey.setSignatureKey(signatureKey);

        // Signature (string signature)
        int signatureLength = parseIntField();
        LOGGER.debug("Parsed signatureLength: {}", signatureLength);
        byte[] signature = parseByteArrayField(signatureLength);
        LOGGER.debug("Parsed signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
        publicKey.setSignature(signature);

        LOGGER.debug("Successfully parsed the RSA Certificate Public Key.");

        return new SshPublicKey<>(PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM, publicKey);
    }
}
