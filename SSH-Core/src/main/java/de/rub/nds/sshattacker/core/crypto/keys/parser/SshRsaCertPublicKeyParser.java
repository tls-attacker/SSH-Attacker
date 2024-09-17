package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Locale;
import java.util.Arrays;



import java.nio.charset.StandardCharsets;

public class SshRsaCertPublicKeyParser extends Parser<SshPublicKey<CustomCertRsaPublicKey, CustomRsaPrivateKey>> {
    private final byte[] localArray;
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                    .withLocale(Locale.getDefault())
                    .withZone(ZoneId.systemDefault());

    public SshRsaCertPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
        this.localArray = array;  // Speichere das Array in einer lokalen Variable
    }

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public SshPublicKey<CustomCertRsaPublicKey, CustomRsaPrivateKey> parse() {
        CustomCertRsaPublicKey publicKey = new CustomCertRsaPublicKey();

        // Format (string "ssh-rsa-cert-v01@openssh.com")
        int formatLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed formatLength: {}", formatLength);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed format: {}", format);

        if (!format.equals(PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM.getName())) {
            LOGGER.warn("Unexpected public key format '{}'. Parsing may not yield expected results.", format);
        }

        // Nonce (string nonce)
        int nonceLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed nonceLength: {}", nonceLength);
        byte[] nonce = parseByteArrayField(nonceLength);
        LOGGER.debug("Parsed nonce: {}", Arrays.toString(nonce));
        publicKey.setNonce(nonce);  // Setze Nonce

        // Public Exponent (mpint e)
        int publicExponentLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed publicExponentLength: {}", publicExponentLength);
        publicKey.setPublicExponent(parseBigIntField(publicExponentLength));
        LOGGER.debug("Parsed publicExponent: {}", publicKey.getPublicExponent());

        // Modulus (mpint n)
        int modulusLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed modulusLength: {}", modulusLength);
        publicKey.setModulus(parseBigIntField(modulusLength));
        LOGGER.debug("Parsed modulus: {}", publicKey.getModulus());

        // Serial (uint64 serial)
        long serial = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        LOGGER.debug("Parsed serial: {}", serial);
        publicKey.setSerial(serial);  // Setze Serial

        // Type (uint32 type)
        int certType = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed certType: {}", certType);
        publicKey.setCertType(String.valueOf(certType));

        // Key ID (string key id)
        int keyIdLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed keyIdLength: {}", keyIdLength);
        String keyId = parseByteString(keyIdLength, StandardCharsets.US_ASCII);
        LOGGER.debug("Parsed keyId: {}", keyId);
        publicKey.setKeyId(keyId);  // Setze Key ID

        // Principals (string valid principals)
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
        publicKey.setValidPrincipals(validPrincipals);  // Setze Valid Principals

        // Validity period (uint64 valid after)
        long validFrom = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validFromDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validFrom));
        LOGGER.debug("Parsed validFrom: {} (Date: {})", validFrom, validFromDate);
        publicKey.setValidAfter(validFrom);  // Setze Valid After

        // Validity period (uint64 valid before)
        long validTo = parseBigIntField(DataFormatConstants.UINT64_SIZE).longValue();
        String validToDate = DATE_FORMATTER.format(Instant.ofEpochSecond(validTo));
        LOGGER.debug("Parsed validTo: {} (Date: {})", validTo, validToDate);
        publicKey.setValidBefore(validTo);  // Setze Valid Before

        // Critical Options (string critical options)
        int criticalOptionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed criticalOptionsLength: {}", criticalOptionsLength);

        // Extensions (string extensions)
        int extensionsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Parsed extensionsLength: {}", extensionsLength);
        if (extensionsLength > 0) {
            byte[] extensions = parseByteArrayField(extensionsLength);
            LOGGER.debug("Parsed extensions: {}", extensions);
        }

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
        LOGGER.debug("Parsed signature: {}", signature);
        publicKey.setSignature(signature);  // Setze Signatur

        LOGGER.debug("Successfully parsed the RSA Certificate Public Key.");

        return new SshPublicKey<>(PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM, publicKey);
    }
}


