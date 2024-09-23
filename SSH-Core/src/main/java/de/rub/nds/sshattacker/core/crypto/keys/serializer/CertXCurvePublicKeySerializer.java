/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertXCurvePublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Serializer class to encode an ED25519 certificate public key (ssh-ed25519-cert-v01@openssh.com).
 */
public class CertXCurvePublicKeySerializer extends Serializer<CustomCertXCurvePublicKey> {

    private final CustomCertXCurvePublicKey publicKey;
    private static final Logger LOGGER = LogManager.getLogger(CertXCurvePublicKeySerializer.class);

    public CertXCurvePublicKeySerializer(CustomCertXCurvePublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        LOGGER.debug("Starting serialization of CertXCurvePublicKey.");

        // Format identifier (ssh-ed25519-cert-v01@openssh.com)
        appendInt(PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM.toString().getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM.toString(), StandardCharsets.US_ASCII);

        // Nonce
        byte[] nonce = publicKey.getNonce();
        appendInt(nonce.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(nonce);

        // Public Key
        byte[] publicKeyBytes = publicKey.getPublicKey();
        appendInt(publicKeyBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(publicKeyBytes);

        // Serial (uint64)
        appendBigInteger(BigInteger.valueOf(publicKey.getSerial()), DataFormatConstants.UINT64_SIZE);

        // Certificate type (uint32)
        appendInt(Integer.parseInt(publicKey.getCertType()), DataFormatConstants.UINT32_SIZE);

        // Key ID (string)
        String keyId = publicKey.getKeyId();
        appendInt(keyId.getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(keyId, StandardCharsets.US_ASCII);

        // Principals (string list)
        String[] validPrincipals = publicKey.getValidPrincipals();
        if (validPrincipals != null) {
            StringBuilder principalsBuilder = new StringBuilder();
            for (String principal : validPrincipals) {
                principalsBuilder.append(principal).append('\0');  // Null-terminated list
            }
            String principalsString = principalsBuilder.toString();
            appendInt(principalsString.length(), DataFormatConstants.STRING_SIZE_LENGTH);
            appendString(principalsString, StandardCharsets.US_ASCII);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);  // Empty principals list
        }

        // Valid After (uint64) - Convert long to BigInteger
        appendBigInteger(BigInteger.valueOf(publicKey.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // Valid Before (uint64) - Convert long to BigInteger
        appendBigInteger(BigInteger.valueOf(publicKey.getValidBefore()), DataFormatConstants.UINT64_SIZE);

        // Critical Options
        Map<String, String> criticalOptions = publicKey.getCriticalOptions();
        appendStringMap(criticalOptions);

        // Extensions
        Map<String, String> extensions = publicKey.getExtensions();
        appendStringMap(extensions);

        // Signature Key
        byte[] signatureKey = publicKey.getSignatureKey();
        appendInt(signatureKey.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(signatureKey);

        // Signature
        byte[] signature = publicKey.getSignature();
        appendInt(signature.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(signature);
    }

    private void appendStringMap(Map<String, String> stringMap) {
        if (stringMap != null && !stringMap.isEmpty()) {
            StringBuilder optionsBuilder = new StringBuilder();
            for (Map.Entry<String, String> entry : stringMap.entrySet()) {
                optionsBuilder.append(serializeString(entry.getKey()));
                optionsBuilder.append(serializeString(entry.getValue()));
            }
            byte[] optionsBytes = optionsBuilder.toString().getBytes(StandardCharsets.US_ASCII);
            appendInt(optionsBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(optionsBytes);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Leeres Feld, wenn die Map leer ist
        }
    }
    private static String serializeString(String value) {
        byte[] valueBytes = value.getBytes(StandardCharsets.US_ASCII);
        return buildStringWithLength(valueBytes);
    }
    private static String buildStringWithLength(byte[] valueBytes) {
        return new String(ByteBuffer.allocate(DataFormatConstants.STRING_SIZE_LENGTH).putInt(valueBytes.length).array())
                + new String(valueBytes, StandardCharsets.US_ASCII);
    }
}
