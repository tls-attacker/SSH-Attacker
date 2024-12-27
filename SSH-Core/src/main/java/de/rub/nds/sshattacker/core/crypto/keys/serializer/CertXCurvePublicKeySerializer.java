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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
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

    private static final Logger LOGGER = LogManager.getLogger(CertXCurvePublicKeySerializer.class);

    @Override
    protected void serializeBytes(CustomCertXCurvePublicKey object, SerializerStream output) {
        LOGGER.debug("Starting serialization of CertXCurvePublicKey.");

        /*
         * The ssh-ed25519-cert-v01@openssh.com format:
         * string    "ssh-ed25519-cert-v01@openssh.com"
         * string    nonce
         * string    pk
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */

        // 1. Format identifier (ssh-ed25519-cert-v01@openssh.com)
        output.appendInt(
                PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM
                        .toString()
                        .getBytes(StandardCharsets.US_ASCII)
                        .length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString(
                PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM.toString(),
                StandardCharsets.US_ASCII);

        // 2. Nonce
        byte[] nonce = object.getNonce();
        if (nonce != null) {
            output.appendInt(nonce.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(nonce);
        } else {
            output.appendInt(
                    0, DataFormatConstants.STRING_SIZE_LENGTH); // Fallback for missing nonce
        }

        // 3. Public Key (Corresponds to "pk" in the Ed25519 format)
        byte[] publicKeyBytes = object.getCoordinate();
        if (publicKeyBytes != null) {
            output.appendInt(publicKeyBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(publicKeyBytes);
        } else {
            throw new IllegalStateException("Public Key is not set in the publicKey object");
        }

        // 4. Serial (uint64) - Convert long to BigInteger
        output.appendBigInteger(
                BigInteger.valueOf(object.getSerial()), DataFormatConstants.UINT64_SIZE);

        // 5. Certificate type (uint32)
        output.appendInt(Integer.parseInt(object.getCertType()), DataFormatConstants.UINT32_SIZE);

        // 6. Key ID (string)
        String keyId = object.getKeyId();
        if (keyId != null) {
            output.appendInt(
                    keyId.getBytes(StandardCharsets.US_ASCII).length,
                    DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendString(keyId, StandardCharsets.US_ASCII);
        } else {
            output.appendInt(
                    0, DataFormatConstants.STRING_SIZE_LENGTH); // Fallback for missing Key ID
        }

        // 7. Valid Principals (string list)
        String[] validPrincipals = object.getValidPrincipals();
        if (validPrincipals != null && validPrincipals.length > 0) {
            // Create a buffer large enough to hold all principals, grow dynamically if needed
            ByteBuffer principalsBuffer = ByteBuffer.allocate(1024); // Start with a reasonable size
            for (String principal : validPrincipals) {
                if (principal != null) {
                    byte[] principalBytes = principal.getBytes(StandardCharsets.US_ASCII);
                    principalsBuffer.putInt(principalBytes.length); // Append length of principal
                    principalsBuffer.put(principalBytes); // Append principal itself
                }
            }
            // Extract the serialized principals and append them to the final output
            byte[] principalsSerialized = new byte[principalsBuffer.position()];
            principalsBuffer.flip();
            principalsBuffer.get(principalsSerialized);

            output.appendInt(principalsSerialized.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(principalsSerialized);
        } else {
            output.appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // No valid principals
        }

        // 8. Valid After (uint64) - Convert long to BigInteger
        output.appendBigInteger(
                BigInteger.valueOf(object.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // 9. Valid Before (uint64) - Convert long to BigInteger
        output.appendBigInteger(
                BigInteger.valueOf(object.getValidBefore()), DataFormatConstants.UINT64_SIZE);

        // 10. Critical Options
        Map<String, String> criticalOptions = object.getCriticalOptions();
        appendStringMap(criticalOptions, output);

        // 11. Extensions
        Map<String, String> extensions = object.getExtensions();
        appendStringMap(extensions, output);

        // 12. Reserved
        String reserved = object.getReserved();
        if (reserved != null) {
            byte[] reservedBytes = reserved.getBytes(StandardCharsets.US_ASCII);
            output.appendInt(reservedBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(reservedBytes);
        } else {
            output.appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // No reserved field
        }

        // 13. Signature Key (The public key used to sign this certificate)
        byte[] signatureKey = object.getSignatureKey();
        if (signatureKey != null) {
            output.appendInt(signatureKey.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(signatureKey);
        } else {
            throw new IllegalStateException("Signature Key is not set in the publicKey");
        }

        // 14. Signature (The actual signature on the certificate)
        byte[] signature = object.getSignature();
        if (signature != null) {
            output.appendInt(signature.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(signature);
        } else {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
    }

    private static void appendStringMap(Map<String, String> stringMap, SerializerStream output) {
        if (stringMap != null && !stringMap.isEmpty()) {
            StringBuilder optionsBuilder = new StringBuilder();
            for (Map.Entry<String, String> entry : stringMap.entrySet()) {
                optionsBuilder.append(serializeString(entry.getKey()));
                optionsBuilder.append(serializeString(entry.getValue()));
            }
            byte[] optionsBytes = optionsBuilder.toString().getBytes(StandardCharsets.US_ASCII);
            output.appendInt(optionsBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(optionsBytes);
        } else {
            output.appendInt(
                    0, DataFormatConstants.STRING_SIZE_LENGTH); // Empty field if map is empty
        }
    }

    private static String serializeString(String value) {
        byte[] valueBytes = value.getBytes(StandardCharsets.US_ASCII);
        return buildStringWithLength(valueBytes);
    }

    private static String buildStringWithLength(byte[] valueBytes) {
        return new String(
                        ByteBuffer.allocate(DataFormatConstants.STRING_SIZE_LENGTH)
                                .putInt(valueBytes.length)
                                .array())
                + new String(valueBytes, StandardCharsets.US_ASCII);
    }
}
