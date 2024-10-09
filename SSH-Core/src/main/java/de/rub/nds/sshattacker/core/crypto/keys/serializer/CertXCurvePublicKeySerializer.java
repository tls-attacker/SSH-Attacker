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
        appendInt(PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM.toString().getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(PublicKeyFormat.SSH_ED25519_CERT_V01_OPENSSH_COM.toString(), StandardCharsets.US_ASCII);

        // 2. Nonce
        byte[] nonce = publicKey.getNonce();
        if (nonce != null) {
            appendInt(nonce.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(nonce);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Fallback for missing nonce
        }

        // 3. Public Key (Corresponds to "pk" in the Ed25519 format)
        byte[] publicKeyBytes = publicKey.getPublicKey();
        if (publicKeyBytes != null) {
            appendInt(publicKeyBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(publicKeyBytes);
        } else {
            throw new IllegalStateException("Public Key is not set in the publicKey object");
        }

        // 4. Serial (uint64) - Convert long to BigInteger
        appendBigInteger(BigInteger.valueOf(publicKey.getSerial()), DataFormatConstants.UINT64_SIZE);

        // 5. Certificate type (uint32)
        appendInt(Integer.parseInt(publicKey.getCertType()), DataFormatConstants.UINT32_SIZE);

        // 6. Key ID (string)
        String keyId = publicKey.getKeyId();
        if (keyId != null) {
            appendInt(keyId.getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendString(keyId, StandardCharsets.US_ASCII);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Fallback for missing Key ID
        }

        // 7. Valid Principals (string list)
        String[] validPrincipals = publicKey.getValidPrincipals();
        if (validPrincipals != null && validPrincipals.length > 0) {
            // Create a buffer large enough to hold all principals, grow dynamically if needed
            ByteBuffer principalsBuffer = ByteBuffer.allocate(1024); // Start with a reasonable size
            for (String principal : validPrincipals) {
                if (principal != null) {
                    byte[] principalBytes = principal.getBytes(StandardCharsets.US_ASCII);
                    principalsBuffer.putInt(principalBytes.length);  // Append length of principal
                    principalsBuffer.put(principalBytes);            // Append principal itself
                }
            }
            // Extract the serialized principals and append them to the final output
            byte[] principalsSerialized = new byte[principalsBuffer.position()];
            principalsBuffer.flip();
            principalsBuffer.get(principalsSerialized);

            appendInt(principalsSerialized.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(principalsSerialized);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // No valid principals
        }

        // 8. Valid After (uint64) - Convert long to BigInteger
        appendBigInteger(BigInteger.valueOf(publicKey.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // 9. Valid Before (uint64) - Convert long to BigInteger
        appendBigInteger(BigInteger.valueOf(publicKey.getValidBefore()), DataFormatConstants.UINT64_SIZE);

        // 10. Critical Options
        Map<String, String> criticalOptions = publicKey.getCriticalOptions();
        appendStringMap(criticalOptions);

        // 11. Extensions
        Map<String, String> extensions = publicKey.getExtensions();
        appendStringMap(extensions);

        // 12. Reserved
        String reserved = publicKey.getReserved();
        if (reserved != null) {
            byte[] reservedBytes = reserved.getBytes(StandardCharsets.US_ASCII);
            appendInt(reservedBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(reservedBytes);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // No reserved field
        }

        // 13. Signature Key (The public key used to sign this certificate)
        byte[] signatureKey = publicKey.getSignatureKey();
        if (signatureKey != null) {
            appendInt(signatureKey.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(signatureKey);
        } else {
            throw new IllegalStateException("Signature Key is not set in the publicKey");
        }

        // 14. Signature (The actual signature on the certificate)
        byte[] signature = publicKey.getSignature();
        if (signature != null) {
            appendInt(signature.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(signature);
        } else {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
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
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Empty field if map is empty
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
