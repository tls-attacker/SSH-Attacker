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
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertRsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.nio.ByteBuffer;

/**
 * Serializer class to encode an RSA certificate public key (ssh-rsa-cert-v01@openssh.com) format.
 */
public class CertRsaPublicKeySerializer extends Serializer<CustomCertRsaPublicKey> {

    private final CustomCertRsaPublicKey publicKey;

    public CertRsaPublicKeySerializer(CustomCertRsaPublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        /*
         * The ssh-rsa-cert-v01@openssh.com format as specified in the SSH protocol:
         *   string    "ssh-rsa-cert-v01@openssh.com"
         *   string    nonce
         *   mpint     e
         *   mpint     n
         *   uint64    serial
         *   uint32    type
         *   string    key id
         *   string    valid principals
         *   uint64    valid after
         *   uint64    valid before
         *   string    critical options
         *   string    extensions
         *   string    reserved
         *   string    signature key
         *   string    signature
         */

        // Format identifier (ssh-rsa-cert-v01@openssh.com)
        appendInt(PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM.toString().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM.toString(), StandardCharsets.US_ASCII);

        // Nonce
        byte[] nonce = publicKey.getNonce();
        appendInt(nonce.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(nonce);

        // Public Exponent (e)
        byte[] encodedExponent = publicKey.getPublicExponent().toByteArray();
        appendInt(encodedExponent.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedExponent);

        // Modulus (n)
        byte[] encodedModulus = publicKey.getModulus().toByteArray();
        appendInt(encodedModulus.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedModulus);

        // Serial (uint64) -- using BigInteger instead of long
        appendBigInteger(BigInteger.valueOf(publicKey.getSerial()), DataFormatConstants.UINT64_SIZE);

        // Certificate type (uint32)
        appendInt(Integer.parseInt(publicKey.getCertType()), DataFormatConstants.UINT32_SIZE);

        // Key ID (string)
        String keyId = publicKey.getKeyId();
        appendInt(keyId.getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(keyId, StandardCharsets.US_ASCII);

        // Valid Principals (string list)
        String[] validPrincipals = publicKey.getValidPrincipals();
        if (validPrincipals != null && validPrincipals.length > 0) {
            // Append each principal as separate SSH strings, according to SSH format expectations
            ByteBuffer principalsBuffer = ByteBuffer.allocate(1024); // Initial buffer size; grows dynamically if needed
            for (String principal : validPrincipals) {
                byte[] principalBytes = principal.getBytes(StandardCharsets.US_ASCII);
                // Serialize each principal with length prefix
                principalsBuffer.putInt(principalBytes.length);
                principalsBuffer.put(principalBytes);
            }
            byte[] principalsSerialized = new byte[principalsBuffer.position()];
            principalsBuffer.flip();
            principalsBuffer.get(principalsSerialized);

            appendInt(principalsSerialized.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(principalsSerialized);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Empty principals list
        }

        // Valid After (uint64) -- using BigInteger instead of long
        appendBigInteger(BigInteger.valueOf(publicKey.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // Valid Before (uint64) -- using BigInteger instead of long
        appendBigInteger(BigInteger.valueOf(publicKey.getValidBefore()), DataFormatConstants.UINT64_SIZE);

        // Critical Options
        Map<String, String> criticalOptions = publicKey.getCriticalOptions();
        appendStringMap(criticalOptions);

        // Extensions
        Map<String, String> extensions = publicKey.getExtensions();
        appendStringMap(extensions);

        // Reserved (Assuming reserved field is empty)
        String reserved = publicKey.getReserved();
        if (reserved != null) {
            byte[] reservedBytes = reserved.getBytes(StandardCharsets.US_ASCII);
            appendInt(reservedBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(reservedBytes);
        } else {
            // Assuming no reserved data, add an empty string field
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);
        }

        // Signature Key (The public key used to sign this certificate)
        byte[] signatureKey = publicKey.getSignatureKey();
        if (signatureKey == null) {
            throw new IllegalStateException("Signature Key is not set in the publicKey");
        }
        appendInt(signatureKey.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(signatureKey);

        // Signature (The actual signature on the certificate)
        byte[] signature = publicKey.getSignature();
        if (signature == null) {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
        appendInt(signature.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(signature);

    }

    private void appendStringMap(Map<String, String> stringMap) {
        if (stringMap != null && !stringMap.isEmpty()) {
            StringBuilder optionsBuilder = new StringBuilder();
            for (Map.Entry<String, String> entry : stringMap.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                optionsBuilder.append(serializeString(key));
                optionsBuilder.append(serializeString(value));
            }
            byte[] optionsBytes = optionsBuilder.toString().getBytes(StandardCharsets.US_ASCII);
            appendInt(optionsBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(optionsBytes);
        } else {
            // Empty options
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);
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