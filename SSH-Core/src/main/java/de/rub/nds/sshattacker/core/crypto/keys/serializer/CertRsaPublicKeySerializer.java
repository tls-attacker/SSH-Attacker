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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Serializer class to encode an RSA certificate public key (ssh-rsa-cert-v01@openssh.com) format.
 */
public class CertRsaPublicKeySerializer extends Serializer<CustomCertRsaPublicKey> {

    @Override
    protected void serializeBytes(CustomCertRsaPublicKey object, SerializerStream output) {
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
        output.appendInt(
                PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM
                        .toString()
                        .getBytes(StandardCharsets.US_ASCII)
                        .length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString(
                PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM.toString(), StandardCharsets.US_ASCII);

        // Nonce
        byte[] nonce = object.getNonce();
        output.appendInt(nonce.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(nonce);

        // Public Exponent (e)
        byte[] encodedExponent = object.getPublicExponent().toByteArray();
        output.appendInt(encodedExponent.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        output.appendBytes(encodedExponent);

        // Modulus (n)
        byte[] encodedModulus = object.getModulus().toByteArray();
        output.appendInt(encodedModulus.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        output.appendBytes(encodedModulus);

        // Serial (uint64) -- using BigInteger instead of long
        output.appendBigInteger(
                BigInteger.valueOf(object.getSerial()), DataFormatConstants.UINT64_SIZE);

        // Certificate type (uint32)
        output.appendInt(Integer.parseInt(object.getCertType()), DataFormatConstants.UINT32_SIZE);

        // Key ID (string)
        String keyId = object.getKeyId();
        output.appendInt(
                keyId.getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString(keyId, StandardCharsets.US_ASCII);

        // Valid Principals (string list)
        String[] validPrincipals = object.getValidPrincipals();
        if (validPrincipals != null && validPrincipals.length > 0) {
            // Append each principal as separate SSH strings, according to SSH format expectations
            ByteBuffer principalsBuffer =
                    ByteBuffer.allocate(1024); // Initial buffer size; grows dynamically if needed
            for (String principal : validPrincipals) {
                byte[] principalBytes = principal.getBytes(StandardCharsets.US_ASCII);
                // Serialize each principal with length prefix
                principalsBuffer.putInt(principalBytes.length);
                principalsBuffer.put(principalBytes);
            }
            byte[] principalsSerialized = new byte[principalsBuffer.position()];
            principalsBuffer.flip();
            principalsBuffer.get(principalsSerialized);

            output.appendInt(principalsSerialized.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(principalsSerialized);
        } else {
            output.appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Empty principals list
        }

        // Valid After (uint64) -- using BigInteger instead of long
        output.appendBigInteger(
                BigInteger.valueOf(object.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // Valid Before (uint64) -- using BigInteger instead of long
        output.appendBigInteger(
                BigInteger.valueOf(object.getValidBefore()), DataFormatConstants.UINT64_SIZE);

        // Critical Options
        Map<String, String> criticalOptions = object.getCriticalOptions();
        PublicKeySerializerHelper.appendStringMap(criticalOptions, output);

        // Extensions
        Map<String, String> extensions = object.getExtensions();
        PublicKeySerializerHelper.appendStringMap(extensions, output);

        // Reserved (Assuming reserved field is empty)
        String reserved = object.getReserved();
        if (reserved != null) {
            byte[] reservedBytes = reserved.getBytes(StandardCharsets.US_ASCII);
            output.appendInt(reservedBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(reservedBytes);
        } else {
            // Assuming no reserved data, add an empty string field
            output.appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);
        }

        // Signature Key (The public key used to sign this certificate)
        byte[] signatureKey = object.getSignatureKey();
        if (signatureKey == null) {
            throw new IllegalStateException("Signature Key is not set in the publicKey");
        }
        output.appendInt(signatureKey.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(signatureKey);

        // Signature (The actual signature on the certificate)
        byte[] signature = object.getSignature();
        if (signature == null) {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
        output.appendInt(signature.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(signature);
    }
}
