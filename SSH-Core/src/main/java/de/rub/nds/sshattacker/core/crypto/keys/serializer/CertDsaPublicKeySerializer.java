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
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertDsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Serializer class to encode a DSA certificate public key (ssh-dss-cert-v01@openssh.com) format.
 */
public class CertDsaPublicKeySerializer extends Serializer<CustomCertDsaPublicKey> {

    @Override
    protected void serializeBytes(CustomCertDsaPublicKey object, SerializerStream output) {
        /*
         * The ssh-dss-cert-v01@openssh.com format as specified in the SSH protocol:
         *   string    "ssh-dss-cert-v01@openssh.com"
         *   string    nonce
         *   mpint     p
         *   mpint     q
         *   mpint     g
         *   mpint     y
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

        // Format identifier (ssh-dss-cert-v01@openssh.com)
        output.appendLengthPrefixedString(
                PublicKeyFormat.SSH_DSS_CERT_V01_OPENSSH_COM.toString(), StandardCharsets.US_ASCII);

        // Nonce
        byte[] nonce = object.getNonce();
        output.appendLengthPrefixedBytes(nonce);

        // p (DSA prime)
        output.appendLengthPrefixedBigInteger(object.getP());

        // q (DSA subprime)
        output.appendLengthPrefixedBigInteger(object.getQ());

        // g (DSA generator)
        output.appendLengthPrefixedBigInteger(object.getG());

        // y (DSA public key)
        output.appendLengthPrefixedBigInteger(object.getY());

        // Serial (uint64) -- using BigInteger instead of long
        output.appendBigInteger(
                BigInteger.valueOf(object.getSerial()), DataFormatConstants.UINT64_SIZE);

        // Certificate type (uint32)
        output.appendInt(Integer.parseInt(object.getCertType()));

        // Key ID (string)
        String keyId = object.getKeyId();
        output.appendLengthPrefixedString(keyId, StandardCharsets.US_ASCII);

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

            output.appendLengthPrefixedBytes(principalsSerialized);
        } else {
            output.appendInt(0); // Empty principals list
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

        // Reserved
        String reserved = object.getReserved();
        if (reserved != null) {
            byte[] reservedBytes = reserved.getBytes(StandardCharsets.US_ASCII);
            output.appendLengthPrefixedBytes(reservedBytes);
        } else {
            output.appendInt(0);
        }

        // Signature Key (The public key used to sign this certificate)
        byte[] signatureKey = object.getSignatureKey();
        if (signatureKey == null) {
            throw new IllegalStateException("Signature Key is not set in the publicKey");
        }
        output.appendLengthPrefixedBytes(signatureKey);

        // Signature (The actual signature on the certificate)
        byte[] signature = object.getSignature();
        if (signature == null) {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
        output.appendLengthPrefixedBytes(signature);
    }
}
