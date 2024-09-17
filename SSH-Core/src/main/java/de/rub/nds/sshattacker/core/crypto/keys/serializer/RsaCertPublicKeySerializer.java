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

/** Serializer class to encode an RSA certificate public key (ssh-rsa-cert-v01@openssh.com) format. */
public class RsaCertPublicKeySerializer extends Serializer<CustomCertRsaPublicKey> {

    private final CustomCertRsaPublicKey publicKey;

    public RsaCertPublicKeySerializer(CustomCertRsaPublicKey publicKey) {
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
        appendInt(PublicKeyFormat.SSH_RSA_CERT_V01_OPENSSH_COM.toString().getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
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

        // Valid After (uint64) -- using BigInteger instead of long
        appendBigInteger(BigInteger.valueOf(publicKey.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // Valid Before (uint64) -- using BigInteger instead of long
        appendBigInteger(BigInteger.valueOf(publicKey.getValidBefore()), DataFormatConstants.UINT64_SIZE);

        // Critical Options (Assuming no critical options, just an empty string for now)
        appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);  // Empty critical options

        // Extensions (Assuming no extensions, just an empty string for now)
        appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);  // Empty extensions

        // Reserved (Assuming reserved field is empty)
        appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);  // Empty reserved field

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
}
