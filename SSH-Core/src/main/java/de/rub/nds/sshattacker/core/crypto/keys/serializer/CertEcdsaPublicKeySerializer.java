/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.EcPointFormat;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertEcdsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Serializer class to encode an ECDSA certificate public key
 * (ecdsa-sha2-nistp*-cert-v01@openssh.com) format.
 */
public class CertEcdsaPublicKeySerializer extends Serializer<CustomCertEcdsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger(CertEcdsaPublicKeySerializer.class);

    @Override
    protected void serializeBytes(CustomCertEcdsaPublicKey object, SerializerStream output) {
        // Add debugging information before serialization
        LOGGER.debug("Starting serialization of CertEcdsaPublicKey.");
        LOGGER.debug("Curve Name: {}", object.getGroup().getJavaName());
        LOGGER.debug("Public Key: {}", object.getWAsPoint());
        LOGGER.debug("Nonce: {}", object.getNonce());
        LOGGER.debug("Signature Key: {}", object.getSignatureKey());
        LOGGER.debug("Signature: {}", object.getSignature());

        /*
         * The ecdsa-sha2-nistp*-cert-v01@openssh.com format as specified in the SSH protocol:
         *   string    "ecdsa-sha2-nistp*-cert-v01@openssh.com"
         *   string    nonce
         *   string    curve
         *   string    Q (the public key)
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

        // Format identifier (ecdsa-sha2-nistp*-cert-v01@openssh.com)
        NamedEcGroup curve = object.getGroup();
        switch (curve) {
            case SECP256R1:
                output.appendInt(
                        PublicKeyFormat.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM
                                .toString()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length,
                        DataFormatConstants.STRING_SIZE_LENGTH);
                output.appendString(
                        PublicKeyFormat.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM.toString(),
                        StandardCharsets.US_ASCII);
                break;
            case SECP384R1:
                output.appendInt(
                        PublicKeyFormat.ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM
                                .toString()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length,
                        DataFormatConstants.STRING_SIZE_LENGTH);
                output.appendString(
                        PublicKeyFormat.ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM.toString(),
                        StandardCharsets.US_ASCII);
                break;
            case SECP521R1:
                output.appendInt(
                        PublicKeyFormat.ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM
                                .toString()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length,
                        DataFormatConstants.STRING_SIZE_LENGTH);
                output.appendString(
                        PublicKeyFormat.ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM.toString(),
                        StandardCharsets.US_ASCII);
                break;
            default:
                throw new IllegalArgumentException("Unsupported curve: " + curve);
        }
        // Nonce
        byte[] nonce = object.getNonce();
        output.appendInt(nonce.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(nonce);

        // Curve name
        // String curveName = publicKey.getCurveName();
        output.appendInt(
                curve.getIdentifier().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString(curve.getIdentifier(), StandardCharsets.US_ASCII);

        // Public Key (Q)
        byte[] encodedQ =
                PointFormatter.formatToByteArray(
                        object.getGroup(), object.getWAsPoint(), EcPointFormat.UNCOMPRESSED);
        output.appendInt(encodedQ.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(encodedQ);

        // Serial (uint64)
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

        // Valid After (uint64)
        output.appendBigInteger(
                BigInteger.valueOf(object.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // Valid Before (uint64)
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
            output.appendInt(reservedBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(reservedBytes);
        } else {
            output.appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);
        }

        // Signature Key
        byte[] signatureKey = object.getSignatureKey();
        if (signatureKey == null) {
            throw new IllegalStateException("Signature Key is not set in the publicKey");
        }
        output.appendInt(signatureKey.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(signatureKey);

        // Signature
        byte[] signature = object.getSignature();
        if (signature == null) {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
        output.appendInt(signature.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(signature);
    }
}
